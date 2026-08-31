//! Bounded Linux process inventory for QEMU hot-fork audits.
//!
//! Hot-fork readiness remains a QEMU-owned protocol decision. This module
//! supplies the complementary host audit of one exact process generation: it
//! records every visible thread, descriptor, and mapping twice under fixed
//! entry and byte limits and accepts only an identical fixed point. The report
//! is operational evidence for the Phase 6 lab; it is not a child-resource
//! disposition table and cannot authorize a fork.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::{
    QemuNodeChannelError, QemuNodeError, QemuProcessIdentity, QmpHotForkAioHandlerInventory,
    QmpHotForkAioInventory, QmpHotForkBlockBackendInventory, QmpHotForkBottomHalfInventory,
    QmpHotForkMonitorInventory, QmpHotForkMutexInventory, QmpHotForkPluginResourceInventory,
    QmpHotForkRcuInventory, QmpHotForkReadiness, QmpHotForkThreadInventory,
    QmpHotForkTimerInventory,
};

/// Maximum threads, descriptors, or mappings retained by one audit.
pub const MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES: usize = 65_536;
/// Maximum aggregate bytes retained from one `/proc/<pid>` inventory pass.
pub const MAX_QEMU_HOT_FORK_INVENTORY_BYTES: usize = 16 * 1024 * 1024;
/// Maximum bytes retained for one thread name.
pub const MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES: usize = 256;
/// Maximum bytes retained for one descriptor target.
pub const MAX_QEMU_HOT_FORK_DESCRIPTOR_TARGET_BYTES: usize = 4 * 1024;
/// Maximum bytes retained for one canonical `/proc/<pid>/maps` record.
pub const MAX_QEMU_HOT_FORK_MAPPING_RECORD_BYTES: usize = 8 * 1024;

/// One Linux thread visible in the audited QEMU generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkThreadInventory {
    thread_id: u32,
    name: Vec<u8>,
}

impl QemuHotForkThreadInventory {
    /// Returns the Linux thread identifier.
    #[must_use]
    pub const fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Returns the exact bounded bytes from `/proc/<pid>/task/<tid>/comm`.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }
}

/// One open Linux descriptor visible in the audited QEMU generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkDescriptorInventory {
    descriptor: u32,
    target: Vec<u8>,
}

impl QemuHotForkDescriptorInventory {
    /// Returns the process-local descriptor number.
    #[must_use]
    pub const fn descriptor(&self) -> u32 {
        self.descriptor
    }

    /// Returns the exact bounded `/proc/<pid>/fd/<n>` link target bytes.
    #[must_use]
    pub fn target(&self) -> &[u8] {
        &self.target
    }
}

/// One canonical Linux virtual-memory mapping record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkMappingInventory {
    record: Vec<u8>,
    writable: bool,
    shared: bool,
    start: u64,
    end: u64,
    device_major: u64,
    device_minor: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValidatedMappingRecord {
    writable: bool,
    shared: bool,
    start: u64,
    end: u64,
    device_major: u64,
    device_minor: u64,
    inode: u64,
}

impl QemuHotForkMappingInventory {
    /// Returns the exact bounded record from `/proc/<pid>/maps`, without newline.
    #[must_use]
    pub fn record(&self) -> &[u8] {
        &self.record
    }

    /// Returns whether the kernel marks this mapping writable.
    #[must_use]
    pub const fn writable(&self) -> bool {
        self.writable
    }

    /// Returns whether the kernel marks this mapping shared.
    #[must_use]
    pub const fn shared(&self) -> bool {
        self.shared
    }

    const fn length(&self) -> u64 {
        self.end - self.start
    }
}

/// Stable two-pass inventory of one exact Linux QEMU process generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkProcessInventory {
    process: QemuProcessIdentity,
    threads: Vec<QemuHotForkThreadInventory>,
    descriptors: Vec<QemuHotForkDescriptorInventory>,
    mappings: Vec<QemuHotForkMappingInventory>,
    retained_bytes: usize,
}

impl QemuHotForkProcessInventory {
    /// Returns the exact process generation bracketed around the inventory.
    #[must_use]
    pub const fn process(&self) -> &QemuProcessIdentity {
        &self.process
    }

    /// Returns every visible thread in numeric identifier order.
    #[must_use]
    pub fn threads(&self) -> &[QemuHotForkThreadInventory] {
        &self.threads
    }

    /// Returns every visible descriptor in numeric order.
    #[must_use]
    pub fn descriptors(&self) -> &[QemuHotForkDescriptorInventory] {
        &self.descriptors
    }

    /// Returns every mapping in the kernel-provided address order.
    #[must_use]
    pub fn mappings(&self) -> &[QemuHotForkMappingInventory] {
        &self.mappings
    }

    /// Returns aggregate retained thread-name, descriptor-target, and map bytes.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Returns the number of writable shared mappings requiring disposition.
    #[must_use]
    pub fn writable_shared_mappings(&self) -> usize {
        self.mappings
            .iter()
            .filter(|mapping| mapping.writable() && mapping.shared())
            .count()
    }
}

/// Cohesive QMP-side evidence captured before the matching process inventory.
pub(crate) struct QemuHotForkQmpInventory {
    readiness: QmpHotForkReadiness,
    threads: QmpHotForkThreadInventory,
    rcu: QmpHotForkRcuInventory,
    aio: QmpHotForkAioInventory,
    aio_handlers: QmpHotForkAioHandlerInventory,
    block_backends: QmpHotForkBlockBackendInventory,
    plugin_resources: QmpHotForkPluginResourceInventory,
    bottom_halves: QmpHotForkBottomHalfInventory,
    mutexes: QmpHotForkMutexInventory,
    timers: QmpHotForkTimerInventory,
    monitors: QmpHotForkMonitorInventory,
}

impl QemuHotForkQmpInventory {
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor preserves the one-to-one order of the eleven exact QMP inventories"
    )]
    pub(crate) const fn new(
        readiness: QmpHotForkReadiness,
        threads: QmpHotForkThreadInventory,
        rcu: QmpHotForkRcuInventory,
        aio: QmpHotForkAioInventory,
        aio_handlers: QmpHotForkAioHandlerInventory,
        block_backends: QmpHotForkBlockBackendInventory,
        plugin_resources: QmpHotForkPluginResourceInventory,
        bottom_halves: QmpHotForkBottomHalfInventory,
        mutexes: QmpHotForkMutexInventory,
        timers: QmpHotForkTimerInventory,
        monitors: QmpHotForkMonitorInventory,
    ) -> Self {
        Self {
            readiness,
            threads,
            rcu,
            aio,
            aio_handlers,
            block_backends,
            plugin_resources,
            bottom_halves,
            mutexes,
            timers,
            monitors,
        }
    }
}

/// Exact QEMU readiness and stable Linux process evidence from one audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkAudit {
    readiness: QmpHotForkReadiness,
    qemu_threads: QmpHotForkThreadInventory,
    qemu_rcu: QmpHotForkRcuInventory,
    qemu_aio: QmpHotForkAioInventory,
    qemu_aio_handlers: QmpHotForkAioHandlerInventory,
    qemu_block_backends: QmpHotForkBlockBackendInventory,
    qemu_plugin_resources: QmpHotForkPluginResourceInventory,
    qemu_bottom_halves: QmpHotForkBottomHalfInventory,
    qemu_mutexes: QmpHotForkMutexInventory,
    qemu_timers: QmpHotForkTimerInventory,
    qemu_monitors: QmpHotForkMonitorInventory,
    process: QemuHotForkProcessInventory,
    externally_created_thread_ids: Vec<u32>,
}

impl QemuHotForkAudit {
    pub(crate) fn new(
        qmp: QemuHotForkQmpInventory,
        process: QemuHotForkProcessInventory,
    ) -> Result<Self, QemuHotForkAuditError> {
        let QemuHotForkQmpInventory {
            readiness,
            threads: qemu_threads,
            rcu: qemu_rcu,
            aio: qemu_aio,
            aio_handlers: qemu_aio_handlers,
            block_backends: qemu_block_backends,
            plugin_resources: qemu_plugin_resources,
            bottom_halves: qemu_bottom_halves,
            mutexes: qemu_mutexes,
            timers: qemu_timers,
            monitors: qemu_monitors,
        } = qmp;

        if !qemu_threads.complete() {
            return Err(QemuHotForkAuditError::ThreadInventoryIncomplete);
        }
        if !qemu_rcu.complete() {
            return Err(QemuHotForkAuditError::RcuInventoryIncomplete);
        }
        if !qemu_aio.complete() {
            return Err(QemuHotForkAuditError::AioInventoryIncomplete);
        }
        if !qemu_aio_handlers.complete() {
            return Err(QemuHotForkAuditError::AioHandlerInventoryIncomplete);
        }
        if !qemu_block_backends.complete() {
            return Err(QemuHotForkAuditError::BlockBackendInventoryIncomplete);
        }
        if !qemu_plugin_resources.complete() {
            return Err(QemuHotForkAuditError::PluginResourceInventoryIncomplete);
        }
        if !qemu_mutexes.complete() {
            return Err(QemuHotForkAuditError::MutexInventoryIncomplete);
        }
        if !qemu_bottom_halves.complete() {
            return Err(QemuHotForkAuditError::BottomHalfInventoryIncomplete);
        }
        if !qemu_timers.complete() {
            return Err(QemuHotForkAuditError::TimerInventoryIncomplete);
        }
        if !qemu_monitors.complete() {
            return Err(QemuHotForkAuditError::MonitorInventoryIncomplete);
        }
        if !qemu_monitors.is_supported_parent_profile() {
            return Err(QemuHotForkAuditError::UnsupportedMonitorProfile);
        }

        let mut qemu_index = 0_usize;
        let mut externally_created_thread_ids = Vec::new();
        for process_thread in process.threads() {
            let process_thread_id = process_thread.thread_id();
            if qemu_threads
                .threads()
                .get(qemu_index)
                .is_some_and(|thread| thread.thread_id() == process_thread_id)
            {
                qemu_index += 1;
            } else {
                externally_created_thread_ids.push(process_thread_id);
            }
        }
        if let Some(thread) = qemu_threads.threads().get(qemu_index) {
            return Err(QemuHotForkAuditError::RegisteredThreadMissing {
                thread_id: thread.thread_id(),
            });
        }
        let mut qemu_thread_index = 0_usize;
        for reader in qemu_rcu.readers() {
            while qemu_threads
                .threads()
                .get(qemu_thread_index)
                .is_some_and(|thread| thread.thread_id() < reader.thread_id())
            {
                qemu_thread_index += 1;
            }
            if qemu_threads
                .threads()
                .get(qemu_thread_index)
                .is_none_or(|thread| thread.thread_id() != reader.thread_id())
            {
                return Err(QemuHotForkAuditError::RcuReaderMissing {
                    thread_id: reader.thread_id(),
                });
            }
        }
        for context in qemu_aio.contexts() {
            let Some(home_thread_id) = context.home_thread_id() else {
                continue;
            };
            if qemu_threads
                .threads()
                .binary_search_by_key(&home_thread_id, |thread| thread.thread_id())
                .is_err()
            {
                return Err(QemuHotForkAuditError::AioHomeThreadMissing {
                    context_id: context.context_id(),
                    thread_id: home_thread_id,
                });
            }
        }
        for bottom_half in qemu_bottom_halves.bottom_halves() {
            if qemu_aio
                .contexts()
                .binary_search_by_key(&bottom_half.context_id(), |context| context.context_id())
                .is_err()
            {
                return Err(QemuHotForkAuditError::BottomHalfContextMissing {
                    bottom_half_id: bottom_half.bottom_half_id(),
                    context_id: bottom_half.context_id(),
                });
            }
        }
        for handler in qemu_aio_handlers.handlers() {
            if qemu_aio
                .contexts()
                .binary_search_by_key(&handler.context_id(), |context| context.context_id())
                .is_err()
            {
                return Err(QemuHotForkAuditError::AioHandlerContextMissing {
                    handler_id: handler.handler_id(),
                    context_id: handler.context_id(),
                });
            }
            if !handler.deleted()
                && process
                    .descriptors()
                    .binary_search_by_key(&handler.descriptor(), |entry| entry.descriptor())
                    .is_err()
            {
                return Err(QemuHotForkAuditError::AioHandlerDescriptorMissing {
                    handler_id: handler.handler_id(),
                    descriptor: handler.descriptor(),
                });
            }
        }
        for backend in qemu_block_backends.backends() {
            if qemu_aio
                .contexts()
                .binary_search_by_key(&backend.context_id(), |context| context.context_id())
                .is_err()
            {
                return Err(QemuHotForkAuditError::BlockBackendContextMissing {
                    backend_id: backend.backend_id(),
                    context_id: backend.context_id(),
                });
            }
        }
        validate_plugin_resource_process_bindings(&qemu_plugin_resources, &process)?;
        for mutex in qemu_mutexes.mutexes() {
            let Some(owner_thread_id) = mutex.owner_thread_id() else {
                continue;
            };
            if qemu_threads
                .threads()
                .binary_search_by_key(&owner_thread_id, |thread| thread.thread_id())
                .is_err()
            {
                return Err(QemuHotForkAuditError::MutexOwnerThreadMissing {
                    mutex_id: mutex.mutex_id(),
                    thread_id: owner_thread_id,
                });
            }
        }
        Ok(Self {
            readiness,
            qemu_threads,
            qemu_rcu,
            qemu_aio,
            qemu_aio_handlers,
            qemu_block_backends,
            qemu_plugin_resources,
            qemu_bottom_halves,
            qemu_mutexes,
            qemu_timers,
            qemu_monitors,
            process,
            externally_created_thread_ids,
        })
    }

    /// Returns QEMU's exact versioned readiness proof report.
    #[must_use]
    pub const fn readiness(&self) -> QmpHotForkReadiness {
        self.readiness
    }

    /// Returns QEMU's matching bounded internal active-thread registry.
    #[must_use]
    pub const fn qemu_threads(&self) -> &QmpHotForkThreadInventory {
        &self.qemu_threads
    }

    /// Returns QEMU's matching bounded observational RCU inventory.
    #[must_use]
    pub const fn qemu_rcu(&self) -> &QmpHotForkRcuInventory {
        &self.qemu_rcu
    }

    /// Returns QEMU's matching bounded observational AioContext inventory.
    #[must_use]
    pub const fn qemu_aio(&self) -> &QmpHotForkAioInventory {
        &self.qemu_aio
    }

    /// Returns QEMU's matching bounded allocated-AIO-handler inventory.
    #[must_use]
    pub const fn qemu_aio_handlers(&self) -> &QmpHotForkAioHandlerInventory {
        &self.qemu_aio_handlers
    }

    /// Returns QEMU's matching bounded allocated-block-backend inventory.
    #[must_use]
    pub const fn qemu_block_backends(&self) -> &QmpHotForkBlockBackendInventory {
        &self.qemu_block_backends
    }

    /// Returns QEMU's matching sealed Crucible plugin-resource inventory.
    #[must_use]
    pub const fn qemu_plugin_resources(&self) -> &QmpHotForkPluginResourceInventory {
        &self.qemu_plugin_resources
    }

    /// Returns QEMU's matching bounded allocated-bottom-half inventory.
    #[must_use]
    pub const fn qemu_bottom_halves(&self) -> &QmpHotForkBottomHalfInventory {
        &self.qemu_bottom_halves
    }

    /// Returns QEMU's matching bounded observational mutex ownership inventory.
    #[must_use]
    pub const fn qemu_mutexes(&self) -> &QmpHotForkMutexInventory {
        &self.qemu_mutexes
    }

    /// Returns QEMU's matching bounded observational live-timer inventory.
    #[must_use]
    pub const fn qemu_timers(&self) -> &QmpHotForkTimerInventory {
        &self.qemu_timers
    }

    /// Returns QEMU's matching bounded monitor/parser inventory.
    #[must_use]
    pub const fn qemu_monitors(&self) -> QmpHotForkMonitorInventory {
        self.qemu_monitors
    }

    /// Returns the matching stable process inventory.
    #[must_use]
    pub const fn process(&self) -> &QemuHotForkProcessInventory {
        &self.process
    }

    /// Returns procfs thread IDs absent from QEMU's internal registry.
    ///
    /// These threads may come from linked libraries or other raw pthread users;
    /// each remains a blocker until QEMU owns an explicit disposition for it.
    #[must_use]
    pub fn externally_created_thread_ids(&self) -> &[u32] {
        &self.externally_created_thread_ids
    }
}

/// Failure while capturing one exact hot-fork process audit.
#[derive(Debug, Error)]
pub enum QemuHotForkAuditError {
    /// The QEMU child identity could not be authenticated.
    #[error("QEMU process identity could not be authenticated for hot-fork audit")]
    ProcessIdentity(#[source] QemuNodeError),
    /// The QMP readiness query failed.
    #[error("QEMU hot-fork readiness query failed")]
    Readiness(#[source] QemuNodeChannelError),
    /// The QEMU-owned active-thread inventory query failed.
    #[error("QEMU hot-fork active-thread inventory query failed")]
    ThreadInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned RCU inventory query failed.
    #[error("QEMU hot-fork RCU inventory query failed")]
    RcuInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned AioContext inventory query failed.
    #[error("QEMU hot-fork AioContext inventory query failed")]
    AioInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned allocated-AIO-handler inventory query failed.
    #[error("QEMU hot-fork AIO-handler inventory query failed")]
    AioHandlerInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned allocated-block-backend inventory query failed.
    #[error("QEMU hot-fork block-backend inventory query failed")]
    BlockBackendInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned sealed plugin-resource inventory query failed.
    #[error("QEMU hot-fork plugin-resource inventory query failed")]
    PluginResourceInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned allocated-bottom-half inventory query failed.
    #[error("QEMU hot-fork bottom-half inventory query failed")]
    BottomHalfInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned mutex inventory query failed.
    #[error("QEMU hot-fork mutex inventory query failed")]
    MutexInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned live-timer inventory query failed.
    #[error("QEMU hot-fork live-timer inventory query failed")]
    TimerInventory(#[source] QemuNodeChannelError),
    /// The QEMU-owned monitor/parser inventory query failed.
    #[error("QEMU hot-fork monitor/parser inventory query failed")]
    MonitorInventory(#[source] QemuNodeChannelError),
    /// QEMU was not at the exact paused/device-flush boundary.
    #[error("QEMU is not at the exact paused boundary required for hot-fork audit")]
    NotExactPausedBoundary,
    /// QEMU's proof bitmap changed around the process inventory.
    #[error("QEMU hot-fork readiness changed during process inventory")]
    ReadinessChanged,
    /// QEMU's internal active-thread registry changed around procfs capture.
    #[error("QEMU hot-fork active-thread inventory changed during process inventory")]
    ThreadInventoryChanged,
    /// QEMU's observational RCU inventory changed around procfs capture.
    #[error("QEMU hot-fork RCU inventory changed during process inventory")]
    RcuInventoryChanged,
    /// QEMU's observational AioContext inventory changed around procfs capture.
    #[error("QEMU hot-fork AioContext inventory changed during process inventory")]
    AioInventoryChanged,
    /// QEMU's observational AIO-handler inventory changed around procfs capture.
    #[error("QEMU hot-fork AIO-handler inventory changed during process inventory")]
    AioHandlerInventoryChanged,
    /// QEMU's block-backend inventory changed around procfs capture.
    #[error("QEMU hot-fork block-backend inventory changed during process inventory")]
    BlockBackendInventoryChanged,
    /// QEMU's sealed plugin-resource inventory changed around procfs capture.
    #[error("QEMU hot-fork plugin-resource inventory changed during process inventory")]
    PluginResourceInventoryChanged,
    /// QEMU's observational bottom-half inventory changed around procfs capture.
    #[error("QEMU hot-fork bottom-half inventory changed during process inventory")]
    BottomHalfInventoryChanged,
    /// QEMU's observational mutex inventory changed around procfs capture.
    #[error("QEMU hot-fork mutex inventory changed during process inventory")]
    MutexInventoryChanged,
    /// QEMU's observational live-timer inventory changed around procfs capture.
    #[error("QEMU hot-fork live-timer inventory changed during process inventory")]
    TimerInventoryChanged,
    /// QEMU's monitor/parser inventory changed around procfs capture.
    #[error("QEMU hot-fork monitor/parser inventory changed during process inventory")]
    MonitorInventoryChanged,
    /// QEMU could not report every live mutex with valid ownership state.
    #[error("QEMU hot-fork mutex inventory is incomplete")]
    MutexInventoryIncomplete,
    /// QEMU could not report every active thread with structurally valid state.
    #[error("QEMU hot-fork active-thread inventory is incomplete")]
    ThreadInventoryIncomplete,
    /// QEMU could not report every RCU reader with structurally valid state.
    #[error("QEMU hot-fork RCU inventory is incomplete")]
    RcuInventoryIncomplete,
    /// QEMU could not report every AioContext with structurally valid state.
    #[error("QEMU hot-fork AioContext inventory is incomplete")]
    AioInventoryIncomplete,
    /// QEMU could not report every allocated AIO handler with valid state.
    #[error("QEMU hot-fork AIO-handler inventory is incomplete")]
    AioHandlerInventoryIncomplete,
    /// QEMU could not report every allocated block backend with valid state.
    #[error("QEMU hot-fork block-backend inventory is incomplete")]
    BlockBackendInventoryIncomplete,
    /// QEMU did not report one complete internally consistent plugin manifest.
    #[error("QEMU hot-fork plugin-resource inventory is incomplete")]
    PluginResourceInventoryIncomplete,
    /// QEMU could not report every live timer with structurally valid state.
    #[error("QEMU hot-fork live-timer inventory is incomplete")]
    TimerInventoryIncomplete,
    /// QEMU could not report every monitor and parser with stable bounded state.
    #[error("QEMU hot-fork monitor/parser inventory is incomplete")]
    MonitorInventoryIncomplete,
    /// QEMU's monitor topology is outside the supported parent-template profile.
    #[error("QEMU hot-fork monitor/parser inventory is not the supported parent profile")]
    UnsupportedMonitorProfile,
    /// QEMU could not report every allocated bottom half with stable valid state.
    #[error("QEMU hot-fork bottom-half inventory is incomplete")]
    BottomHalfInventoryIncomplete,
    /// A QEMU-registered thread was absent from the exact procfs inventory.
    #[error("QEMU-registered thread {thread_id} is absent from the process inventory")]
    RegisteredThreadMissing {
        /// Missing registered operating-system thread identifier.
        thread_id: u32,
    },
    /// An RCU reader was absent from QEMU's exact active-thread registry.
    #[error("QEMU RCU reader {thread_id} is absent from the active-thread registry")]
    RcuReaderMissing {
        /// Missing RCU reader operating-system thread identifier.
        thread_id: u32,
    },
    /// An assigned AioContext home thread was absent from QEMU's thread registry.
    #[error(
        "QEMU AioContext {context_id} home thread {thread_id} is absent from the active-thread registry"
    )]
    AioHomeThreadMissing {
        /// Process-local AioContext identifier.
        context_id: u64,
        /// Missing operating-system home-thread identifier.
        thread_id: u32,
    },
    /// An allocated AIO handler named an absent AioContext.
    #[error("QEMU AIO handler {handler_id} names absent AioContext {context_id}")]
    AioHandlerContextMissing {
        /// Process-local AIO-handler identifier.
        handler_id: u64,
        /// Missing process-local AioContext identifier.
        context_id: u64,
    },
    /// A live AIO handler named a descriptor absent from the process inventory.
    #[error("QEMU AIO handler {handler_id} names absent descriptor {descriptor}")]
    AioHandlerDescriptorMissing {
        /// Process-local AIO-handler identifier.
        handler_id: u64,
        /// Missing process-local descriptor number.
        descriptor: u32,
    },
    /// An allocated block backend named an absent AioContext.
    #[error("QEMU block backend {backend_id} names absent AioContext {context_id}")]
    BlockBackendContextMissing {
        /// Process-local block-backend identifier.
        backend_id: u64,
        /// Missing process-local AioContext identifier.
        context_id: u64,
    },
    /// A descriptor sealed into the plugin manifest was absent from procfs.
    #[error("QEMU plugin {role} descriptor {descriptor} is absent from the process inventory")]
    PluginDescriptorMissing {
        /// Stable plugin descriptor role.
        role: &'static str,
        /// Missing process-local descriptor number.
        descriptor: i32,
    },
    /// A sealed plugin descriptor did not have its required Linux object type.
    #[error("QEMU plugin {role} descriptor {descriptor} has an invalid procfs target")]
    PluginDescriptorTargetInvalid {
        /// Stable plugin descriptor role.
        role: &'static str,
        /// Process-local descriptor number with the wrong target type.
        descriptor: i32,
    },
    /// The shared-memory object sealed by the plugin had no process mapping.
    #[error(
        "QEMU plugin shared-memory object {device_major:x}:{device_minor:x}/{inode} has no process mapping"
    )]
    PluginSharedMappingMissing {
        /// Linux device major number decoded from the manifest's `dev_t`.
        device_major: u64,
        /// Linux device minor number decoded from the manifest's `dev_t`.
        device_minor: u64,
        /// Linux backing-object inode.
        inode: u64,
    },
    /// A plugin shared-memory mapping lacked writable shared permissions.
    #[error(
        "QEMU plugin shared-memory object {device_major:x}:{device_minor:x}/{inode} is not entirely writable and shared"
    )]
    PluginSharedMappingPermissions {
        /// Linux device major number decoded from the manifest's `dev_t`.
        device_major: u64,
        /// Linux device minor number decoded from the manifest's `dev_t`.
        device_minor: u64,
        /// Linux backing-object inode.
        inode: u64,
    },
    /// Plugin shared-memory mappings did not cover the sealed byte length.
    #[error("QEMU plugin shared-memory mappings cover {actual} bytes, expected exactly {expected}")]
    PluginSharedMappingLengthMismatch {
        /// Sealed shared-memory byte length.
        expected: u64,
        /// Aggregate matching process-mapping length.
        actual: u64,
    },
    /// An allocated bottom half named an absent AioContext.
    #[error("QEMU bottom half {bottom_half_id} names absent AioContext {context_id}")]
    BottomHalfContextMissing {
        /// Process-local bottom-half identifier.
        bottom_half_id: u64,
        /// Missing process-local AioContext identifier.
        context_id: u64,
    },
    /// A mutex owner was absent from QEMU's active-thread registry.
    #[error(
        "QEMU mutex {mutex_id} owner thread {thread_id} is absent from the active-thread registry"
    )]
    MutexOwnerThreadMissing {
        /// Process-local mutex identifier.
        mutex_id: u64,
        /// Missing operating-system owner-thread identifier.
        thread_id: u32,
    },
    /// Linux process inventory failed.
    #[error(transparent)]
    Inventory(#[from] QemuHotForkInventoryError),
}

/// Failure while reading a bounded Linux QEMU process inventory.
#[derive(Debug, Error)]
pub enum QemuHotForkInventoryError {
    /// The expected PID no longer exists.
    #[error("QEMU process {process_id} is not present")]
    ProcessMissing {
        /// Missing process identifier.
        process_id: u32,
    },
    /// The PID names another process generation or executable.
    #[error("QEMU process identity changed during hot-fork inventory")]
    ProcessIdentityChanged,
    /// Reading the current process generation failed.
    #[error("QEMU process {process_id} identity could not be read")]
    ProcessIdentityRead {
        /// Process identifier whose generation was requested.
        process_id: u32,
        /// Typed process-identity failure.
        source: QemuNodeError,
    },
    /// A `/proc` operation failed.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// Stable operation name.
        operation: &'static str,
        /// Affected procfs path.
        path: PathBuf,
        /// Underlying host error.
        source: io::Error,
    },
    /// A kernel record was malformed.
    #[error("QEMU hot-fork {category} inventory contains a malformed record")]
    Malformed {
        /// Stable inventory category.
        category: &'static str,
    },
    /// A dimension exceeded its fixed audit bound.
    #[error("QEMU hot-fork {category} inventory exceeds limit {limit}")]
    LimitExceeded {
        /// Stable inventory category.
        category: &'static str,
        /// Enforced maximum.
        limit: usize,
    },
    /// Two consecutive bounded passes did not identify one fixed point.
    #[error("QEMU process resources changed during hot-fork inventory")]
    InventoryChanged,
}

/// Captures one stable bounded inventory for an exact Linux QEMU generation.
///
/// The function authenticates `expected` before and after two complete passes
/// and requires the passes to match byte-for-byte. This proves only an observed
/// fixed point. It does not classify mutexes, make mappings fork-safe, or grant
/// child-reinitialization authority.
///
/// # Errors
///
/// Returns [`QemuHotForkInventoryError`] when the process is absent or changed,
/// procfs is unavailable or malformed, a bound is exceeded, or the two passes
/// differ.
pub(crate) fn capture_linux_qemu_hot_fork_process_inventory(
    expected: &QemuProcessIdentity,
) -> Result<QemuHotForkProcessInventory, QemuHotForkInventoryError> {
    require_process_identity(expected)?;
    let proc_directory = PathBuf::from("/proc").join(expected.process_id.to_string());

    // Warm the bounded allocations before the compared passes. This matters
    // when a diagnostic targets its own process in a conformance test: the
    // audit's allocator growth must not look like guest mapping drift.
    let warm = capture_once(&proc_directory, expected)?;
    drop(warm);
    let first = capture_once(&proc_directory, expected)?;
    let second = capture_once(&proc_directory, expected)?;
    require_process_identity(expected)?;
    if first != second {
        return Err(QemuHotForkInventoryError::InventoryChanged);
    }
    Ok(first)
}

fn require_process_identity(
    expected: &QemuProcessIdentity,
) -> Result<(), QemuHotForkInventoryError> {
    match crate::linux_process_identity(expected.process_id) {
        Ok(Some(observed)) if observed == *expected => Ok(()),
        Ok(Some(_)) => Err(QemuHotForkInventoryError::ProcessIdentityChanged),
        Ok(None) => Err(QemuHotForkInventoryError::ProcessMissing {
            process_id: expected.process_id,
        }),
        Err(source) => Err(QemuHotForkInventoryError::ProcessIdentityRead {
            process_id: expected.process_id,
            source,
        }),
    }
}

fn capture_once(
    proc_directory: &Path,
    process: &QemuProcessIdentity,
) -> Result<QemuHotForkProcessInventory, QemuHotForkInventoryError> {
    let mut retained_bytes = 0_usize;
    let threads = capture_threads(proc_directory, &mut retained_bytes)?;
    let descriptors = capture_descriptors(proc_directory, &mut retained_bytes)?;
    let mappings = capture_mappings(proc_directory, &mut retained_bytes)?;
    Ok(QemuHotForkProcessInventory {
        process: process.clone(),
        threads,
        descriptors,
        mappings,
        retained_bytes,
    })
}

fn capture_threads(
    proc_directory: &Path,
    retained_bytes: &mut usize,
) -> Result<Vec<QemuHotForkThreadInventory>, QemuHotForkInventoryError> {
    let task_directory = proc_directory.join("task");
    let thread_ids = numeric_directory_entries(&task_directory, "thread-count")?;
    let mut threads = Vec::with_capacity(thread_ids.len());
    for thread_id in thread_ids {
        let path = task_directory.join(thread_id.to_string()).join("comm");
        let record_limit = MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES.checked_add(1).ok_or(
            QemuHotForkInventoryError::LimitExceeded {
                category: "thread-name-bytes",
                limit: MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES,
            },
        )?;
        let mut name = read_bounded_file(&path, record_limit, "thread-name-record-bytes")?;
        if name.last() == Some(&b'\n') {
            name.pop();
        }
        if name.len() > MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES {
            return Err(QemuHotForkInventoryError::LimitExceeded {
                category: "thread-name-bytes",
                limit: MAX_QEMU_HOT_FORK_THREAD_NAME_BYTES,
            });
        }
        charge_bytes(retained_bytes, name.len())?;
        threads.push(QemuHotForkThreadInventory { thread_id, name });
    }
    Ok(threads)
}

fn capture_descriptors(
    proc_directory: &Path,
    retained_bytes: &mut usize,
) -> Result<Vec<QemuHotForkDescriptorInventory>, QemuHotForkInventoryError> {
    let descriptor_directory = proc_directory.join("fd");
    let descriptors = numeric_directory_entries(&descriptor_directory, "descriptor-count")?;
    let mut inventory = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let path = descriptor_directory.join(descriptor.to_string());
        let target = fs::read_link(&path)
            .map_err(|source| proc_io("read descriptor target", &path, source))?;
        let target = target.as_os_str().as_bytes();
        if target.len() > MAX_QEMU_HOT_FORK_DESCRIPTOR_TARGET_BYTES {
            return Err(QemuHotForkInventoryError::LimitExceeded {
                category: "descriptor-target-bytes",
                limit: MAX_QEMU_HOT_FORK_DESCRIPTOR_TARGET_BYTES,
            });
        }
        charge_bytes(retained_bytes, target.len())?;
        inventory.push(QemuHotForkDescriptorInventory {
            descriptor,
            target: target.to_vec(),
        });
    }
    Ok(inventory)
}

fn capture_mappings(
    proc_directory: &Path,
    retained_bytes: &mut usize,
) -> Result<Vec<QemuHotForkMappingInventory>, QemuHotForkInventoryError> {
    let path = proc_directory.join("maps");
    let file =
        File::open(&path).map_err(|source| proc_io("open mapping inventory", &path, source))?;
    let mut reader = BufReader::new(file);
    let mut mappings = Vec::new();
    loop {
        let Some(record) = read_bounded_line(
            &mut reader,
            MAX_QEMU_HOT_FORK_MAPPING_RECORD_BYTES,
            "mapping-record-bytes",
            &path,
        )?
        else {
            break;
        };
        if mappings.len() == MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES {
            return Err(QemuHotForkInventoryError::LimitExceeded {
                category: "mapping-count",
                limit: MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES,
            });
        }
        let validated = validate_mapping_record(&record)?;
        charge_bytes(retained_bytes, record.len())?;
        mappings.push(QemuHotForkMappingInventory {
            record,
            writable: validated.writable,
            shared: validated.shared,
            start: validated.start,
            end: validated.end,
            device_major: validated.device_major,
            device_minor: validated.device_minor,
            inode: validated.inode,
        });
    }
    Ok(mappings)
}

fn numeric_directory_entries(
    directory: &Path,
    category: &'static str,
) -> Result<Vec<u32>, QemuHotForkInventoryError> {
    let entries = fs::read_dir(directory)
        .map_err(|source| proc_io("open process inventory directory", directory, source))?;
    let mut values = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|source| proc_io("read process inventory directory", directory, source))?;
        let Some(value) = parse_decimal_u32(entry.file_name().as_os_str().as_bytes()) else {
            return Err(QemuHotForkInventoryError::Malformed { category });
        };
        if values.len() == MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES {
            return Err(QemuHotForkInventoryError::LimitExceeded {
                category,
                limit: MAX_QEMU_HOT_FORK_INVENTORY_ENTRIES,
            });
        }
        values.push(value);
    }
    values.sort_unstable();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(QemuHotForkInventoryError::Malformed { category });
    }
    Ok(values)
}

fn parse_decimal_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then_some(())
            .and_then(|()| value.checked_mul(10))
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
    })
}

fn read_bounded_file(
    path: &Path,
    limit: usize,
    category: &'static str,
) -> Result<Vec<u8>, QemuHotForkInventoryError> {
    let file =
        File::open(path).map_err(|source| proc_io("open process inventory file", path, source))?;
    let maximum = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or(QemuHotForkInventoryError::LimitExceeded { category, limit })?;
    let mut bytes = Vec::new();
    file.take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|source| proc_io("read process inventory file", path, source))?;
    if bytes.len() > limit {
        return Err(QemuHotForkInventoryError::LimitExceeded { category, limit });
    }
    Ok(bytes)
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
    category: &'static str,
    path: &Path,
) -> Result<Option<Vec<u8>>, QemuHotForkInventoryError> {
    let mut record = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|source| QemuHotForkInventoryError::Io {
                operation: "read process mapping inventory",
                path: path.to_path_buf(),
                source,
            })?;
        if available.is_empty() {
            return if record.is_empty() {
                Ok(None)
            } else {
                Ok(Some(record))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let content_end = newline.unwrap_or(available.len());
        let new_length = record
            .len()
            .checked_add(content_end)
            .ok_or(QemuHotForkInventoryError::LimitExceeded { category, limit })?;
        if new_length > limit {
            return Err(QemuHotForkInventoryError::LimitExceeded { category, limit });
        }
        record.extend_from_slice(&available[..content_end]);
        if newline.is_some() {
            reader.consume(content_end + 1);
            return Ok(Some(record));
        }
        reader.consume(content_end);
    }
}

fn validate_mapping_record(
    record: &[u8],
) -> Result<ValidatedMappingRecord, QemuHotForkInventoryError> {
    let mut fields = record
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let range = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let permissions = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let offset = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let device = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let inode = fields.next().ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;

    let Some((start, end)) = split_once_byte(range, b'-') else {
        return Err(QemuHotForkInventoryError::Malformed {
            category: "mapping",
        });
    };
    let start = parse_hex_u64(start).ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let end = parse_hex_u64(end).ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    if start >= end || permissions.len() != 4 || parse_hex_u64(offset).is_none() {
        return Err(QemuHotForkInventoryError::Malformed {
            category: "mapping",
        });
    }
    let Some((major, minor)) = split_once_byte(device, b':') else {
        return Err(QemuHotForkInventoryError::Malformed {
            category: "mapping",
        });
    };
    let device_major = parse_hex_u64(major).ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let device_minor = parse_hex_u64(minor).ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    let inode = parse_decimal_u64(inode).ok_or(QemuHotForkInventoryError::Malformed {
        category: "mapping",
    })?;
    if !matches!(permissions[0], b'r' | b'-')
        || !matches!(permissions[1], b'w' | b'-')
        || !matches!(permissions[2], b'x' | b'-')
        || !matches!(permissions[3], b'p' | b's')
    {
        return Err(QemuHotForkInventoryError::Malformed {
            category: "mapping",
        });
    }
    Ok(ValidatedMappingRecord {
        writable: permissions[1] == b'w',
        shared: permissions[3] == b's',
        start,
        end,
        device_major,
        device_minor,
        inode,
    })
}

fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a') + 10,
            b'A'..=b'F' => u64::from(byte - b'A') + 10,
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit)
    })
}

fn parse_decimal_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        byte.is_ascii_digit()
            .then_some(())
            .and_then(|()| value.checked_mul(10))
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
    })
}

fn split_once_byte(bytes: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().position(|byte| *byte == delimiter)?;
    let (before, after) = bytes.split_at(index);
    Some((before, &after[1..]))
}

fn validate_plugin_resource_process_bindings(
    plugin: &QmpHotForkPluginResourceInventory,
    process: &QemuHotForkProcessInventory,
) -> Result<(), QemuHotForkAuditError> {
    for (role, descriptor) in [("control", plugin.control_fd()), ("wake", plugin.wake_fd())] {
        let descriptor_key = u32::try_from(descriptor)
            .map_err(|_| QemuHotForkAuditError::PluginDescriptorMissing { role, descriptor })?;
        let index = process
            .descriptors()
            .binary_search_by_key(&descriptor_key, |entry| entry.descriptor())
            .map_err(|_| QemuHotForkAuditError::PluginDescriptorMissing { role, descriptor })?;
        let target = process.descriptors()[index].target();
        let target_valid = match role {
            "control" => socket_target_inode(target).is_some(),
            "wake" => target == b"anon_inode:[eventfd]",
            _ => false,
        };
        if !target_valid {
            return Err(QemuHotForkAuditError::PluginDescriptorTargetInvalid { role, descriptor });
        }
    }

    let (device_major, device_minor) = linux_device_components(plugin.shmem_device());
    let mut found = false;
    let mut actual = 0_u64;
    for mapping in process.mappings().iter().filter(|mapping| {
        mapping.device_major == device_major
            && mapping.device_minor == device_minor
            && mapping.inode == plugin.shmem_inode()
    }) {
        found = true;
        if !mapping.writable() || !mapping.shared() {
            return Err(QemuHotForkAuditError::PluginSharedMappingPermissions {
                device_major,
                device_minor,
                inode: plugin.shmem_inode(),
            });
        }
        actual = actual.checked_add(mapping.length()).ok_or(
            QemuHotForkAuditError::PluginSharedMappingLengthMismatch {
                expected: plugin.shmem_length(),
                actual: u64::MAX,
            },
        )?;
    }
    if !found {
        return Err(QemuHotForkAuditError::PluginSharedMappingMissing {
            device_major,
            device_minor,
            inode: plugin.shmem_inode(),
        });
    }
    if actual != plugin.shmem_length() {
        return Err(QemuHotForkAuditError::PluginSharedMappingLengthMismatch {
            expected: plugin.shmem_length(),
            actual,
        });
    }
    Ok(())
}

fn socket_target_inode(target: &[u8]) -> Option<u64> {
    let inode = target.strip_prefix(b"socket:[")?.strip_suffix(b"]")?;
    parse_decimal_u64(inode).filter(|inode| *inode != 0)
}

const fn linux_device_components(device: u64) -> (u64, u64) {
    let major = ((device & 0x0000_0000_000f_ff00) >> 8) | ((device & 0xffff_f000_0000_0000) >> 32);
    let minor = (device & 0x0000_0000_0000_00ff) | ((device & 0x0000_0fff_fff0_0000) >> 12);
    (major, minor)
}

fn charge_bytes(retained: &mut usize, amount: usize) -> Result<(), QemuHotForkInventoryError> {
    let next = retained
        .checked_add(amount)
        .ok_or(QemuHotForkInventoryError::LimitExceeded {
            category: "aggregate-bytes",
            limit: MAX_QEMU_HOT_FORK_INVENTORY_BYTES,
        })?;
    if next > MAX_QEMU_HOT_FORK_INVENTORY_BYTES {
        return Err(QemuHotForkInventoryError::LimitExceeded {
            category: "aggregate-bytes",
            limit: MAX_QEMU_HOT_FORK_INVENTORY_BYTES,
        });
    }
    *retained = next;
    Ok(())
}

fn proc_io(operation: &'static str, path: &Path, source: io::Error) -> QemuHotForkInventoryError {
    QemuHotForkInventoryError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::fs;
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    fn qmp_inventory(
        readiness: QmpHotForkReadiness,
        threads: QmpHotForkThreadInventory,
        rcu: QmpHotForkRcuInventory,
        aio: QmpHotForkAioInventory,
        bottom_halves: QmpHotForkBottomHalfInventory,
        mutexes: QmpHotForkMutexInventory,
        timers: QmpHotForkTimerInventory,
    ) -> QemuHotForkQmpInventory {
        let context_id = aio
            .contexts()
            .first()
            .map_or(1, |context| context.context_id());
        QemuHotForkQmpInventory::new(
            readiness,
            threads,
            rcu,
            aio,
            QmpHotForkAioHandlerInventory::one_read(1, context_id, 3),
            QmpHotForkBlockBackendInventory::one_hidden(1, context_id),
            QmpHotForkPluginResourceInventory::one_complete(1),
            bottom_halves,
            mutexes,
            timers,
            QmpHotForkMonitorInventory::one_supported(),
        )
    }

    #[test]
    fn fixture_inventory_is_sorted_complete_and_classifies_shared_writes() {
        let directory = TempDir::new().expect("inventory fixture");
        let process = directory.path().join("42");
        fs::create_dir_all(process.join("task/42")).expect("primary task");
        fs::create_dir_all(process.join("task/77")).expect("secondary task");
        fs::write(process.join("task/42/comm"), b"qemu-main\n").expect("primary comm");
        fs::write(process.join("task/77/comm"), b"worker\n").expect("secondary comm");
        fs::create_dir_all(process.join("fd")).expect("descriptor directory");
        symlink("socket:[11]", process.join("fd/9")).expect("socket link");
        symlink("/run/qmp.sock", process.join("fd/3")).expect("QMP link");
        fs::write(
            process.join("maps"),
            b"1000-2000 r--p 00000000 00:00 0 /qemu\n2000-3000 rw-s 00000000 00:01 7 /ring\n",
        )
        .expect("mapping fixture");
        let identity = QemuProcessIdentity {
            process_id: 42,
            start_time_ticks: 9,
            executable: PathBuf::from("/qemu"),
        };

        let inventory = capture_once(&process, &identity).expect("fixture inventory");
        assert_eq!(
            inventory
                .threads()
                .iter()
                .map(QemuHotForkThreadInventory::thread_id)
                .collect::<Vec<_>>(),
            vec![42, 77]
        );
        assert_eq!(
            inventory
                .descriptors()
                .iter()
                .map(QemuHotForkDescriptorInventory::descriptor)
                .collect::<Vec<_>>(),
            vec![3, 9]
        );
        assert_eq!(inventory.mappings().len(), 2);
        assert_eq!(inventory.writable_shared_mappings(), 1);
        assert_eq!(inventory.process(), &identity);
    }

    #[test]
    fn mapping_parser_rejects_alternate_or_oversized_records() {
        assert_eq!(
            validate_mapping_record(b"1000-2000 rw-s 0 00:01 7 /ring").expect("canonical mapping"),
            ValidatedMappingRecord {
                writable: true,
                shared: true,
                start: 0x1000,
                end: 0x2000,
                device_major: 0,
                device_minor: 1,
                inode: 7,
            }
        );
        assert!(matches!(
            validate_mapping_record(b"1000-2000 rw-z 0 00:01 7 /ring"),
            Err(QemuHotForkInventoryError::Malformed {
                category: "mapping"
            })
        ));

        let input = vec![b'x'; MAX_QEMU_HOT_FORK_MAPPING_RECORD_BYTES + 1];
        assert!(matches!(
            read_bounded_line(
                &mut BufReader::new(input.as_slice()),
                MAX_QEMU_HOT_FORK_MAPPING_RECORD_BYTES,
                "mapping-record-bytes",
                Path::new("fixture-maps")
            ),
            Err(QemuHotForkInventoryError::LimitExceeded {
                category: "mapping-record-bytes",
                ..
            })
        ));
    }

    #[test]
    fn aggregate_byte_charge_is_checked_before_retention() {
        let mut retained = MAX_QEMU_HOT_FORK_INVENTORY_BYTES;
        assert!(matches!(
            charge_bytes(&mut retained, 1),
            Err(QemuHotForkInventoryError::LimitExceeded {
                category: "aggregate-bytes",
                ..
            })
        ));
        assert_eq!(retained, MAX_QEMU_HOT_FORK_INVENTORY_BYTES);
    }

    #[test]
    fn qemu_registry_is_exactly_reconciled_with_procfs_threads() {
        let process = QemuHotForkProcessInventory {
            process: QemuProcessIdentity {
                process_id: 10,
                start_time_ticks: 1,
                executable: PathBuf::from("/qemu"),
            },
            threads: vec![
                QemuHotForkThreadInventory {
                    thread_id: 10,
                    name: b"qmp-main-loop".to_vec(),
                },
                QemuHotForkThreadInventory {
                    thread_id: 20,
                    name: b"external".to_vec(),
                },
            ],
            descriptors: vec![
                QemuHotForkDescriptorInventory {
                    descriptor: 3,
                    target: b"socket:[7]".to_vec(),
                },
                QemuHotForkDescriptorInventory {
                    descriptor: 4,
                    target: b"anon_inode:[eventfd]".to_vec(),
                },
            ],
            mappings: vec![QemuHotForkMappingInventory {
                record: b"1000-2000 rw-s 00000000 00:01 2 /ring".to_vec(),
                writable: true,
                shared: true,
                start: 0x1000,
                end: 0x2000,
                device_major: 0,
                device_minor: 1,
                inode: 2,
            }],
            retained_bytes: 26,
        };
        let readiness =
            QmpHotForkReadiness::from_acknowledged_proofs(7).expect("scripted readiness bitmap");
        let audit = QemuHotForkAudit::new(
            qmp_inventory(
                readiness,
                QmpHotForkThreadInventory::one_coordinator(10),
                QmpHotForkRcuInventory::from_reader_ids(&[10]),
                QmpHotForkAioInventory::one_idle(1, 10),
                QmpHotForkBottomHalfInventory::one_idle(1, 1),
                QmpHotForkMutexInventory::one_owned(1, 10),
                QmpHotForkTimerInventory::empty(),
            ),
            process.clone(),
        )
        .expect("registered coordinator should match procfs");
        assert_eq!(audit.externally_created_thread_ids(), &[20]);

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::incomplete(),
                    QmpHotForkRcuInventory::from_reader_ids(&[10]),
                    QmpHotForkAioInventory::one_idle(1, 10),
                    QmpHotForkBottomHalfInventory::one_idle(1, 1),
                    QmpHotForkMutexInventory::one_owned(1, 10),
                    QmpHotForkTimerInventory::empty(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::ThreadInventoryIncomplete)
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(10),
                    QmpHotForkRcuInventory::incomplete(),
                    QmpHotForkAioInventory::one_idle(1, 10),
                    QmpHotForkBottomHalfInventory::one_idle(1, 1),
                    QmpHotForkMutexInventory::one_owned(1, 10),
                    QmpHotForkTimerInventory::empty(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::RcuInventoryIncomplete)
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(10),
                    QmpHotForkRcuInventory::from_reader_ids(&[10]),
                    QmpHotForkAioInventory::incomplete(),
                    QmpHotForkBottomHalfInventory::one_idle(1, 1),
                    QmpHotForkMutexInventory::one_owned(1, 10),
                    QmpHotForkTimerInventory::empty(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::AioInventoryIncomplete)
        ));

        let mut incomplete_handlers = qmp_inventory(
            readiness,
            QmpHotForkThreadInventory::one_coordinator(10),
            QmpHotForkRcuInventory::from_reader_ids(&[10]),
            QmpHotForkAioInventory::one_idle(1, 10),
            QmpHotForkBottomHalfInventory::one_idle(1, 1),
            QmpHotForkMutexInventory::one_owned(1, 10),
            QmpHotForkTimerInventory::empty(),
        );
        incomplete_handlers.aio_handlers = QmpHotForkAioHandlerInventory::incomplete();
        assert!(matches!(
            QemuHotForkAudit::new(incomplete_handlers, process.clone()),
            Err(QemuHotForkAuditError::AioHandlerInventoryIncomplete)
        ));

        let mut incomplete_backends = qmp_inventory(
            readiness,
            QmpHotForkThreadInventory::one_coordinator(10),
            QmpHotForkRcuInventory::from_reader_ids(&[10]),
            QmpHotForkAioInventory::one_idle(1, 10),
            QmpHotForkBottomHalfInventory::one_idle(1, 1),
            QmpHotForkMutexInventory::one_owned(1, 10),
            QmpHotForkTimerInventory::empty(),
        );
        incomplete_backends.block_backends = QmpHotForkBlockBackendInventory::incomplete();
        assert!(matches!(
            QemuHotForkAudit::new(incomplete_backends, process.clone()),
            Err(QemuHotForkAuditError::BlockBackendInventoryIncomplete)
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(10),
                    QmpHotForkRcuInventory::from_reader_ids(&[10]),
                    QmpHotForkAioInventory::one_idle(1, 10),
                    QmpHotForkBottomHalfInventory::one_idle(1, 1),
                    QmpHotForkMutexInventory::incomplete(),
                    QmpHotForkTimerInventory::empty(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::MutexInventoryIncomplete)
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(10),
                    QmpHotForkRcuInventory::from_reader_ids(&[10]),
                    QmpHotForkAioInventory::one_idle(1, 10),
                    QmpHotForkBottomHalfInventory::one_idle(1, 1),
                    QmpHotForkMutexInventory::one_owned(1, 10),
                    QmpHotForkTimerInventory::incomplete(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::TimerInventoryIncomplete)
        ));

        let mut incomplete_monitor = qmp_inventory(
            readiness,
            QmpHotForkThreadInventory::one_coordinator(10),
            QmpHotForkRcuInventory::from_reader_ids(&[10]),
            QmpHotForkAioInventory::one_idle(1, 10),
            QmpHotForkBottomHalfInventory::one_idle(1, 1),
            QmpHotForkMutexInventory::one_owned(1, 10),
            QmpHotForkTimerInventory::empty(),
        );
        incomplete_monitor.monitors = QmpHotForkMonitorInventory::incomplete();
        assert!(matches!(
            QemuHotForkAudit::new(incomplete_monitor, process.clone()),
            Err(QemuHotForkAuditError::MonitorInventoryIncomplete)
        ));

        let mut unsupported_monitor = qmp_inventory(
            readiness,
            QmpHotForkThreadInventory::one_coordinator(10),
            QmpHotForkRcuInventory::from_reader_ids(&[10]),
            QmpHotForkAioInventory::one_idle(1, 10),
            QmpHotForkBottomHalfInventory::one_idle(1, 1),
            QmpHotForkMutexInventory::one_owned(1, 10),
            QmpHotForkTimerInventory::empty(),
        );
        unsupported_monitor.monitors = QmpHotForkMonitorInventory::one_queued();
        assert!(matches!(
            QemuHotForkAudit::new(unsupported_monitor, process.clone()),
            Err(QemuHotForkAuditError::UnsupportedMonitorProfile)
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(10),
                    QmpHotForkRcuInventory::from_reader_ids(&[10]),
                    QmpHotForkAioInventory::one_idle(1, 10),
                    QmpHotForkBottomHalfInventory::incomplete(),
                    QmpHotForkMutexInventory::one_owned(1, 10),
                    QmpHotForkTimerInventory::empty(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::BottomHalfInventoryIncomplete)
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(10),
                    QmpHotForkRcuInventory::from_reader_ids(&[10]),
                    QmpHotForkAioInventory::one_idle(1, 10),
                    QmpHotForkBottomHalfInventory::one_idle(9, 2),
                    QmpHotForkMutexInventory::one_owned(1, 10),
                    QmpHotForkTimerInventory::empty(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::BottomHalfContextMissing {
                bottom_half_id: 9,
                context_id: 2,
            })
        ));

        let mut missing_handler_context = qmp_inventory(
            readiness,
            QmpHotForkThreadInventory::one_coordinator(10),
            QmpHotForkRcuInventory::from_reader_ids(&[10]),
            QmpHotForkAioInventory::one_idle(1, 10),
            QmpHotForkBottomHalfInventory::one_idle(1, 1),
            QmpHotForkMutexInventory::one_owned(1, 10),
            QmpHotForkTimerInventory::empty(),
        );
        missing_handler_context.aio_handlers = QmpHotForkAioHandlerInventory::one_read(9, 2, 3);
        assert!(matches!(
            QemuHotForkAudit::new(missing_handler_context, process.clone()),
            Err(QemuHotForkAuditError::AioHandlerContextMissing {
                handler_id: 9,
                context_id: 2,
            })
        ));

        let mut missing_backend_context = qmp_inventory(
            readiness,
            QmpHotForkThreadInventory::one_coordinator(10),
            QmpHotForkRcuInventory::from_reader_ids(&[10]),
            QmpHotForkAioInventory::one_idle(1, 10),
            QmpHotForkBottomHalfInventory::one_idle(1, 1),
            QmpHotForkMutexInventory::one_owned(1, 10),
            QmpHotForkTimerInventory::empty(),
        );
        missing_backend_context.block_backends = QmpHotForkBlockBackendInventory::one_hidden(9, 2);
        assert!(matches!(
            QemuHotForkAudit::new(missing_backend_context, process.clone()),
            Err(QemuHotForkAuditError::BlockBackendContextMissing {
                backend_id: 9,
                context_id: 2,
            })
        ));

        let mut missing_handler_descriptor = qmp_inventory(
            readiness,
            QmpHotForkThreadInventory::one_coordinator(10),
            QmpHotForkRcuInventory::from_reader_ids(&[10]),
            QmpHotForkAioInventory::one_idle(1, 10),
            QmpHotForkBottomHalfInventory::one_idle(1, 1),
            QmpHotForkMutexInventory::one_owned(1, 10),
            QmpHotForkTimerInventory::empty(),
        );
        missing_handler_descriptor.aio_handlers = QmpHotForkAioHandlerInventory::one_read(9, 1, 5);
        assert!(matches!(
            QemuHotForkAudit::new(missing_handler_descriptor, process.clone()),
            Err(QemuHotForkAuditError::AioHandlerDescriptorMissing {
                handler_id: 9,
                descriptor: 5,
            })
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(10),
                    QmpHotForkRcuInventory::from_reader_ids(&[20]),
                    QmpHotForkAioInventory::one_idle(1, 10),
                    QmpHotForkBottomHalfInventory::one_idle(1, 1),
                    QmpHotForkMutexInventory::one_owned(1, 10),
                    QmpHotForkTimerInventory::empty(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::RcuReaderMissing { thread_id: 20 })
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(10),
                    QmpHotForkRcuInventory::from_reader_ids(&[10]),
                    QmpHotForkAioInventory::one_idle(7, 20),
                    QmpHotForkBottomHalfInventory::one_idle(1, 7),
                    QmpHotForkMutexInventory::one_owned(1, 10),
                    QmpHotForkTimerInventory::empty(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::AioHomeThreadMissing {
                context_id: 7,
                thread_id: 20,
            })
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(10),
                    QmpHotForkRcuInventory::from_reader_ids(&[10]),
                    QmpHotForkAioInventory::one_idle(1, 10),
                    QmpHotForkBottomHalfInventory::one_idle(1, 1),
                    QmpHotForkMutexInventory::one_owned(9, 20),
                    QmpHotForkTimerInventory::empty(),
                ),
                process.clone(),
            ),
            Err(QemuHotForkAuditError::MutexOwnerThreadMissing {
                mutex_id: 9,
                thread_id: 20,
            })
        ));

        assert!(matches!(
            QemuHotForkAudit::new(
                qmp_inventory(
                    readiness,
                    QmpHotForkThreadInventory::one_coordinator(30),
                    QmpHotForkRcuInventory::from_reader_ids(&[30]),
                    QmpHotForkAioInventory::one_idle(1, 30),
                    QmpHotForkBottomHalfInventory::one_idle(1, 1),
                    QmpHotForkMutexInventory::one_owned(1, 30),
                    QmpHotForkTimerInventory::empty(),
                ),
                process,
            ),
            Err(QemuHotForkAuditError::RegisteredThreadMissing { thread_id: 30 })
        ));
    }

    #[test]
    fn plugin_manifest_is_bound_to_exact_descriptors_and_shared_mapping() {
        let qmp = || {
            qmp_inventory(
                QmpHotForkReadiness::from_acknowledged_proofs(7)
                    .expect("scripted readiness bitmap"),
                QmpHotForkThreadInventory::one_coordinator(10),
                QmpHotForkRcuInventory::from_reader_ids(&[10]),
                QmpHotForkAioInventory::one_idle(1, 10),
                QmpHotForkBottomHalfInventory::one_idle(1, 1),
                QmpHotForkMutexInventory::one_owned(1, 10),
                QmpHotForkTimerInventory::empty(),
            )
        };
        let process = |descriptors: Vec<QemuHotForkDescriptorInventory>,
                       writable: bool,
                       end: u64| QemuHotForkProcessInventory {
            process: QemuProcessIdentity {
                process_id: 10,
                start_time_ticks: 1,
                executable: PathBuf::from("/qemu"),
            },
            threads: vec![QemuHotForkThreadInventory {
                thread_id: 10,
                name: b"qmp-main-loop".to_vec(),
            }],
            descriptors,
            mappings: vec![QemuHotForkMappingInventory {
                record: b"1000-2000 rw-s 00000000 00:01 2 /ring".to_vec(),
                writable,
                shared: true,
                start: 0x1000,
                end,
                device_major: 0,
                device_minor: 1,
                inode: 2,
            }],
            retained_bytes: 0,
        };
        let descriptors = || {
            vec![
                QemuHotForkDescriptorInventory {
                    descriptor: 3,
                    target: b"socket:[7]".to_vec(),
                },
                QemuHotForkDescriptorInventory {
                    descriptor: 4,
                    target: b"anon_inode:[eventfd]".to_vec(),
                },
            ]
        };

        QemuHotForkAudit::new(qmp(), process(descriptors(), true, 0x2000))
            .expect("exact plugin process bindings should validate");
        assert!(matches!(
            QemuHotForkAudit::new(qmp(), process(descriptors()[..1].to_vec(), true, 0x2000)),
            Err(QemuHotForkAuditError::PluginDescriptorMissing {
                role: "wake",
                descriptor: 4,
            })
        ));
        assert!(matches!(
            QemuHotForkAudit::new(qmp(), process(descriptors(), false, 0x2000)),
            Err(QemuHotForkAuditError::PluginSharedMappingPermissions { .. })
        ));
        assert!(matches!(
            QemuHotForkAudit::new(qmp(), process(descriptors(), true, 0x3000)),
            Err(QemuHotForkAuditError::PluginSharedMappingLengthMismatch {
                expected: 4096,
                actual: 8192,
            })
        ));
    }

    #[test]
    fn process_generation_mismatch_fails_before_inventory() {
        let mut identity = crate::linux_process_identity(std::process::id())
            .expect("read current process identity")
            .expect("current process exists");
        identity.start_time_ticks = identity.start_time_ticks.wrapping_add(1);

        assert!(matches!(
            capture_linux_qemu_hot_fork_process_inventory(&identity),
            Err(QemuHotForkInventoryError::ProcessIdentityChanged)
        ));
    }
}
