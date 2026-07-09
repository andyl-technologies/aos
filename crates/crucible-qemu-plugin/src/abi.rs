//! QEMU plugin ABI scaffold and inert callback ownership.
//!
//! QEMU loads this crate as a `cdylib` and looks up the exported install
//! symbol:
//!
//! ```text
//! qemu_plugin_install(id, info, argc, argv)
//! ```
//!
//! This module keeps that raw ABI boundary narrow. The current scaffold records
//! the entry point, validates the execution-model assumptions in safe Rust, and
//! owns inert callback function pointers for every device/channel family that
//! later tasks wire to real behavior. Under the required single-threaded
//! round-robin TCG model, QEMU serializes registered vCPU-thread callbacks so
//! plugin callback state is not accessed concurrently.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint, c_void};

use crate::{
    ExactDeadlineError, ExactDeadlineReader, QemuAdvanceVirtualTimeDirectFn, QemuClockDeadlineFn,
    QemuInjectPreemptionFn, QemuReadRrCursorFn, QemuReadVcpuRegsFn, SynchronousIdleAdvance,
    SynchronousIdleAdvanceError,
};
use crate::{PLUGIN_ARG_SIMFD, PluginArgs, PluginArgsParseError};
use crate::{PluginPreemptionInjector, PreemptionError};
use crate::{PluginVcpuIntrospector, VcpuIntrospectionError};

/// QEMU plugin identifier type passed to the install entry point.
pub type QemuPluginId = u64;

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuPluginApiVersionRange {
    min: c_int,
    cur: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuPluginSystemInfo {
    smp_vcpus: c_int,
    max_vcpus: c_int,
}

/// Minimal QEMU `qemu_info_t` layout consumed by the install scaffold.
///
/// This mirrors the prefix and single `system` union member installed by AOS
/// QEMU 10.0.0. The scaffold copies only scalar ABI-version and vCPU-count
/// fields while QEMU guarantees the pointer is live during `qemu_plugin_install`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QemuPluginInfo {
    target_name: *const c_char,
    version: QemuPluginApiVersionRange,
    system_emulation: bool,
    system: QemuPluginSystemInfo,
}

/// QEMU install return value meaning the plugin loaded successfully.
pub const QEMU_PLUGIN_INSTALL_OK: c_int = 0;
/// QEMU install return value meaning plugin registration failed.
pub const QEMU_PLUGIN_INSTALL_ERROR: c_int = -1;
/// QEMU plugin API version exported by AOS QEMU 10.0.0.
pub const QEMU_PLUGIN_API_VERSION: c_int = 4;
/// The exported symbol QEMU resolves when loading this `cdylib`.
pub const QEMU_PLUGIN_INSTALL_SYMBOL: &str = "qemu_plugin_install";
/// The exported symbol QEMU checks before calling the install hook.
pub const QEMU_PLUGIN_VERSION_SYMBOL: &str = "qemu_plugin_version";
/// Compatibility label for RFC text that calls the install hook `Register`.
pub const QEMU_PLUGIN_REGISTER_ENTRYPOINT_SYMBOL: &str = QEMU_PLUGIN_INSTALL_SYMBOL;
/// QEMU plugin API symbol used to read raw instruction count.
pub const QEMU_PLUGIN_ICOUNT_RAW_SYMBOL: &str = "qemu_plugin_icount_raw";
/// QEMU plugin API symbol used to request current-vCPU exit.
pub const QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL: &str = "qemu_plugin_force_vcpu_exit";
/// QEMU plugin API symbol used to register the setup wake fd with QEMU.
pub const QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL: &str = "qemu_plugin_register_wake_fd";
/// QEMU plugin API symbol used to block through QEMU's main loop.
pub const QEMU_PLUGIN_MAIN_LOOP_WAIT_SYMBOL: &str = "qemu_plugin_main_loop_wait";
/// QEMU plugin API symbol used to register shmem block submit/poll callbacks.
pub const QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL: &str = "qemu_plugin_register_blk_cb";
/// QEMU plugin API symbol used to register shmem 9p burst/submit/poll callbacks.
pub const QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL: &str = "qemu_plugin_register_9p_cb";
/// Minimum supported vCPU count under single-threaded round-robin TCG.
pub const MIN_SUPPORTED_VCPU_COUNT: u32 = 1;
const QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL_C: &[u8] = b"qemu_plugin_clock_deadline_ns\0";
const QEMU_PLUGIN_ADVANCE_VIRTUAL_TIME_DIRECT_SYMBOL_C: &[u8] =
    b"qemu_plugin_advance_virtual_time_direct\0";
const QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL_C: &[u8] = b"qemu_plugin_inject_preemption\0";
const QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL_C: &[u8] = b"qemu_plugin_read_vcpu_regs\0";
const QEMU_PLUGIN_RR_CURSOR_SYMBOL_C: &[u8] = b"qemu_plugin_rr_cursor\0";
const QEMU_PLUGIN_ICOUNT_RAW_SYMBOL_C: &[u8] = b"qemu_plugin_icount_raw\0";
const QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL_C: &[u8] = b"qemu_plugin_force_vcpu_exit\0";
const QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL_C: &[u8] = b"qemu_plugin_register_wake_fd\0";
const QEMU_PLUGIN_MAIN_LOOP_WAIT_SYMBOL_C: &[u8] = b"qemu_plugin_main_loop_wait\0";
const QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_tcg_exec_cb\0";
const QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_blk_cb\0";
const QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_9p_cb\0";

#[cfg(test)]
static TEST_CLOCK_DEADLINE_SYMBOL: std::sync::Mutex<Option<QemuClockDeadlineFn>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn test_clock_deadline_symbol_override() -> Option<QemuClockDeadlineFn> {
    match TEST_CLOCK_DEADLINE_SYMBOL.lock() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    }
}

#[cfg(test)]
fn set_test_clock_deadline_symbol(symbol: Option<QemuClockDeadlineFn>) {
    match TEST_CLOCK_DEADLINE_SYMBOL.lock() {
        Ok(mut guard) => *guard = symbol,
        Err(poisoned) => *poisoned.into_inner() = symbol,
    }
}

/// The TCG threading mode relevant to plugin callback serialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuTcgThreading {
    /// QEMU serializes all vCPU callbacks onto one host thread.
    SingleThreadedRoundRobin,
    /// QEMU may execute vCPU callbacks concurrently and is unsupported.
    MultiThreadedTcg,
}

/// Validated QEMU execution model for the plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuPluginExecutionModel {
    smp_vcpus: u32,
    threading: QemuTcgThreading,
}

impl QemuPluginExecutionModel {
    /// Validates the vCPU count and TCG threading mode.
    ///
    /// # Errors
    ///
    /// Returns [`QemuPluginAbiError::NoVcpus`] when `smp_vcpus` is zero, or
    /// [`QemuPluginAbiError::MultiThreadedTcg`] when MTTCG would invalidate the
    /// plugin's single-threaded callback-state invariant.
    pub const fn validate(
        smp_vcpus: u32,
        threading: QemuTcgThreading,
    ) -> Result<Self, QemuPluginAbiError> {
        if smp_vcpus < MIN_SUPPORTED_VCPU_COUNT {
            return Err(QemuPluginAbiError::NoVcpus);
        }
        if matches!(threading, QemuTcgThreading::MultiThreadedTcg) {
            return Err(QemuPluginAbiError::MultiThreadedTcg);
        }
        Ok(Self {
            smp_vcpus,
            threading,
        })
    }

    /// Returns the number of guest vCPUs in this QEMU process.
    #[must_use]
    pub const fn smp_vcpus(self) -> u32 {
        self.smp_vcpus
    }

    /// Returns the validated TCG threading mode.
    #[must_use]
    pub const fn threading(self) -> QemuTcgThreading {
        self.threading
    }

    /// Returns whether the current process uses the degenerate single-vCPU case.
    #[must_use]
    pub const fn is_single_vcpu(self) -> bool {
        self.smp_vcpus == 1
    }
}

/// The lifecycle phase owned by the plugin core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginLifecyclePhase {
    /// The `cdylib` entry point has not yet been called.
    Uninstalled,
    /// QEMU called the install entry point, but full sim registration is pending.
    InstalledInert,
    /// Full sim registration completed and callbacks may affect the guest.
    Active,
    /// Registration failed loudly and no later callbacks may run.
    Failed,
}

/// Mutable lifecycle state kept separate from re-entrant device callback pointers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginLifecycleCore {
    phase: PluginLifecyclePhase,
    execution_model: QemuPluginExecutionModel,
}

impl PluginLifecycleCore {
    /// Builds an inert lifecycle core after the QEMU install entry point returns.
    #[must_use]
    pub const fn installed_inert(execution_model: QemuPluginExecutionModel) -> Self {
        Self {
            phase: PluginLifecyclePhase::InstalledInert,
            execution_model,
        }
    }

    /// Returns the current lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> PluginLifecyclePhase {
        self.phase
    }

    /// Returns the validated execution model.
    #[must_use]
    pub const fn execution_model(&self) -> QemuPluginExecutionModel {
        self.execution_model
    }
}

/// A callback family owned by the QEMU plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginDeviceCallbackKind {
    /// Guest network transmit interception.
    NetworkTx,
    /// Guest network receive injection.
    NetworkRx,
    /// Block-device submit interception.
    BlockSubmit,
    /// Block-device completion polling.
    BlockPoll,
    /// 9p request submit interception.
    Virtio9pSubmit,
    /// 9p completion polling.
    Virtio9pPoll,
    /// Optional white-box guest doorbell trap.
    WhiteboxDoorbell,
}

/// All device and channel callback families the plugin owns.
pub const OWNED_DEVICE_CALLBACK_KINDS: [PluginDeviceCallbackKind; 7] = [
    PluginDeviceCallbackKind::NetworkTx,
    PluginDeviceCallbackKind::NetworkRx,
    PluginDeviceCallbackKind::BlockSubmit,
    PluginDeviceCallbackKind::BlockPoll,
    PluginDeviceCallbackKind::Virtio9pSubmit,
    PluginDeviceCallbackKind::Virtio9pPoll,
    PluginDeviceCallbackKind::WhiteboxDoorbell,
];

/// Common inert C callback signature for the initial scaffold.
///
/// Registered callbacks are invoked under QEMU's enforced vCPU-thread
/// callback contract: single-threaded round-robin TCG serializes all vCPU and
/// device callback execution in this process.
pub type InertDeviceCallback = extern "C" fn(QemuPluginId, *mut c_void);
/// QEMU raw-icount reader exported by `crucible-plugin-icount-raw`.
pub type QemuIcountRawFn = extern "C" fn() -> u64;
/// QEMU current-vCPU exit request exported by `crucible-plugin-vcpu-exit`.
pub type QemuForceVcpuExitFn = extern "C" fn();
/// QEMU wake-fd registration exported by `crucible-plugin-wake-fd`.
pub type QemuRegisterWakeFdFn = extern "C" fn(c_int) -> c_int;
/// QEMU blocking main-loop wait exported by `crucible-plugin-wake-fd`.
pub type QemuMainLoopWaitFn = extern "C" fn();
/// TCG-exec callback body passed to QEMU's registration export.
pub type QemuTcgExecCbFn = extern "C" fn(c_uint, u64, *mut c_void);
/// QEMU TCG-exec callback registration exported by `crucible-plugin-tcg-exec-cb`.
pub type QemuRegisterTcgExecCbFn = extern "C" fn(Option<QemuTcgExecCbFn>, *mut c_void);
/// Block submit callback body passed to QEMU's shmem block driver.
pub type QemuBlkSubmitCbFn = extern "C" fn(u32, u32, u64, *const u8, usize, *mut c_void) -> c_int;
/// Block completion poll callback body passed to QEMU's shmem block driver.
pub type QemuBlkPollCbFn = extern "C" fn(u32, *mut u8, usize, *mut c_void) -> i64;
/// QEMU shmem block callback registration exported by `crucible-blk-shmem`.
pub type QemuRegisterBlkCbFn =
    extern "C" fn(Option<QemuBlkSubmitCbFn>, Option<QemuBlkPollCbFn>, *mut c_void);
/// 9p burst callback body passed to QEMU's virtio-9p device.
pub type QemuNinePBurstCbFn = extern "C" fn(*mut c_void);
/// 9p submit callback body passed to QEMU's virtio-9p device.
pub type QemuNinePSubmitCbFn = extern "C" fn(u32, *const u8, usize, usize, *mut c_void) -> c_int;
/// 9p completion poll callback body passed to QEMU's virtio-9p device.
pub type QemuNinePPollCbFn = extern "C" fn(u32, *mut u8, usize, *mut c_void) -> i64;
/// QEMU shmem 9p callback registration exported by `crucible-dev-cb-api`.
pub type QemuRegisterNinePCbFn = extern "C" fn(
    Option<QemuNinePBurstCbFn>,
    Option<QemuNinePSubmitCbFn>,
    Option<QemuNinePPollCbFn>,
    Option<QemuNinePBurstCbFn>,
    *mut c_void,
);

/// Required runtime APIs added by the T-PATCH-11 QEMU patch group.
#[derive(Clone, Copy, Debug)]
pub struct PluginRuntimeApis {
    icount_raw: QemuIcountRawFn,
    force_vcpu_exit: QemuForceVcpuExitFn,
    register_wake_fd: QemuRegisterWakeFdFn,
    main_loop_wait: QemuMainLoopWaitFn,
    register_tcg_exec_cb: QemuRegisterTcgExecCbFn,
}

impl PluginRuntimeApis {
    /// Requires every T-PATCH-11 runtime export before install succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`QemuPluginAbiError::RuntimeApiCapability`] naming the first
    /// missing QEMU symbol.
    pub fn require(
        icount_raw: Option<QemuIcountRawFn>,
        force_vcpu_exit: Option<QemuForceVcpuExitFn>,
        register_wake_fd: Option<QemuRegisterWakeFdFn>,
        main_loop_wait: Option<QemuMainLoopWaitFn>,
        register_tcg_exec_cb: Option<QemuRegisterTcgExecCbFn>,
    ) -> Result<Self, QemuPluginAbiError> {
        Ok(Self {
            icount_raw: require_runtime_api(icount_raw, QEMU_PLUGIN_ICOUNT_RAW_SYMBOL)?,
            force_vcpu_exit: require_runtime_api(
                force_vcpu_exit,
                QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL,
            )?,
            register_wake_fd: require_runtime_api(
                register_wake_fd,
                QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL,
            )?,
            main_loop_wait: require_runtime_api(main_loop_wait, QEMU_PLUGIN_MAIN_LOOP_WAIT_SYMBOL)?,
            register_tcg_exec_cb: require_runtime_api(
                register_tcg_exec_cb,
                crate::QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL,
            )?,
        })
    }

    /// Returns the raw icount reader.
    #[must_use]
    pub const fn icount_raw(self) -> QemuIcountRawFn {
        self.icount_raw
    }

    /// Returns the current-vCPU exit requester.
    #[must_use]
    pub const fn force_vcpu_exit(self) -> QemuForceVcpuExitFn {
        self.force_vcpu_exit
    }

    /// Returns QEMU's wake-fd registration function.
    #[must_use]
    pub const fn register_wake_fd(self) -> QemuRegisterWakeFdFn {
        self.register_wake_fd
    }

    /// Returns QEMU's blocking main-loop wait function.
    #[must_use]
    pub const fn main_loop_wait(self) -> QemuMainLoopWaitFn {
        self.main_loop_wait
    }

    /// Returns QEMU's TCG-exec callback registration function.
    #[must_use]
    pub const fn register_tcg_exec_cb(self) -> QemuRegisterTcgExecCbFn {
        self.register_tcg_exec_cb
    }
}

/// Registration-time-initialized callback pointer table.
///
/// The table is immutable after construction. Re-entrant device paths can read
/// these pointers without taking a lifecycle lock, satisfying the self-deadlock
/// avoidance rule in RFC-0010 [PLUG-4]. Soundness depends on rejecting MTTCG so
/// process-local callback state remains serialized on the vCPU thread.
#[derive(Clone, Copy, Debug)]
pub struct RegisteredDeviceCallbacks {
    network_tx: InertDeviceCallback,
    network_rx: InertDeviceCallback,
    block_submit: InertDeviceCallback,
    block_poll: InertDeviceCallback,
    virtio9p_submit: InertDeviceCallback,
    virtio9p_poll: InertDeviceCallback,
    whitebox_doorbell: InertDeviceCallback,
}

impl RegisteredDeviceCallbacks {
    /// Returns the inert scaffold callback table.
    #[must_use]
    pub const fn inert() -> Self {
        Self {
            network_tx: crucible_qemu_plugin_inert_network_tx_cb,
            network_rx: crucible_qemu_plugin_inert_network_rx_cb,
            block_submit: crucible_qemu_plugin_inert_block_submit_cb,
            block_poll: crucible_qemu_plugin_inert_block_poll_cb,
            virtio9p_submit: crucible_qemu_plugin_inert_9p_submit_cb,
            virtio9p_poll: crucible_qemu_plugin_inert_9p_poll_cb,
            whitebox_doorbell: crucible_qemu_plugin_inert_whitebox_doorbell_cb,
        }
    }

    /// Returns the callback pointer for a callback family.
    #[must_use]
    pub const fn callback_for(self, kind: PluginDeviceCallbackKind) -> InertDeviceCallback {
        match kind {
            PluginDeviceCallbackKind::NetworkTx => self.network_tx,
            PluginDeviceCallbackKind::NetworkRx => self.network_rx,
            PluginDeviceCallbackKind::BlockSubmit => self.block_submit,
            PluginDeviceCallbackKind::BlockPoll => self.block_poll,
            PluginDeviceCallbackKind::Virtio9pSubmit => self.virtio9p_submit,
            PluginDeviceCallbackKind::Virtio9pPoll => self.virtio9p_poll,
            PluginDeviceCallbackKind::WhiteboxDoorbell => self.whitebox_doorbell,
        }
    }
}

/// Re-entrancy-safe partition of mutable lifecycle and immutable callback state.
#[derive(Clone, Debug)]
pub struct PluginStatePartition {
    lifecycle_core: PluginLifecycleCore,
    device_callbacks: RegisteredDeviceCallbacks,
    exact_deadline_reader: Option<ExactDeadlineReader>,
    synchronous_idle_advance: Option<SynchronousIdleAdvance>,
    preemption_injector: Option<PluginPreemptionInjector>,
    vcpu_introspector: Option<PluginVcpuIntrospector>,
    runtime_apis: Option<PluginRuntimeApis>,
}

impl PluginStatePartition {
    /// Builds the inert scaffold state partition.
    #[must_use]
    pub const fn inert(execution_model: QemuPluginExecutionModel) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: None,
            synchronous_idle_advance: None,
            preemption_injector: None,
            vcpu_introspector: None,
            runtime_apis: None,
        }
    }

    /// Builds scaffold state after requiring exact virtual-clock deadline support.
    #[must_use]
    pub const fn with_required_deadline(
        execution_model: QemuPluginExecutionModel,
        exact_deadline_reader: ExactDeadlineReader,
    ) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: Some(exact_deadline_reader),
            synchronous_idle_advance: None,
            preemption_injector: None,
            vcpu_introspector: None,
            runtime_apis: None,
        }
    }

    /// Builds scaffold state after requiring all idle-time QEMU capabilities.
    #[must_use]
    pub const fn with_required_time_capabilities(
        execution_model: QemuPluginExecutionModel,
        exact_deadline_reader: ExactDeadlineReader,
        synchronous_idle_advance: SynchronousIdleAdvance,
    ) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: Some(exact_deadline_reader),
            synchronous_idle_advance: Some(synchronous_idle_advance),
            preemption_injector: None,
            vcpu_introspector: None,
            runtime_apis: None,
        }
    }

    /// Builds scaffold state after requiring all RUN-time QEMU capabilities.
    #[must_use]
    pub const fn with_required_preemption_capabilities(
        execution_model: QemuPluginExecutionModel,
        exact_deadline_reader: ExactDeadlineReader,
        synchronous_idle_advance: SynchronousIdleAdvance,
        preemption_injector: PluginPreemptionInjector,
    ) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: Some(exact_deadline_reader),
            synchronous_idle_advance: Some(synchronous_idle_advance),
            preemption_injector: Some(preemption_injector),
            vcpu_introspector: None,
            runtime_apis: None,
        }
    }

    /// Builds scaffold state after requiring all fingerprint-time QEMU capabilities.
    #[must_use]
    pub const fn with_required_vcpu_introspection_capabilities(
        execution_model: QemuPluginExecutionModel,
        exact_deadline_reader: ExactDeadlineReader,
        synchronous_idle_advance: SynchronousIdleAdvance,
        preemption_injector: PluginPreemptionInjector,
        vcpu_introspector: PluginVcpuIntrospector,
    ) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: Some(exact_deadline_reader),
            synchronous_idle_advance: Some(synchronous_idle_advance),
            preemption_injector: Some(preemption_injector),
            vcpu_introspector: Some(vcpu_introspector),
            runtime_apis: None,
        }
    }

    /// Builds scaffold state after requiring all runtime QEMU capabilities.
    #[must_use]
    pub const fn with_required_runtime_api_capabilities(
        execution_model: QemuPluginExecutionModel,
        exact_deadline_reader: ExactDeadlineReader,
        synchronous_idle_advance: SynchronousIdleAdvance,
        preemption_injector: PluginPreemptionInjector,
        vcpu_introspector: PluginVcpuIntrospector,
        runtime_apis: PluginRuntimeApis,
    ) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: Some(exact_deadline_reader),
            synchronous_idle_advance: Some(synchronous_idle_advance),
            preemption_injector: Some(preemption_injector),
            vcpu_introspector: Some(vcpu_introspector),
            runtime_apis: Some(runtime_apis),
        }
    }

    /// Returns mutable lifecycle state owned by lifecycle callbacks.
    #[must_use]
    pub const fn lifecycle_core(&self) -> &PluginLifecycleCore {
        &self.lifecycle_core
    }

    /// Returns immutable device-callback pointers for re-entrant paths.
    #[must_use]
    pub const fn device_callbacks(&self) -> &RegisteredDeviceCallbacks {
        &self.device_callbacks
    }

    /// Returns the required exact deadline reader resolved during install, if present.
    #[must_use]
    pub const fn exact_deadline_reader(&self) -> Option<&ExactDeadlineReader> {
        self.exact_deadline_reader.as_ref()
    }

    /// Returns the synchronous direct-advance handle resolved during install, if present.
    #[must_use]
    pub const fn synchronous_idle_advance(&self) -> Option<&SynchronousIdleAdvance> {
        self.synchronous_idle_advance.as_ref()
    }

    /// Returns the commanded-preemption injector resolved during install, if present.
    #[must_use]
    pub const fn preemption_injector(&self) -> Option<&PluginPreemptionInjector> {
        self.preemption_injector.as_ref()
    }

    /// Returns the vCPU introspector resolved during install, if present.
    #[must_use]
    pub const fn vcpu_introspector(&self) -> Option<&PluginVcpuIntrospector> {
        self.vcpu_introspector.as_ref()
    }

    /// Returns the T-PATCH-11 runtime APIs resolved during install, if present.
    #[must_use]
    pub const fn runtime_apis(&self) -> Option<PluginRuntimeApis> {
        self.runtime_apis
    }
}

/// An error produced while validating the QEMU plugin ABI scaffold.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum QemuPluginAbiError {
    /// QEMU passed a negative argument count.
    #[error("QEMU plugin install argc {argc} is negative")]
    NegativeArgc {
        /// Rejected `argc` value.
        argc: c_int,
    },
    /// QEMU passed arguments but no argument vector.
    #[error("QEMU plugin install argv is null for argc {argc}")]
    MissingArgv {
        /// Positive `argc` value.
        argc: c_int,
    },
    /// QEMU did not provide plugin information.
    #[error("QEMU plugin install info pointer is null")]
    MissingInfo,
    /// One plugin argument pointer was null.
    #[error("QEMU plugin install argv[{index}] is null")]
    NullArgvEntry {
        /// Index of the null argument pointer.
        index: usize,
    },
    /// One plugin argument was not valid UTF-8.
    #[error("QEMU plugin install argv[{index}] is not valid UTF-8")]
    InvalidArgvUtf8 {
        /// Index of the non-UTF-8 argument.
        index: usize,
    },
    /// QEMU's plugin arguments failed Crucible's fail-closed parser.
    #[error("QEMU plugin install arguments are invalid: {source}")]
    PluginArgs {
        /// Underlying argument parser error.
        source: PluginArgsParseError,
    },
    /// QEMU's supported plugin API range does not include this plugin.
    #[error("QEMU plugin API range {min}..={cur} does not include required version {required}")]
    UnsupportedPluginApi {
        /// Minimum API version supported by QEMU.
        min: c_int,
        /// Current API version supported by QEMU.
        cur: c_int,
        /// Plugin API version exported by this crate.
        required: c_int,
    },
    /// QEMU reported zero guest vCPUs.
    #[error("QEMU plugin execution model has no vCPUs")]
    NoVcpus,
    /// QEMU is using multi-threaded TCG, which can re-enter plugin state concurrently.
    #[error("QEMU plugin requires single-threaded round-robin TCG, not MTTCG")]
    MultiThreadedTcg,
    /// The required exact deadline capability is unavailable.
    #[error("QEMU plugin exact deadline capability failed")]
    ExactDeadlineCapability {
        /// Underlying exact deadline error.
        source: ExactDeadlineError,
    },
    /// The required synchronous idle-advance capability is unavailable.
    #[error("QEMU plugin synchronous idle-advance capability failed")]
    SynchronousIdleAdvanceCapability {
        /// Underlying synchronous idle-advance error.
        source: SynchronousIdleAdvanceError,
    },
    /// The required commanded preemption-injection capability is unavailable.
    #[error("QEMU plugin preemption-injection capability failed")]
    PreemptionInjectionCapability {
        /// Underlying preemption injection error.
        source: PreemptionError,
    },
    /// The required vCPU introspection capability is unavailable.
    #[error("QEMU plugin vCPU introspection capability failed")]
    VcpuIntrospectionCapability {
        /// Underlying vCPU introspection error.
        source: VcpuIntrospectionError,
    },
    /// A required T-PATCH-11 runtime API export is unavailable.
    #[error("QEMU plugin runtime API capability {symbol} is unavailable")]
    RuntimeApiCapability {
        /// Missing QEMU symbol.
        symbol: &'static str,
    },
}

fn require_runtime_api<T>(symbol: Option<T>, name: &'static str) -> Result<T, QemuPluginAbiError> {
    symbol.ok_or(QemuPluginAbiError::RuntimeApiCapability { symbol: name })
}

/// Validates raw install arguments without dereferencing them.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when the `info` pointer is null, `argc` is
/// negative, or `argv` is null while `argc` is positive.
pub fn validate_install_boundary(
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> Result<(), QemuPluginAbiError> {
    if info.is_null() {
        return Err(QemuPluginAbiError::MissingInfo);
    }
    if argc < 0 {
        return Err(QemuPluginAbiError::NegativeArgc { argc });
    }
    if argc > 0 && argv.is_null() {
        return Err(QemuPluginAbiError::MissingArgv { argc });
    }
    Ok(())
}

/// Parses the QEMU plugin argument vector into Crucible's typed launch args.
///
/// QEMU exposes comma-separated `-plugin` options to plugins as an argument
/// vector. This helper accepts both QEMU's split vector form and the testable
/// single-string form by joining argv entries with commas before feeding the
/// existing fail-closed parser.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when `argc`/`argv` violate the raw ABI
/// boundary, an argv entry is null or non-UTF-8, or the parsed plugin arguments
/// omit required Crucible keys such as `simfd` and `slot`.
///
/// # ABI contract
///
/// This is a boundary shim: the raw `argv` pointer is dereferenced only inside
/// narrow `unsafe` blocks whose safety rests on QEMU's plugin ABI, which
/// guarantees that for positive `argc` the vector holds at least `argc` live,
/// NUL-terminated C-string entries for the duration of `qemu_plugin_install`.
/// Null-pointer shapes are rejected before any dereference, so the signature is
/// safe to call from Rust that already holds QEMU's argument vector. It is
/// crate-internal (`pub(crate)`): the only real caller is `qemu_plugin_install`
/// in this crate, which keeps the raw-pointer boundary confined here.
pub(crate) fn parse_install_plugin_args(
    argc: c_int,
    argv: *mut *mut c_char,
) -> Result<PluginArgs, QemuPluginAbiError> {
    if argc < 0 {
        return Err(QemuPluginAbiError::NegativeArgc { argc });
    }
    if argc > 0 && argv.is_null() {
        return Err(QemuPluginAbiError::MissingArgv { argc });
    }

    let argc = usize::try_from(argc).map_err(|_error| QemuPluginAbiError::NegativeArgc { argc })?;
    if argc == 0 {
        return Err(QemuPluginAbiError::PluginArgs {
            source: PluginArgsParseError::MissingRequiredKey {
                key: PLUGIN_ARG_SIMFD,
            },
        });
    }

    let mut raw_args = Vec::with_capacity(argc);
    for index in 0..argc {
        let arg = unsafe {
            // SAFETY: `argv` is non-null for positive `argc`, and QEMU provides
            // at least `argc` entries for the duration of `qemu_plugin_install`.
            *argv.add(index)
        };
        if arg.is_null() {
            return Err(QemuPluginAbiError::NullArgvEntry { index });
        }
        let arg = unsafe {
            // SAFETY: QEMU plugin argv entries are NUL-terminated C strings.
            CStr::from_ptr(arg)
        };
        let arg = arg
            .to_str()
            .map_err(|_error| QemuPluginAbiError::InvalidArgvUtf8 { index })?;
        raw_args.push(arg);
    }

    PluginArgs::parse(&raw_args.join(","))
        .map_err(|source| QemuPluginAbiError::PluginArgs { source })
}

/// Extracts and validates the execution model from QEMU install information.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError::UnsupportedPluginApi`] when QEMU's API range
/// excludes [`QEMU_PLUGIN_API_VERSION`]. Returns
/// [`QemuPluginAbiError::NoVcpus`] or
/// [`QemuPluginAbiError::MultiThreadedTcg`] when the execution model violates
/// the plugin's single-threaded round-robin TCG contract.
pub fn execution_model_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
) -> Result<QemuPluginExecutionModel, QemuPluginAbiError> {
    validate_qemu_plugin_api_range(info)?;
    let smp_vcpus =
        u32::try_from(info.system.smp_vcpus).map_err(|_error| QemuPluginAbiError::NoVcpus)?;
    QemuPluginExecutionModel::validate(smp_vcpus, threading)
}

/// Builds the inert install scaffold after raw boundary validation.
///
/// # Errors
///
/// This scaffold currently has no additional failure modes because
/// `execution_model` is already validated. The `Result` preserves the
/// registration-shim error surface for follow-up tasks.
pub const fn install_inert_scaffold(
    execution_model: QemuPluginExecutionModel,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    Ok(PluginStatePartition::inert(execution_model))
}

/// Builds install scaffold state after requiring exact-deadline introspection.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError::ExactDeadlineCapability`] when the required
/// `qemu_plugin_clock_deadline_ns` symbol is unavailable.
pub fn install_required_deadline_scaffold(
    execution_model: QemuPluginExecutionModel,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    Ok(PluginStatePartition::with_required_deadline(
        execution_model,
        exact_deadline_reader,
    ))
}

/// Builds install scaffold state after requiring all idle-time QEMU capabilities.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError::ExactDeadlineCapability`] when the exact
/// deadline export is unavailable, or
/// [`QemuPluginAbiError::SynchronousIdleAdvanceCapability`] when the direct
/// advance/drain export is unavailable.
pub fn install_required_time_capability_scaffold(
    execution_model: QemuPluginExecutionModel,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    let synchronous_idle_advance = SynchronousIdleAdvance::require(advance_virtual_time_direct)
        .map_err(|source| QemuPluginAbiError::SynchronousIdleAdvanceCapability { source })?;
    Ok(PluginStatePartition::with_required_time_capabilities(
        execution_model,
        exact_deadline_reader,
        synchronous_idle_advance,
    ))
}

/// Builds install scaffold state after requiring all preemption-time capabilities.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError::ExactDeadlineCapability`] when the exact
/// deadline export is unavailable,
/// [`QemuPluginAbiError::SynchronousIdleAdvanceCapability`] when the direct
/// advance/drain export is unavailable, or
/// [`QemuPluginAbiError::PreemptionInjectionCapability`] when the commanded
/// preemption-injection export is unavailable.
pub fn install_required_preemption_scaffold(
    execution_model: QemuPluginExecutionModel,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    let synchronous_idle_advance = SynchronousIdleAdvance::require(advance_virtual_time_direct)
        .map_err(|source| QemuPluginAbiError::SynchronousIdleAdvanceCapability { source })?;
    let preemption_injector = PluginPreemptionInjector::require(inject_preemption)
        .map_err(|source| QemuPluginAbiError::PreemptionInjectionCapability { source })?;
    Ok(PluginStatePartition::with_required_preemption_capabilities(
        execution_model,
        exact_deadline_reader,
        synchronous_idle_advance,
        preemption_injector,
    ))
}

/// Builds install scaffold state after requiring all fingerprint-time capabilities.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when any required time-control, preemption, or
/// vCPU-introspection export is unavailable.
pub fn install_required_vcpu_introspection_scaffold(
    execution_model: QemuPluginExecutionModel,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
    read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
    read_rr_cursor: Option<QemuReadRrCursorFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    let synchronous_idle_advance = SynchronousIdleAdvance::require(advance_virtual_time_direct)
        .map_err(|source| QemuPluginAbiError::SynchronousIdleAdvanceCapability { source })?;
    let preemption_injector = PluginPreemptionInjector::require(inject_preemption)
        .map_err(|source| QemuPluginAbiError::PreemptionInjectionCapability { source })?;
    let vcpu_introspector = PluginVcpuIntrospector::require(read_vcpu_regs, read_rr_cursor)
        .map_err(|source| QemuPluginAbiError::VcpuIntrospectionCapability { source })?;
    Ok(
        PluginStatePartition::with_required_vcpu_introspection_capabilities(
            execution_model,
            exact_deadline_reader,
            synchronous_idle_advance,
            preemption_injector,
            vcpu_introspector,
        ),
    )
}

/// Builds install scaffold state after requiring all T-PATCH-11 runtime APIs.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when any required deterministic plugin export
/// or T-PATCH-11 runtime API export is unavailable.
// crucible-lint: allow rust-allow -- ABI scaffold constructors mirror QEMU's runtime export list.
#[allow(clippy::too_many_arguments)]
pub fn install_required_runtime_api_scaffold(
    execution_model: QemuPluginExecutionModel,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
    read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
    read_rr_cursor: Option<QemuReadRrCursorFn>,
    icount_raw: Option<QemuIcountRawFn>,
    force_vcpu_exit: Option<QemuForceVcpuExitFn>,
    register_wake_fd: Option<QemuRegisterWakeFdFn>,
    main_loop_wait: Option<QemuMainLoopWaitFn>,
    register_tcg_exec_cb: Option<QemuRegisterTcgExecCbFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    let synchronous_idle_advance = SynchronousIdleAdvance::require(advance_virtual_time_direct)
        .map_err(|source| QemuPluginAbiError::SynchronousIdleAdvanceCapability { source })?;
    let preemption_injector = PluginPreemptionInjector::require(inject_preemption)
        .map_err(|source| QemuPluginAbiError::PreemptionInjectionCapability { source })?;
    let vcpu_introspector = PluginVcpuIntrospector::require(read_vcpu_regs, read_rr_cursor)
        .map_err(|source| QemuPluginAbiError::VcpuIntrospectionCapability { source })?;
    let runtime_apis = PluginRuntimeApis::require(
        icount_raw,
        force_vcpu_exit,
        register_wake_fd,
        main_loop_wait,
        register_tcg_exec_cb,
    )?;
    Ok(
        PluginStatePartition::with_required_runtime_api_capabilities(
            execution_model,
            exact_deadline_reader,
            synchronous_idle_advance,
            preemption_injector,
            vcpu_introspector,
            runtime_apis,
        ),
    )
}

/// Builds the inert install scaffold from QEMU install information.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when the QEMU API range, vCPU count, or TCG
/// threading mode violates the plugin ABI contract.
pub fn install_inert_scaffold_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_inert_scaffold(execution_model)
}

/// Builds required-deadline install scaffold state from QEMU install information.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when the execution model is unsupported or the
/// required exact-deadline symbol is unavailable.
pub fn install_required_deadline_scaffold_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_required_deadline_scaffold(execution_model, clock_deadline_ns)
}

/// Builds required idle-time capability scaffold state from QEMU install information.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when the execution model is unsupported, the
/// exact-deadline symbol is unavailable, or the synchronous direct-advance
/// symbol is unavailable.
pub fn install_required_time_capability_scaffold_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_required_time_capability_scaffold(
        execution_model,
        clock_deadline_ns,
        advance_virtual_time_direct,
    )
}

/// Builds required preemption capability scaffold state from QEMU install information.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when the execution model is unsupported, the
/// exact-deadline symbol is unavailable, the synchronous direct-advance symbol
/// is unavailable, or the commanded preemption-injection symbol is unavailable.
pub fn install_required_preemption_scaffold_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_required_preemption_scaffold(
        execution_model,
        clock_deadline_ns,
        advance_virtual_time_direct,
        inject_preemption,
    )
}

/// Builds required vCPU-introspection scaffold state from QEMU install information.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when the execution model is unsupported or any
/// required deterministic plugin export is unavailable.
pub fn install_required_vcpu_introspection_scaffold_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
    read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
    read_rr_cursor: Option<QemuReadRrCursorFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_required_vcpu_introspection_scaffold(
        execution_model,
        clock_deadline_ns,
        advance_virtual_time_direct,
        inject_preemption,
        read_vcpu_regs,
        read_rr_cursor,
    )
}

/// Builds required runtime-API scaffold state from QEMU install information.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when the execution model is unsupported or any
/// required deterministic plugin export is unavailable.
// crucible-lint: allow rust-allow -- QEMU install metadata expands to the required runtime exports.
#[allow(clippy::too_many_arguments)]
pub fn install_required_runtime_api_scaffold_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
    read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
    read_rr_cursor: Option<QemuReadRrCursorFn>,
    icount_raw: Option<QemuIcountRawFn>,
    force_vcpu_exit: Option<QemuForceVcpuExitFn>,
    register_wake_fd: Option<QemuRegisterWakeFdFn>,
    main_loop_wait: Option<QemuMainLoopWaitFn>,
    register_tcg_exec_cb: Option<QemuRegisterTcgExecCbFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_required_runtime_api_scaffold(
        execution_model,
        clock_deadline_ns,
        advance_virtual_time_direct,
        inject_preemption,
        read_vcpu_regs,
        read_rr_cursor,
        icount_raw,
        force_vcpu_exit,
        register_wake_fd,
        main_loop_wait,
        register_tcg_exec_cb,
    )
}

/// Resolves QEMU's required exact-deadline export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_clock_deadline_symbol() -> Option<QemuClockDeadlineFn> {
    #[cfg(test)]
    if let Some(symbol) = test_clock_deadline_symbol_override() {
        return Some(symbol);
    }

    // SAFETY: The symbol name is a static NUL-terminated byte string. `dlsym`
    // returns either null or a process symbol address. QEMU's patch defines this
    // symbol with the exact `extern "C" fn() -> i64` ABI used by
    // `QemuClockDeadlineFn`; callers fail closed when the symbol is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_clock_deadline_ns`, whose patched QEMU declaration is
        // `int64_t qemu_plugin_clock_deadline_ns(void)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuClockDeadlineFn>(symbol) })
    }
}

/// Resolves QEMU's required exact-deadline export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_clock_deadline_symbol() -> Option<QemuClockDeadlineFn> {
    None
}

/// Resolves QEMU's required synchronous direct-advance export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_advance_virtual_time_direct_symbol() -> Option<QemuAdvanceVirtualTimeDirectFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn(i64)` ABI used by
    // `QemuAdvanceVirtualTimeDirectFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_ADVANCE_VIRTUAL_TIME_DIRECT_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_advance_virtual_time_direct`, whose patched QEMU
        // declaration is `void qemu_plugin_advance_virtual_time_direct(int64_t)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuAdvanceVirtualTimeDirectFn>(symbol) })
    }
}

/// Resolves QEMU's required synchronous direct-advance export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_advance_virtual_time_direct_symbol()
-> Option<QemuAdvanceVirtualTimeDirectFn> {
    None
}

/// Resolves QEMU's required commanded-preemption export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_inject_preemption_symbol() -> Option<QemuInjectPreemptionFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact
    // `extern "C" fn(u64, u64, u64, c_uint, u32, u32, u32) -> c_int` ABI used
    // by `QemuInjectPreemptionFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_inject_preemption`, whose patched QEMU declaration
        // matches `QemuInjectPreemptionFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuInjectPreemptionFn>(symbol) })
    }
}

/// Resolves QEMU's required commanded-preemption export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_inject_preemption_symbol() -> Option<QemuInjectPreemptionFn> {
    None
}

/// Resolves QEMU's required per-vCPU register export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_read_vcpu_regs_symbol() -> Option<QemuReadVcpuRegsFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `QemuReadVcpuRegsFn` ABI used by the safe wrapper; callers
    // fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for `qemu_plugin_read_vcpu_regs`,
        // whose patched QEMU declaration matches `QemuReadVcpuRegsFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuReadVcpuRegsFn>(symbol) })
    }
}

/// Resolves QEMU's required per-vCPU register export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_read_vcpu_regs_symbol() -> Option<QemuReadVcpuRegsFn> {
    None
}

/// Resolves QEMU's required round-robin cursor export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_rr_cursor_symbol() -> Option<QemuReadRrCursorFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `QemuReadRrCursorFn` ABI used by the safe wrapper; callers
    // fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_RR_CURSOR_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for `qemu_plugin_rr_cursor`,
        // whose patched QEMU declaration matches `QemuReadRrCursorFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuReadRrCursorFn>(symbol) })
    }
}

/// Resolves QEMU's required round-robin cursor export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_rr_cursor_symbol() -> Option<QemuReadRrCursorFn> {
    None
}

/// Resolves QEMU's raw-icount read export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_icount_raw_symbol() -> Option<QemuIcountRawFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn() -> u64` ABI used by
    // `QemuIcountRawFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_ICOUNT_RAW_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for `qemu_plugin_icount_raw`,
        // whose patched QEMU declaration is `uint64_t qemu_plugin_icount_raw(void)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuIcountRawFn>(symbol) })
    }
}

/// Resolves QEMU's raw-icount read export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_icount_raw_symbol() -> Option<QemuIcountRawFn> {
    None
}

/// Resolves QEMU's current-vCPU exit export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_force_vcpu_exit_symbol() -> Option<QemuForceVcpuExitFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn()` ABI used by `QemuForceVcpuExitFn`;
    // callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_force_vcpu_exit`, whose patched QEMU declaration is
        // `void qemu_plugin_force_vcpu_exit(void)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuForceVcpuExitFn>(symbol) })
    }
}

/// Resolves QEMU's current-vCPU exit export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_force_vcpu_exit_symbol() -> Option<QemuForceVcpuExitFn> {
    None
}

/// Resolves QEMU's wake-fd registration export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_wake_fd_symbol() -> Option<QemuRegisterWakeFdFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn(c_int) -> c_int` ABI used by
    // `QemuRegisterWakeFdFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_wake_fd`, whose patched QEMU declaration is
        // `int qemu_plugin_register_wake_fd(int)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterWakeFdFn>(symbol) })
    }
}

/// Resolves QEMU's wake-fd registration export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_wake_fd_symbol() -> Option<QemuRegisterWakeFdFn> {
    None
}

/// Resolves QEMU's blocking main-loop wait export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_main_loop_wait_symbol() -> Option<QemuMainLoopWaitFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn()` ABI used by `QemuMainLoopWaitFn`;
    // callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_MAIN_LOOP_WAIT_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_main_loop_wait`, whose patched QEMU declaration is
        // `void qemu_plugin_main_loop_wait(void)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuMainLoopWaitFn>(symbol) })
    }
}

/// Resolves QEMU's blocking main-loop wait export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_main_loop_wait_symbol() -> Option<QemuMainLoopWaitFn> {
    None
}

/// Resolves QEMU's TCG-exec callback registration export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_tcg_exec_cb_symbol() -> Option<QemuRegisterTcgExecCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `QemuRegisterTcgExecCbFn` ABI; callers fail closed when
    // absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_tcg_exec_cb`, whose patched QEMU declaration
        // matches `QemuRegisterTcgExecCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterTcgExecCbFn>(symbol) })
    }
}

/// Resolves QEMU's TCG-exec callback registration export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_tcg_exec_cb_symbol() -> Option<QemuRegisterTcgExecCbFn> {
    None
}

/// Resolves QEMU's shmem block callback registration export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_blk_cb_symbol() -> Option<QemuRegisterBlkCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `QemuRegisterBlkCbFn` ABI; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_blk_cb`, whose patched QEMU declaration
        // matches `QemuRegisterBlkCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterBlkCbFn>(symbol) })
    }
}

/// Resolves QEMU's shmem block callback registration export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_blk_cb_symbol() -> Option<QemuRegisterBlkCbFn> {
    None
}

/// Resolves QEMU's shmem 9p callback registration export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_9p_cb_symbol() -> Option<QemuRegisterNinePCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `QemuRegisterNinePCbFn` ABI; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_9p_cb`, whose patched QEMU declaration
        // matches `QemuRegisterNinePCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterNinePCbFn>(symbol) })
    }
}

/// Resolves QEMU's shmem 9p callback registration export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_9p_cb_symbol() -> Option<QemuRegisterNinePCbFn> {
    None
}

fn validate_qemu_plugin_api_range(info: &QemuPluginInfo) -> Result<(), QemuPluginAbiError> {
    if info.version.min > QEMU_PLUGIN_API_VERSION || info.version.cur < QEMU_PLUGIN_API_VERSION {
        return Err(QemuPluginAbiError::UnsupportedPluginApi {
            min: info.version.min,
            cur: info.version.cur,
            required: QEMU_PLUGIN_API_VERSION,
        });
    }
    Ok(())
}

fn install_required_runtime_api_scaffold_from_boundary(
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    validate_install_boundary(info, argc, argv)?;
    // `parse_install_plugin_args` is a boundary shim: it rejects null shapes and
    // confines its `argv` dereferences to `// SAFETY`-justified `unsafe` blocks,
    // so it is called without an outer `unsafe` here.
    let _args = parse_install_plugin_args(argc, argv)?;
    // SAFETY: `validate_install_boundary` rejected null, and QEMU's plugin ABI
    // guarantees `info` points at a live `qemu_info_t` for this install call.
    // Only scalar fields are copied before the pointer lifetime ends.
    let info = unsafe { &*info };

    install_required_runtime_api_scaffold_from_qemu_info(
        info,
        QemuTcgThreading::SingleThreadedRoundRobin,
        resolve_qemu_clock_deadline_symbol(),
        resolve_qemu_advance_virtual_time_direct_symbol(),
        resolve_qemu_inject_preemption_symbol(),
        resolve_qemu_read_vcpu_regs_symbol(),
        resolve_qemu_rr_cursor_symbol(),
        resolve_qemu_icount_raw_symbol(),
        resolve_qemu_force_vcpu_exit_symbol(),
        resolve_qemu_register_wake_fd_symbol(),
        resolve_qemu_main_loop_wait_symbol(),
        resolve_qemu_register_tcg_exec_cb_symbol(),
    )
}

/// QEMU plugin API version exported for QEMU's loader compatibility check.
#[unsafe(no_mangle)]
pub static qemu_plugin_version: c_int = QEMU_PLUGIN_API_VERSION;

/// QEMU `cdylib` install entry point.
///
/// The install path validates the raw ABI shape and execution model, then fails
/// closed unless QEMU exposes the required exact-deadline, synchronous
/// direct-advance, commanded-preemption, vCPU-introspection, and T-PATCH-11
/// runtime API capabilities. Device callbacks remain inert until later tasks
/// replace the callback bodies.
///
/// # ABI contract
///
/// QEMU's `dlopen` loader calls this symbol, passing either a null `info`
/// pointer for an error result or a pointer to a live `qemu_info_t` with the AOS
/// QEMU 10.0.0 layout, and (for positive `argc`) this plugin's argument vector,
/// all valid for the duration of the call. The body forwards those raw inputs to
/// `install_required_runtime_api_scaffold_from_boundary`, which validates the
/// null shapes and confines every dereference to `// SAFETY`-justified `unsafe`
/// blocks, so this entry point needs no `unsafe` of its own. It keeps
/// `#[unsafe(no_mangle)] extern "C"` to satisfy QEMU's symbol-lookup contract.
#[unsafe(no_mangle)]
pub extern "C" fn qemu_plugin_install(
    _id: QemuPluginId,
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    match install_required_runtime_api_scaffold_from_boundary(info, argc, argv) {
        Ok(_state) => QEMU_PLUGIN_INSTALL_OK,
        Err(_error) => QEMU_PLUGIN_INSTALL_ERROR,
    }
}

/// Inert scaffold device and vCPU callbacks, grouped in a child module to keep
/// this file within the RFC-0010 file-shape limits.
mod inert_callbacks;
pub use inert_callbacks::{
    crucible_qemu_plugin_inert_9p_poll_cb, crucible_qemu_plugin_inert_9p_submit_cb,
    crucible_qemu_plugin_inert_block_poll_cb, crucible_qemu_plugin_inert_block_submit_cb,
    crucible_qemu_plugin_inert_network_rx_cb, crucible_qemu_plugin_inert_network_tx_cb,
    crucible_qemu_plugin_inert_vcpu_idle_cb, crucible_qemu_plugin_inert_vcpu_init_cb,
    crucible_qemu_plugin_inert_vcpu_resume_cb, crucible_qemu_plugin_inert_whitebox_doorbell_cb,
};

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::ptr::NonNull;

    const fn qemu_info_fixture(smp_vcpus: c_int, api_min: c_int, api_cur: c_int) -> QemuPluginInfo {
        QemuPluginInfo {
            target_name: std::ptr::null(),
            version: QemuPluginApiVersionRange {
                min: api_min,
                cur: api_cur,
            },
            system_emulation: true,
            system: QemuPluginSystemInfo {
                smp_vcpus,
                max_vcpus: smp_vcpus,
            },
        }
    }

    fn call_qemu_plugin_install(
        info: *const QemuPluginInfo,
        argc: c_int,
        argv: *mut *mut c_char,
    ) -> c_int {
        // Tests pass either live fixture pointers or boundary cases that
        // `validate_install_boundary` rejects before `info` is dereferenced; the
        // entry point is now a safe call.
        qemu_plugin_install(7, info, argc, argv)
    }

    fn plugin_argv(args: &[&str]) -> (Vec<CString>, Vec<*mut c_char>) {
        let strings = args
            .iter()
            .map(|arg| {
                CString::new(*arg).unwrap_or_else(|error| {
                    panic!("test plugin arg should not contain interior NUL: {error}")
                })
            })
            .collect::<Vec<_>>();
        let ptrs = strings
            .iter()
            .map(|arg| arg.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        (strings, ptrs)
    }

    fn valid_plugin_argv() -> (Vec<CString>, Vec<*mut c_char>) {
        plugin_argv(&[
            "simfd=3",
            "slot=0",
            "shmemfd=4",
            "wakefd=5",
            "whitebox=off",
            "coverage=off",
        ])
    }

    fn call_qemu_plugin_install_with_valid_args(info: *const QemuPluginInfo) -> c_int {
        let (_strings, mut argv) = valid_plugin_argv();
        call_qemu_plugin_install(info, argv.len() as c_int, argv.as_mut_ptr())
    }

    fn parse_install_plugin_args_for_test(
        argc: c_int,
        argv: *mut *mut c_char,
    ) -> Result<PluginArgs, QemuPluginAbiError> {
        // Tests pass either argv vectors backed by live `CString` fixtures, or
        // boundary cases that the parser rejects before reading; the shim is now
        // a safe call.
        parse_install_plugin_args(argc, argv)
    }

    #[test]
    fn abi_install_parses_qemu_plugin_argv_before_runtime_activation() {
        let (_strings, mut split_argv) = plugin_argv(&[
            "simfd=3",
            "slot=2",
            "shmemfd=4",
            "wakefd=5",
            "whitebox=off",
            "coverage=on",
        ]);

        let args =
            parse_install_plugin_args_for_test(split_argv.len() as c_int, split_argv.as_mut_ptr())
                .unwrap_or_else(|error| panic!("split QEMU argv should parse: {error}"));

        assert_eq!(args.sim_fd(), 3);
        assert_eq!(args.slot(), 2);
        assert_eq!(
            args.inherited_fds(),
            Some(crate::PluginInheritedFds {
                shmem_fd: 4,
                wake_fd: 5,
            })
        );
        assert!(!args.whitebox().is_on());
        assert!(args.coverage().is_on());

        let (_strings, mut single_argv) =
            plugin_argv(&["simfd=3,slot=0,shmemfd=4,wakefd=5,whitebox=on,coverage=off"]);
        let args = parse_install_plugin_args_for_test(1, single_argv.as_mut_ptr())
            .unwrap_or_else(|error| panic!("single QEMU argv should parse: {error}"));

        assert_eq!(args.sim_fd(), 3);
        assert_eq!(args.slot(), 0);
        assert!(args.whitebox().is_on());
        assert!(!args.coverage().is_on());
    }

    #[test]
    fn abi_install_plugin_argv_fails_closed_for_missing_and_malformed_args() {
        assert_eq!(
            parse_install_plugin_args_for_test(0, std::ptr::null_mut()).map(|_args| ()),
            Err(QemuPluginAbiError::PluginArgs {
                source: PluginArgsParseError::MissingRequiredKey {
                    key: PLUGIN_ARG_SIMFD,
                },
            })
        );

        let (_strings, mut missing_slot) = plugin_argv(&["simfd=3"]);
        assert_eq!(
            parse_install_plugin_args_for_test(1, missing_slot.as_mut_ptr()).map(|_args| ()),
            Err(QemuPluginAbiError::PluginArgs {
                source: PluginArgsParseError::MissingRequiredKey { key: "slot" },
            })
        );

        let mut null_entry = [std::ptr::null_mut()];
        assert_eq!(
            parse_install_plugin_args_for_test(1, null_entry.as_mut_ptr()).map(|_args| ()),
            Err(QemuPluginAbiError::NullArgvEntry { index: 0 })
        );

        let invalid_utf8 = CString::new(vec![0xff]).unwrap_or_else(|error| {
            panic!("test invalid UTF-8 argument should not contain interior NUL: {error}")
        });
        let mut invalid_utf8_argv = [invalid_utf8.as_ptr().cast_mut()];
        assert_eq!(
            parse_install_plugin_args_for_test(1, invalid_utf8_argv.as_mut_ptr()).map(|_args| ()),
            Err(QemuPluginAbiError::InvalidArgvUtf8 { index: 0 })
        );
    }

    #[test]
    fn abi_install_entrypoint_validates_raw_boundary_and_builds_inert_model() {
        let info = NonNull::<QemuPluginInfo>::dangling().as_ptr();
        let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);

        assert_eq!(
            validate_install_boundary(info, 0, std::ptr::null_mut()),
            Ok(())
        );
        assert_eq!(
            call_qemu_plugin_install_with_valid_args(&valid_info),
            QEMU_PLUGIN_INSTALL_ERROR
        );
        assert!(
            install_inert_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin
            )
            .is_ok()
        );
        assert_eq!(
            call_qemu_plugin_install(std::ptr::null(), 0, std::ptr::null_mut()),
            QEMU_PLUGIN_INSTALL_ERROR
        );
        assert_eq!(
            call_qemu_plugin_install(info, -1, std::ptr::null_mut()),
            QEMU_PLUGIN_INSTALL_ERROR
        );
        assert_eq!(
            call_qemu_plugin_install(info, 1, std::ptr::null_mut()),
            QEMU_PLUGIN_INSTALL_ERROR
        );
    }

    #[test]
    fn abi_qemu_install_path_validates_execution_model_before_success() {
        let single_vcpu = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);
        let multi_vcpu = qemu_info_fixture(4, 1, QEMU_PLUGIN_API_VERSION);
        let no_vcpu = qemu_info_fixture(0, 1, QEMU_PLUGIN_API_VERSION);
        let unsupported_api =
            qemu_info_fixture(1, QEMU_PLUGIN_API_VERSION + 1, QEMU_PLUGIN_API_VERSION + 1);

        assert_eq!(
            install_required_deadline_scaffold_from_qemu_info(
                &single_vcpu,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
            )
            .map(|state| state.exact_deadline_reader().is_some()),
            Ok(true)
        );
        assert_eq!(
            install_required_deadline_scaffold_from_qemu_info(
                &multi_vcpu,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
            )
            .map(|state| state.lifecycle_core().execution_model().smp_vcpus()),
            Ok(4)
        );
        assert_eq!(
            install_required_deadline_scaffold_from_qemu_info(
                &no_vcpu,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::NoVcpus)
        );
        assert_eq!(
            install_required_deadline_scaffold_from_qemu_info(
                &unsupported_api,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::UnsupportedPluginApi {
                min: QEMU_PLUGIN_API_VERSION + 1,
                cur: QEMU_PLUGIN_API_VERSION + 1,
                required: QEMU_PLUGIN_API_VERSION,
            })
        );
    }

    #[test]
    fn abi_install_entrypoint_fails_closed_without_exact_deadline_or_direct_advance_symbols() {
        let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);

        assert!(resolve_qemu_advance_virtual_time_direct_symbol().is_none());
        assert_eq!(
            call_qemu_plugin_install_with_valid_args(&valid_info),
            QEMU_PLUGIN_INSTALL_ERROR
        );
        assert_eq!(
            install_required_deadline_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                None,
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::ExactDeadlineCapability {
                source: ExactDeadlineError::CapabilityUnavailable {
                    symbol: crate::QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
                },
            })
        );
    }

    #[test]
    fn abi_install_entrypoint_requires_direct_advance_after_deadline_resolution() {
        let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);
        let _deadline_guard = TestClockDeadlineSymbolGuard::install(abi_test_deadline);
        let Some(deadline) = resolve_qemu_clock_deadline_symbol() else {
            panic!("test exported exact-deadline symbol should resolve");
        };

        assert_eq!(deadline(), 4096);
        assert!(resolve_qemu_advance_virtual_time_direct_symbol().is_none());
        assert_eq!(
            call_qemu_plugin_install_with_valid_args(&valid_info),
            QEMU_PLUGIN_INSTALL_ERROR
        );
    }

    #[test]
    fn abi_install_requires_synchronous_idle_advance_symbol() {
        let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);

        assert_eq!(
            install_required_time_capability_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
                Some(abi_test_direct_advance),
            )
            .map(|state| {
                (
                    state.exact_deadline_reader().is_some(),
                    state.synchronous_idle_advance().is_some(),
                )
            }),
            Ok((true, true))
        );
        assert_eq!(
            install_required_time_capability_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
                None,
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::SynchronousIdleAdvanceCapability {
                source: SynchronousIdleAdvanceError::CapabilityUnavailable {
                    symbol: crate::QEMU_PLUGIN_ADVANCE_VIRTUAL_TIME_DIRECT_SYMBOL,
                },
            })
        );
    }

    #[test]
    fn abi_install_requires_preemption_injection_symbol() {
        let valid_info = qemu_info_fixture(2, 1, QEMU_PLUGIN_API_VERSION);

        assert!(resolve_qemu_inject_preemption_symbol().is_none());
        assert_eq!(
            install_required_preemption_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
                Some(abi_test_direct_advance),
                Some(abi_test_inject_preemption),
            )
            .map(|state| {
                (
                    state.exact_deadline_reader().is_some(),
                    state.synchronous_idle_advance().is_some(),
                    state.preemption_injector().is_some(),
                )
            }),
            Ok((true, true, true))
        );
        assert_eq!(
            install_required_preemption_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
                Some(abi_test_direct_advance),
                None,
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::PreemptionInjectionCapability {
                source: PreemptionError::CapabilityUnavailable {
                    symbol: crate::QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL,
                },
            })
        );
    }

    #[test]
    fn abi_install_requires_vcpu_introspection_symbols() {
        let valid_info = qemu_info_fixture(2, 1, QEMU_PLUGIN_API_VERSION);

        assert!(resolve_qemu_read_vcpu_regs_symbol().is_none());
        assert!(resolve_qemu_rr_cursor_symbol().is_none());
        assert_eq!(
            install_required_vcpu_introspection_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
                Some(abi_test_direct_advance),
                Some(abi_test_inject_preemption),
                Some(abi_test_read_vcpu_regs),
                Some(abi_test_rr_cursor),
            )
            .map(|state| {
                (
                    state.exact_deadline_reader().is_some(),
                    state.synchronous_idle_advance().is_some(),
                    state.preemption_injector().is_some(),
                    state.vcpu_introspector().is_some(),
                )
            }),
            Ok((true, true, true, true))
        );
        assert_eq!(
            install_required_vcpu_introspection_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
                Some(abi_test_direct_advance),
                Some(abi_test_inject_preemption),
                None,
                Some(abi_test_rr_cursor),
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::VcpuIntrospectionCapability {
                source: VcpuIntrospectionError::CapabilityUnavailable {
                    symbol: crate::QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL,
                },
            })
        );
        assert_eq!(
            install_required_vcpu_introspection_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
                Some(abi_test_direct_advance),
                Some(abi_test_inject_preemption),
                Some(abi_test_read_vcpu_regs),
                None,
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::VcpuIntrospectionCapability {
                source: VcpuIntrospectionError::CapabilityUnavailable {
                    symbol: crate::QEMU_PLUGIN_RR_CURSOR_SYMBOL,
                },
            })
        );
    }

    #[test]
    fn abi_install_requires_t_patch_11_runtime_api_symbols() {
        let valid_info = qemu_info_fixture(2, 1, QEMU_PLUGIN_API_VERSION);

        let state = install_required_runtime_api_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            Some(abi_test_direct_advance),
            Some(abi_test_inject_preemption),
            Some(abi_test_read_vcpu_regs),
            Some(abi_test_rr_cursor),
            Some(abi_test_icount_raw),
            Some(abi_test_force_vcpu_exit),
            Some(abi_test_register_wake_fd),
            Some(abi_test_main_loop_wait),
            Some(abi_test_register_tcg_exec_cb),
        )
        .unwrap_or_else(|error| panic!("runtime API scaffold should install: {error}"));
        let runtime_apis = state
            .runtime_apis()
            .unwrap_or_else(|| panic!("runtime API handles should be retained"));

        assert_eq!((runtime_apis.icount_raw())(), 17);
        (runtime_apis.force_vcpu_exit())();
        assert_eq!((runtime_apis.register_wake_fd())(42), 0);
        (runtime_apis.main_loop_wait())();
        (runtime_apis.register_tcg_exec_cb())(None, std::ptr::null_mut());
        assert!(state.exact_deadline_reader().is_some());
        assert!(state.synchronous_idle_advance().is_some());
        assert!(state.preemption_injector().is_some());
        assert!(state.vcpu_introspector().is_some());

        assert_eq!(
            install_required_runtime_api_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
                Some(abi_test_direct_advance),
                Some(abi_test_inject_preemption),
                Some(abi_test_read_vcpu_regs),
                Some(abi_test_rr_cursor),
                None,
                Some(abi_test_force_vcpu_exit),
                Some(abi_test_register_wake_fd),
                Some(abi_test_main_loop_wait),
                Some(abi_test_register_tcg_exec_cb),
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::RuntimeApiCapability {
                symbol: QEMU_PLUGIN_ICOUNT_RAW_SYMBOL,
            })
        );
        assert_eq!(
            install_required_runtime_api_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                Some(abi_test_deadline),
                Some(abi_test_direct_advance),
                Some(abi_test_inject_preemption),
                Some(abi_test_read_vcpu_regs),
                Some(abi_test_rr_cursor),
                Some(abi_test_icount_raw),
                Some(abi_test_force_vcpu_exit),
                Some(abi_test_register_wake_fd),
                Some(abi_test_main_loop_wait),
                None,
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::RuntimeApiCapability {
                symbol: crate::QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL,
            })
        );
    }

    #[test]
    fn abi_install_full_capability_scaffold_fails_closed_without_exact_deadline() {
        let valid_info = qemu_info_fixture(2, 1, QEMU_PLUGIN_API_VERSION);

        assert_eq!(
            install_required_vcpu_introspection_scaffold_from_qemu_info(
                &valid_info,
                QemuTcgThreading::SingleThreadedRoundRobin,
                None,
                Some(abi_test_direct_advance),
                Some(abi_test_inject_preemption),
                Some(abi_test_read_vcpu_regs),
                Some(abi_test_rr_cursor),
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::ExactDeadlineCapability {
                source: ExactDeadlineError::CapabilityUnavailable {
                    symbol: crate::QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
                },
            })
        );
    }

    #[test]
    fn abi_execution_model_requires_single_threaded_tcg_not_single_vcpu_only() {
        let single =
            match QemuPluginExecutionModel::validate(1, QemuTcgThreading::SingleThreadedRoundRobin)
            {
                Ok(model) => model,
                Err(error) => panic!("single-vCPU RR-TCG should validate: {error}"),
            };
        let multi =
            match QemuPluginExecutionModel::validate(4, QemuTcgThreading::SingleThreadedRoundRobin)
            {
                Ok(model) => model,
                Err(error) => panic!("multi-vCPU RR-TCG should validate: {error}"),
            };

        assert!(single.is_single_vcpu());
        assert!(!multi.is_single_vcpu());
        assert_eq!(multi.smp_vcpus(), 4);
        assert_eq!(
            QemuPluginExecutionModel::validate(0, QemuTcgThreading::SingleThreadedRoundRobin),
            Err(QemuPluginAbiError::NoVcpus)
        );
        assert_eq!(
            QemuPluginExecutionModel::validate(1, QemuTcgThreading::MultiThreadedTcg),
            Err(QemuPluginAbiError::MultiThreadedTcg)
        );
    }

    #[test]
    fn abi_safe_scaffold_shim_rejects_invalid_models() {
        let single_vcpu = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);
        let multi_vcpu = qemu_info_fixture(4, 1, QEMU_PLUGIN_API_VERSION);
        let no_vcpu = qemu_info_fixture(0, 1, QEMU_PLUGIN_API_VERSION);
        let negative_vcpu = qemu_info_fixture(-1, 1, QEMU_PLUGIN_API_VERSION);

        assert!(
            install_inert_scaffold_from_qemu_info(
                &single_vcpu,
                QemuTcgThreading::SingleThreadedRoundRobin
            )
            .is_ok()
        );
        assert!(
            install_inert_scaffold_from_qemu_info(
                &multi_vcpu,
                QemuTcgThreading::SingleThreadedRoundRobin
            )
            .is_ok()
        );
        assert_eq!(
            install_inert_scaffold_from_qemu_info(
                &no_vcpu,
                QemuTcgThreading::SingleThreadedRoundRobin
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::NoVcpus)
        );
        assert_eq!(
            install_inert_scaffold_from_qemu_info(
                &negative_vcpu,
                QemuTcgThreading::SingleThreadedRoundRobin
            )
            .map(|_state| ()),
            Err(QemuPluginAbiError::NoVcpus)
        );
        assert_eq!(
            install_inert_scaffold_from_qemu_info(&single_vcpu, QemuTcgThreading::MultiThreadedTcg)
                .map(|_state| ()),
            Err(QemuPluginAbiError::MultiThreadedTcg)
        );
    }

    #[test]
    fn abi_state_partition_keeps_device_callbacks_immutable_and_reentrant_safe() {
        let model =
            match QemuPluginExecutionModel::validate(1, QemuTcgThreading::SingleThreadedRoundRobin)
            {
                Ok(model) => model,
                Err(error) => panic!("test execution model should validate: {error}"),
            };
        let state = match install_inert_scaffold(model) {
            Ok(state) => state,
            Err(error) => panic!("inert scaffold should install: {error}"),
        };

        assert_eq!(
            state.lifecycle_core().phase(),
            PluginLifecyclePhase::InstalledInert
        );
        assert_eq!(state.lifecycle_core().execution_model(), model);
        assert!(state.exact_deadline_reader().is_none());
        assert!(state.synchronous_idle_advance().is_none());
        assert!(state.preemption_injector().is_none());
        assert!(state.vcpu_introspector().is_none());
        for kind in OWNED_DEVICE_CALLBACK_KINDS {
            let callback = state.device_callbacks().callback_for(kind);
            callback(7, std::ptr::null_mut());
        }
    }

    extern "C" fn abi_test_deadline() -> i64 {
        4096
    }

    extern "C" fn abi_test_direct_advance(_target_virtual_ns: i64) {}

    extern "C" fn abi_test_inject_preemption(
        _at_icount: u64,
        _deadline_icount: u64,
        _ceiling_icount: u64,
        _raw_kind: c_uint,
        _arg0: u32,
        _arg1: u32,
        _arg2: u32,
    ) -> c_int {
        0
    }

    extern "C" fn abi_test_read_vcpu_regs(
        _vcpu_id: u32,
        _out_register_bytes: *mut u8,
        _out_register_capacity: usize,
        _out_register_len: *mut usize,
        _out_retired_instruction_count: *mut u64,
    ) -> c_int {
        0
    }

    extern "C" fn abi_test_rr_cursor(_out_cursor: *mut crate::QemuRoundRobinCursor) -> c_int {
        0
    }

    extern "C" fn abi_test_icount_raw() -> u64 {
        17
    }

    extern "C" fn abi_test_force_vcpu_exit() {}

    extern "C" fn abi_test_register_wake_fd(_fd: c_int) -> c_int {
        0
    }

    extern "C" fn abi_test_main_loop_wait() {}

    extern "C" fn abi_test_register_tcg_exec_cb(
        _callback: Option<QemuTcgExecCbFn>,
        _userdata: *mut c_void,
    ) {
    }

    struct TestClockDeadlineSymbolGuard;

    impl TestClockDeadlineSymbolGuard {
        fn install(symbol: QemuClockDeadlineFn) -> Self {
            set_test_clock_deadline_symbol(Some(symbol));
            Self
        }
    }

    impl Drop for TestClockDeadlineSymbolGuard {
        fn drop(&mut self) {
            set_test_clock_deadline_symbol(None);
        }
    }
}
