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
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::raw::{c_char, c_int, c_uint, c_void};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::{
    ExactDeadlineError, ExactDeadlineReader, QemuAdvanceTimeNsFn, QemuClockDeadlineFn,
    QemuInjectPreemptionFn, QemuReadRrCursorFn, QemuReadVcpuRegsFn, QemuRegisterTimeAdvanceCbFn,
    QemuRequestTimeControlFn, QueuedIdleAdvance, QueuedIdleAdvanceError,
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
/// QEMU plugin API symbol used to request a clean or fail-loud process shutdown.
pub const QEMU_PLUGIN_REQUEST_SHUTDOWN_SYMBOL: &str = "qemu_plugin_request_shutdown";
/// QEMU plugin API symbol used to register shmem block submit/poll callbacks.
pub const QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL: &str = "qemu_plugin_register_blk_cb";
/// QEMU plugin API symbol used to register the blocked-device wait callback.
pub const QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL: &str = "qemu_plugin_register_blk_wait_cb";
/// QEMU plugin API symbol used to register shmem 9p burst/submit/poll callbacks.
pub const QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL: &str = "qemu_plugin_register_9p_cb";
/// QEMU plugin API symbol used to register the standard vCPU-init callback.
pub const QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL: &str = "qemu_plugin_register_vcpu_init_cb";
/// QEMU plugin API symbol used to register Crucible all-idle/resume callbacks.
pub const QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL: &str =
    "qemu_plugin_register_vcpu_idle_resume_cb";
/// QEMU plugin API symbol used to connect the sim loop to shared-memory time state.
pub const QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL: &str =
    "qemu_plugin_register_sim_shmem_dispatch_cb";
/// Minimum supported vCPU count under single-threaded round-robin TCG.
pub const MIN_SUPPORTED_VCPU_COUNT: u32 = 1;
const QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL_C: &[u8] = b"qemu_plugin_clock_deadline_ns\0";
const QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL_C: &[u8] = b"qemu_plugin_advance_time_ns\0";
const QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_time_advance_cb\0";
const QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL_C: &[u8] = b"qemu_plugin_inject_preemption\0";
const QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL_C: &[u8] = b"qemu_plugin_read_vcpu_regs\0";
const QEMU_PLUGIN_RR_CURSOR_SYMBOL_C: &[u8] = b"qemu_plugin_rr_cursor\0";
const QEMU_PLUGIN_ICOUNT_RAW_SYMBOL_C: &[u8] = b"qemu_plugin_icount_raw\0";
const QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL_C: &[u8] = b"qemu_plugin_force_vcpu_exit\0";
const QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL_C: &[u8] = b"qemu_plugin_register_wake_fd\0";
const QEMU_PLUGIN_REQUEST_SHUTDOWN_SYMBOL_C: &[u8] = b"qemu_plugin_request_shutdown\0";
const QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_tcg_exec_cb\0";
const QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_vcpu_tb_trans_cb\0";
const QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_vcpu_tb_exec_cb\0";
const QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL_C: &[u8] = b"qemu_plugin_icount_at_tb_entry\0";
const QEMU_PLUGIN_REGISTER_FLUSH_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_flush_cb\0";
const QEMU_PLUGIN_TB_VADDR_SYMBOL_C: &[u8] = b"qemu_plugin_tb_vaddr\0";
const QEMU_PLUGIN_TB_N_INSNS_SYMBOL_C: &[u8] = b"qemu_plugin_tb_n_insns\0";
const QEMU_PLUGIN_TB_GET_INSN_SYMBOL_C: &[u8] = b"qemu_plugin_tb_get_insn\0";
const QEMU_PLUGIN_INSN_SIZE_SYMBOL_C: &[u8] = b"qemu_plugin_insn_size\0";
const QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_blk_cb\0";
const QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_blk_wait_cb\0";
const QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_9p_cb\0";
const QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_vcpu_init_cb\0";
const QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_vcpu_idle_resume_cb\0";
const QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_sim_shmem_dispatch_cb\0";
const QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL_C: &[u8] = b"qemu_plugin_request_time_control\0";
const QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_single_threaded_rr\0";
/// QEMU capability required to observe the callback serialization mode.
pub const QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL: &str = "qemu_plugin_crucible_single_threaded_rr";
/// QEMU callback-serialization proof returning one only for single-threaded RR.
pub type QemuSingleThreadedRrFn = extern "C" fn() -> c_int;

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

    /// Marks the lifecycle active after the full registration sequence succeeds.
    const fn activate(&mut self) {
        self.phase = PluginLifecyclePhase::Active;
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
/// QEMU shutdown request function; nonzero selects the fail-loud host-error path.
pub type QemuRequestShutdownFn = extern "C" fn(c_int);
/// TCG-exec callback body passed to QEMU's registration export.
pub type QemuTcgExecCbFn = extern "C" fn(c_uint, u64, *mut c_void);
/// QEMU TCG-exec callback registration exported by `crucible-plugin-tcg-exec-cb`.
pub type QemuRegisterTcgExecCbFn = extern "C" fn(Option<QemuTcgExecCbFn>, *mut c_void);
/// Block submit callback body passed to QEMU's shmem block driver.
pub type QemuBlkSubmitCbFn = extern "C" fn(u32, u32, u64, *const u8, usize, *mut c_void) -> c_int;
/// Block completion poll callback body passed to QEMU's shmem block driver.
pub type QemuBlkPollCbFn = extern "C" fn(u32, *mut u8, usize, *mut c_void) -> i64;
/// Block device-wait callback body passed to QEMU's shmem block driver.
pub type QemuBlkWaitCbFn = extern "C" fn(u32, *mut c_void);
/// QEMU shmem block callback registration exported by `crucible-blk-shmem`.
pub type QemuRegisterBlkCbFn =
    extern "C" fn(Option<QemuBlkSubmitCbFn>, Option<QemuBlkPollCbFn>, *mut c_void);
/// QEMU shmem block wait registration exported by the device-completion patch.
pub type QemuRegisterBlkWaitCbFn = extern "C" fn(Option<QemuBlkWaitCbFn>, *mut c_void);
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
/// Standard QEMU vCPU lifecycle callback body.
pub type QemuVcpuSimpleCbFn = extern "C" fn(QemuPluginId, c_uint);
/// Standard QEMU vCPU-init callback registration function.
pub type QemuRegisterVcpuInitCbFn = extern "C" fn(QemuPluginId, QemuVcpuSimpleCbFn);
/// Crucible all-vCPUs-idle or resume callback body.
pub type QemuVcpuIdleResumeCbFn = extern "C" fn(c_uint, u64, *mut c_void);
/// QEMU registration function for Crucible all-idle and resume callbacks.
pub type QemuRegisterVcpuIdleResumeCbFn =
    extern "C" fn(Option<QemuVcpuIdleResumeCbFn>, Option<QemuVcpuIdleResumeCbFn>, *mut c_void);
/// Sim-loop callback that publishes the raw aggregate instruction count.
pub type QemuSimShmemPublishIcountCbFn = extern "C" fn(u64, *mut c_void);
/// Sim-loop callback that reads the scheduler-published instruction ceiling.
pub type QemuSimShmemMaxAdvanceIcountCbFn = extern "C" fn(*mut c_void) -> u64;
/// QEMU registration function for sim-loop shared-memory time dispatch.
pub type QemuRegisterSimShmemDispatchCbFn = extern "C" fn(
    Option<QemuSimShmemPublishIcountCbFn>,
    Option<QemuSimShmemMaxAdvanceIcountCbFn>,
    *mut c_void,
);

/// Required runtime APIs added by the T-PATCH-11 QEMU patch group.
#[derive(Clone, Copy, Debug)]
pub struct PluginRuntimeApis {
    icount_raw: QemuIcountRawFn,
    force_vcpu_exit: QemuForceVcpuExitFn,
    register_wake_fd: QemuRegisterWakeFdFn,
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
    queued_idle_advance: Option<QueuedIdleAdvance>,
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
            queued_idle_advance: None,
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
            queued_idle_advance: None,
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
        queued_idle_advance: QueuedIdleAdvance,
    ) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: Some(exact_deadline_reader),
            queued_idle_advance: Some(queued_idle_advance),
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
        queued_idle_advance: QueuedIdleAdvance,
        preemption_injector: PluginPreemptionInjector,
    ) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: Some(exact_deadline_reader),
            queued_idle_advance: Some(queued_idle_advance),
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
        queued_idle_advance: QueuedIdleAdvance,
        preemption_injector: PluginPreemptionInjector,
        vcpu_introspector: PluginVcpuIntrospector,
    ) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: Some(exact_deadline_reader),
            queued_idle_advance: Some(queued_idle_advance),
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
        queued_idle_advance: QueuedIdleAdvance,
        preemption_injector: PluginPreemptionInjector,
        vcpu_introspector: PluginVcpuIntrospector,
        runtime_apis: PluginRuntimeApis,
    ) -> Self {
        Self {
            lifecycle_core: PluginLifecycleCore::installed_inert(execution_model),
            device_callbacks: RegisteredDeviceCallbacks::inert(),
            exact_deadline_reader: Some(exact_deadline_reader),
            queued_idle_advance: Some(queued_idle_advance),
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

    /// Returns the queued idle-advance handle resolved during install, if present.
    #[must_use]
    pub const fn queued_idle_advance(&self) -> Option<&QueuedIdleAdvance> {
        self.queued_idle_advance.as_ref()
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

    /// Marks this state active after setup, callback registration, and the boot barrier.
    pub(crate) const fn activate(
        &mut self,
        _ready: &crate::PluginRegistrationReady,
        _owned_callbacks: &crate::RequiredOwnedCallbacksRegistered,
    ) {
        self.lifecycle_core.activate();
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
    /// QEMU loaded the plugin outside system emulation.
    #[error("QEMU plugin requires system emulation")]
    NotSystemEmulation,
    /// QEMU is using multi-threaded TCG, which can re-enter plugin state concurrently.
    #[error("QEMU plugin requires single-threaded round-robin TCG, not MTTCG")]
    MultiThreadedTcg,
    /// The required exact deadline capability is unavailable.
    #[error("QEMU plugin exact deadline capability failed")]
    ExactDeadlineCapability {
        /// Underlying exact deadline error.
        source: ExactDeadlineError,
    },
    /// The required queued idle-advance capability is unavailable.
    #[error("QEMU plugin queued idle-advance capability failed")]
    QueuedIdleAdvanceCapability {
        /// Underlying queued idle-advance error.
        source: QueuedIdleAdvanceError,
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
/// # Safety
///
/// For positive `argc`, `argv` must point to at least `argc` live pointers to
/// NUL-terminated C strings for the duration of this call. Null pointer shapes
/// are rejected, but pointer provenance and allocation extent cannot be checked.
pub(crate) unsafe fn parse_install_plugin_args(
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
    if !info.system_emulation {
        return Err(QemuPluginAbiError::NotSystemEmulation);
    }
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
/// [`QemuPluginAbiError::QueuedIdleAdvanceCapability`] when the queued advance
/// export is unavailable.
pub fn install_required_time_capability_scaffold(
    execution_model: QemuPluginExecutionModel,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_time_ns: Option<QemuAdvanceTimeNsFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    let queued_idle_advance = QueuedIdleAdvance::require(advance_time_ns)
        .map_err(|source| QemuPluginAbiError::QueuedIdleAdvanceCapability { source })?;
    Ok(PluginStatePartition::with_required_time_capabilities(
        execution_model,
        exact_deadline_reader,
        queued_idle_advance,
    ))
}

/// Builds install scaffold state after requiring all preemption-time capabilities.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError::ExactDeadlineCapability`] when the exact
/// deadline export is unavailable,
/// [`QemuPluginAbiError::QueuedIdleAdvanceCapability`] when the queued advance
/// export is unavailable, or
/// [`QemuPluginAbiError::PreemptionInjectionCapability`] when the commanded
/// preemption-injection export is unavailable.
pub fn install_required_preemption_scaffold(
    execution_model: QemuPluginExecutionModel,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    let queued_idle_advance = QueuedIdleAdvance::require(advance_time_ns)
        .map_err(|source| QemuPluginAbiError::QueuedIdleAdvanceCapability { source })?;
    let preemption_injector = PluginPreemptionInjector::require(inject_preemption)
        .map_err(|source| QemuPluginAbiError::PreemptionInjectionCapability { source })?;
    Ok(PluginStatePartition::with_required_preemption_capabilities(
        execution_model,
        exact_deadline_reader,
        queued_idle_advance,
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
    advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
    read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
    read_rr_cursor: Option<QemuReadRrCursorFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    let queued_idle_advance = QueuedIdleAdvance::require(advance_time_ns)
        .map_err(|source| QemuPluginAbiError::QueuedIdleAdvanceCapability { source })?;
    let preemption_injector = PluginPreemptionInjector::require(inject_preemption)
        .map_err(|source| QemuPluginAbiError::PreemptionInjectionCapability { source })?;
    let vcpu_introspector = PluginVcpuIntrospector::require(read_vcpu_regs, read_rr_cursor)
        .map_err(|source| QemuPluginAbiError::VcpuIntrospectionCapability { source })?;
    Ok(
        PluginStatePartition::with_required_vcpu_introspection_capabilities(
            execution_model,
            exact_deadline_reader,
            queued_idle_advance,
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
    advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
    read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
    read_rr_cursor: Option<QemuReadRrCursorFn>,
    icount_raw: Option<QemuIcountRawFn>,
    force_vcpu_exit: Option<QemuForceVcpuExitFn>,
    register_wake_fd: Option<QemuRegisterWakeFdFn>,
    register_tcg_exec_cb: Option<QemuRegisterTcgExecCbFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    let queued_idle_advance = QueuedIdleAdvance::require(advance_time_ns)
        .map_err(|source| QemuPluginAbiError::QueuedIdleAdvanceCapability { source })?;
    let preemption_injector = PluginPreemptionInjector::require(inject_preemption)
        .map_err(|source| QemuPluginAbiError::PreemptionInjectionCapability { source })?;
    let vcpu_introspector = PluginVcpuIntrospector::require(read_vcpu_regs, read_rr_cursor)
        .map_err(|source| QemuPluginAbiError::VcpuIntrospectionCapability { source })?;
    let runtime_apis = PluginRuntimeApis::require(
        icount_raw,
        force_vcpu_exit,
        register_wake_fd,
        register_tcg_exec_cb,
    )?;
    Ok(
        PluginStatePartition::with_required_runtime_api_capabilities(
            execution_model,
            exact_deadline_reader,
            queued_idle_advance,
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
/// exact-deadline symbol is unavailable, or the queued idle-advance
/// symbol is unavailable.
pub fn install_required_time_capability_scaffold_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_time_ns: Option<QemuAdvanceTimeNsFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_required_time_capability_scaffold(execution_model, clock_deadline_ns, advance_time_ns)
}

/// Builds required preemption capability scaffold state from QEMU install information.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when the execution model is unsupported, the
/// exact-deadline symbol is unavailable, the queued idle-advance symbol
/// is unavailable, or the commanded preemption-injection symbol is unavailable.
pub fn install_required_preemption_scaffold_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
    clock_deadline_ns: Option<QemuClockDeadlineFn>,
    advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_required_preemption_scaffold(
        execution_model,
        clock_deadline_ns,
        advance_time_ns,
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
    advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
    read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
    read_rr_cursor: Option<QemuReadRrCursorFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_required_vcpu_introspection_scaffold(
        execution_model,
        clock_deadline_ns,
        advance_time_ns,
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
    advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    inject_preemption: Option<QemuInjectPreemptionFn>,
    read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
    read_rr_cursor: Option<QemuReadRrCursorFn>,
    icount_raw: Option<QemuIcountRawFn>,
    force_vcpu_exit: Option<QemuForceVcpuExitFn>,
    register_wake_fd: Option<QemuRegisterWakeFdFn>,
    register_tcg_exec_cb: Option<QemuRegisterTcgExecCbFn>,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    let execution_model = execution_model_from_qemu_info(info, threading)?;
    install_required_runtime_api_scaffold(
        execution_model,
        clock_deadline_ns,
        advance_time_ns,
        inject_preemption,
        read_vcpu_regs,
        read_rr_cursor,
        icount_raw,
        force_vcpu_exit,
        register_wake_fd,
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

/// Resolves QEMU's required queued idle-advance export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_advance_time_ns_symbol() -> Option<QemuAdvanceTimeNsFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn(i64) -> c_int` ABI used by
    // `QemuAdvanceTimeNsFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_advance_time_ns`, whose patched QEMU
        // declaration is `int qemu_plugin_advance_time_ns(int64_t)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuAdvanceTimeNsFn>(symbol) })
    }
}

/// Resolves QEMU's required queued idle-advance export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_advance_time_ns_symbol() -> Option<QemuAdvanceTimeNsFn> {
    None
}

/// Resolves QEMU's required queued-advance completion registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_time_advance_cb_symbol() -> Option<QemuRegisterTimeAdvanceCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C"` registration ABI used by
    // `QemuRegisterTimeAdvanceCbFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_time_advance_cb`, whose patched QEMU declaration
        // accepts the matching callback and userdata pointer and returns `int`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterTimeAdvanceCbFn>(symbol) })
    }
}

/// Resolves QEMU's required queued-advance completion registration export.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_time_advance_cb_symbol() -> Option<QemuRegisterTimeAdvanceCbFn> {
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

/// Resolves QEMU's plugin-initiated shutdown export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_request_shutdown_symbol() -> Option<QemuRequestShutdownFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or the patched QEMU function declared as `void (int)`.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REQUEST_SHUTDOWN_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address was resolved by the exact QEMU export
        // name whose C argument and return types match this Rust alias.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRequestShutdownFn>(symbol) })
    }
}

/// Resolves QEMU's plugin-initiated shutdown export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_request_shutdown_symbol() -> Option<QemuRequestShutdownFn> {
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

#[cfg(unix)]
fn resolve_process_symbol(symbol_name: &'static [u8]) -> *mut c_void {
    // SAFETY: every caller supplies a static NUL-terminated symbol name. The
    // returned address is checked for null and converted only to the exact ABI
    // type declared by QEMU 10's public plugin header.
    unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr().cast()) }
}

/// Resolves the complete QEMU API for live basic-block coverage.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError::RuntimeApiCapability`] when any required
/// translation, execution, metadata, exact-icount, or flush symbol is absent.
#[cfg(unix)]
pub(crate) fn resolve_qemu_basic_block_coverage_apis()
-> Result<crate::QemuBasicBlockCoverageApis, QemuPluginAbiError> {
    let register_tb_trans_cb =
        resolve_process_symbol(QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL_C);
    let register_tb_exec_cb = resolve_process_symbol(QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_CB_SYMBOL_C);
    let tb_vaddr = resolve_process_symbol(QEMU_PLUGIN_TB_VADDR_SYMBOL_C);
    let tb_n_insns = resolve_process_symbol(QEMU_PLUGIN_TB_N_INSNS_SYMBOL_C);
    let tb_get_insn = resolve_process_symbol(QEMU_PLUGIN_TB_GET_INSN_SYMBOL_C);
    let insn_size = resolve_process_symbol(QEMU_PLUGIN_INSN_SIZE_SYMBOL_C);
    let icount_at_tb_entry = resolve_process_symbol(QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL_C);
    let register_flush_cb = resolve_process_symbol(QEMU_PLUGIN_REGISTER_FLUSH_CB_SYMBOL_C);
    let require = |symbol: *mut c_void, name| {
        if symbol.is_null() {
            Err(QemuPluginAbiError::RuntimeApiCapability { symbol: name })
        } else {
            Ok(symbol)
        }
    };
    let register_tb_trans_cb = require(
        register_tb_trans_cb,
        crate::QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL,
    )?;
    let register_tb_exec_cb = require(
        register_tb_exec_cb,
        crate::QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_CB_SYMBOL,
    )?;
    let tb_vaddr = require(tb_vaddr, crate::QEMU_PLUGIN_TB_VADDR_SYMBOL)?;
    let tb_n_insns = require(tb_n_insns, crate::QEMU_PLUGIN_TB_N_INSNS_SYMBOL)?;
    let tb_get_insn = require(tb_get_insn, crate::QEMU_PLUGIN_TB_GET_INSN_SYMBOL)?;
    let insn_size = require(insn_size, crate::QEMU_PLUGIN_INSN_SIZE_SYMBOL)?;
    let icount_at_tb_entry = require(
        icount_at_tb_entry,
        crate::QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL,
    )?;
    let register_flush_cb = require(
        register_flush_cb,
        crate::QEMU_PLUGIN_REGISTER_FLUSH_CB_SYMBOL,
    )?;

    // SAFETY: all non-null addresses were resolved by their exact QEMU 10
    // public-plugin symbol names and are converted to matching `extern "C"`
    // function-pointer types.
    Ok(unsafe {
        crate::QemuBasicBlockCoverageApis::new(
            std::mem::transmute::<*mut c_void, crate::QemuRegisterVcpuTbTransCbFn>(
                register_tb_trans_cb,
            ),
            std::mem::transmute::<*mut c_void, crate::QemuRegisterVcpuTbExecCbFn>(
                register_tb_exec_cb,
            ),
            std::mem::transmute::<*mut c_void, crate::QemuTbVaddrFn>(tb_vaddr),
            std::mem::transmute::<*mut c_void, crate::QemuTbNInsnsFn>(tb_n_insns),
            std::mem::transmute::<*mut c_void, crate::QemuTbGetInsnFn>(tb_get_insn),
            std::mem::transmute::<*mut c_void, crate::QemuInsnSizeFn>(insn_size),
            std::mem::transmute::<*mut c_void, crate::QemuIcountAtTbEntryFn>(icount_at_tb_entry),
            std::mem::transmute::<*mut c_void, crate::QemuRegisterFlushCbFn>(register_flush_cb),
        )
    })
}

/// Reports that live basic-block coverage is unavailable off Unix.
///
/// # Errors
///
/// Always returns [`QemuPluginAbiError::RuntimeApiCapability`] because the
/// process-symbol lookup used by the live QEMU plugin is Unix-only.
#[cfg(not(unix))]
pub(crate) const fn resolve_qemu_basic_block_coverage_apis()
-> Result<crate::QemuBasicBlockCoverageApis, QemuPluginAbiError> {
    Err(QemuPluginAbiError::RuntimeApiCapability {
        symbol: crate::QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL,
    })
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

/// Resolves QEMU's shmem block device-wait registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_blk_wait_cb_symbol() -> Option<QemuRegisterBlkWaitCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. Patch 0039 defines the exact
    // `QemuRegisterBlkWaitCbFn` ABI; callers fail closed when it is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address is the exact block-wait registration
        // symbol whose C declaration matches `QemuRegisterBlkWaitCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterBlkWaitCbFn>(symbol) })
    }
}

/// Reports that QEMU's shmem block device-wait registration is unavailable.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_blk_wait_cb_symbol() -> Option<QemuRegisterBlkWaitCbFn> {
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

/// Resolves QEMU's standard vCPU-init callback registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_vcpu_init_cb_symbol() -> Option<QemuRegisterVcpuInitCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU 10.0.0 declares this name
    // with the exact `QemuRegisterVcpuInitCbFn` ABI.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address was resolved by the exact standard QEMU
        // API name whose declaration matches `QemuRegisterVcpuInitCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterVcpuInitCbFn>(symbol) })
    }
}

/// Resolves no vCPU-init registration export outside Unix QEMU environments.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_vcpu_init_cb_symbol() -> Option<QemuRegisterVcpuInitCbFn> {
    None
}

/// Resolves QEMU's Crucible all-idle/resume callback registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_vcpu_idle_resume_cb_symbol() -> Option<QemuRegisterVcpuIdleResumeCbFn>
{
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name. The
    // Crucible patch declares this symbol with the exact callback ABI above.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the exact patched API name establishes the function type.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterVcpuIdleResumeCbFn>(symbol) })
    }
}

/// Resolves no all-idle/resume registration export outside Unix QEMU environments.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_vcpu_idle_resume_cb_symbol()
-> Option<QemuRegisterVcpuIdleResumeCbFn> {
    None
}

/// Resolves QEMU's sim-loop shared-memory dispatch registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_sim_shmem_dispatch_cb_symbol()
-> Option<QemuRegisterSimShmemDispatchCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name. The
    // Crucible patch declares this symbol with the exact callback ABI above.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the exact patched API name establishes the function type.
        Some(unsafe {
            std::mem::transmute::<*mut c_void, QemuRegisterSimShmemDispatchCbFn>(symbol)
        })
    }
}

/// Resolves no sim-loop shmem registration export outside Unix QEMU environments.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_sim_shmem_dispatch_cb_symbol()
-> Option<QemuRegisterSimShmemDispatchCbFn> {
    None
}

/// Resolves QEMU's virtual-time ownership request from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_request_time_control_symbol() -> Option<QemuRequestTimeControlFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU declares this symbol as a
    // no-argument function returning a borrowed opaque pointer.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null symbol was resolved by its exact QEMU API name,
        // whose declaration is `const void *qemu_plugin_request_time_control(void)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRequestTimeControlFn>(symbol) })
    }
}

/// Resolves no time-control request outside Unix QEMU plugin environments.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_request_time_control_symbol() -> Option<QemuRequestTimeControlFn> {
    None
}

/// Resolves QEMU's observable single-threaded round-robin mode proof.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_single_threaded_rr_symbol() -> Option<QemuSingleThreadedRrFn> {
    // SAFETY: the symbol name is static and NUL-terminated. A non-null result
    // is invoked only with the required `int fn(void)` ABI.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the required export has the exact ABI above.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuSingleThreadedRrFn>(symbol) })
    }
}

#[cfg(not(unix))]
const fn resolve_qemu_single_threaded_rr_symbol() -> Option<QemuSingleThreadedRrFn> {
    None
}

fn observed_execution_model<F>(
    info: &QemuPluginInfo,
    resolve_single_threaded_rr: F,
) -> Result<QemuPluginExecutionModel, QemuPluginAbiError>
where
    F: FnOnce() -> Option<QemuSingleThreadedRrFn>,
{
    let execution_model =
        execution_model_from_qemu_info(info, QemuTcgThreading::SingleThreadedRoundRobin)?;
    let single_threaded_rr =
        resolve_single_threaded_rr().ok_or(QemuPluginAbiError::RuntimeApiCapability {
            symbol: QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL,
        })?;
    if single_threaded_rr() != 1 {
        return Err(QemuPluginAbiError::MultiThreadedTcg);
    }
    Ok(execution_model)
}

/// Duplicates the inherited control descriptor into an owned Unix stream.
///
/// # Errors
///
/// Returns the operating-system error from `fcntl(F_DUPFD_CLOEXEC)` when the
/// inherited descriptor is invalid or cannot be duplicated.
#[cfg(unix)]
pub(crate) fn duplicate_control_stream(fd: c_int) -> std::io::Result<UnixStream> {
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` accepts an integer descriptor and either
    // fails without creating a resource or returns a new live owned descriptor.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful `F_DUPFD_CLOEXEC` return is a new descriptor whose
    // ownership is transferred exactly once into `OwnedFd`.
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    Ok(UnixStream::from(owned))
}

#[cfg(unix)]
struct OwnedInstallBoundary {
    args: PluginArgs,
    execution_model: QemuPluginExecutionModel,
}

#[cfg(unix)]
/// Copies QEMU-owned install inputs into process-owned Rust values.
///
/// # Safety
///
/// `info` and the positive-length `argv` vector must satisfy the same lifetime,
/// layout, and NUL-termination contract as [`qemu_plugin_install`].
unsafe fn copy_install_boundary(
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> Result<OwnedInstallBoundary, QemuPluginAbiError> {
    validate_install_boundary(info, argc, argv)?;
    // SAFETY: the caller guarantees the positive-length QEMU argument vector is
    // live and contains NUL-terminated entries for this install call.
    let args = unsafe { parse_install_plugin_args(argc, argv) }?;
    // SAFETY: boundary shape validation rejected null. QEMU's plugin ABI
    // guarantees a live info object; only scalar data is copied into owned state.
    let info = unsafe { &*info };
    let execution_model = observed_execution_model(info, resolve_qemu_single_threaded_rr_symbol)?;
    Ok(OwnedInstallBoundary {
        args,
        execution_model,
    })
}

#[cfg(unix)]
fn install_owned_boundary(
    plugin_id: QemuPluginId,
    boundary: OwnedInstallBoundary,
    reservation: &mut crate::runtime::PluginRuntimeReservation,
) -> Result<crate::PluginRuntimeOwner, crate::runtime::PluginLiveBoundaryError> {
    let clock_deadline_ns = resolve_qemu_clock_deadline_symbol();
    let advance_time_ns = resolve_qemu_advance_time_ns_symbol();
    let register_time_advance_cb = resolve_qemu_register_time_advance_cb_symbol();
    let inject_preemption = resolve_qemu_inject_preemption_symbol();
    let read_vcpu_regs = resolve_qemu_read_vcpu_regs_symbol();
    let read_rr_cursor = resolve_qemu_rr_cursor_symbol();
    let icount_raw = resolve_qemu_icount_raw_symbol();
    let force_vcpu_exit = resolve_qemu_force_vcpu_exit_symbol();
    let register_wake_fd = resolve_qemu_register_wake_fd_symbol();
    let request_shutdown = resolve_qemu_request_shutdown_symbol();
    let register_tcg_exec_cb = resolve_qemu_register_tcg_exec_cb_symbol();
    let register_vcpu_init = resolve_qemu_register_vcpu_init_cb_symbol();
    let register_vcpu_idle_resume = resolve_qemu_register_vcpu_idle_resume_cb_symbol();
    let register_sim_shmem_dispatch = resolve_qemu_register_sim_shmem_dispatch_cb_symbol();
    let register_net_tx = crate::resolve_qemu_register_net_tx_cb_symbol();
    let net_send = crate::resolve_qemu_net_send_symbol();
    let net_flush = crate::resolve_qemu_net_flush_symbol();
    let register_block = resolve_qemu_register_blk_cb_symbol();
    let register_block_wait = resolve_qemu_register_blk_wait_cb_symbol();
    let register_ninep = resolve_qemu_register_9p_cb_symbol();
    let state = install_required_runtime_api_scaffold(
        boundary.execution_model,
        clock_deadline_ns,
        advance_time_ns,
        inject_preemption,
        read_vcpu_regs,
        read_rr_cursor,
        icount_raw,
        force_vcpu_exit,
        register_wake_fd,
        register_tcg_exec_cb,
    )?;
    let runtime_apis = state
        .runtime_apis()
        .ok_or(QemuPluginAbiError::RuntimeApiCapability {
            symbol: QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL,
        })?;
    let request_shutdown =
        require_runtime_api(request_shutdown, QEMU_PLUGIN_REQUEST_SHUTDOWN_SYMBOL)?;
    let basic_block_coverage = if boundary.args.coverage().is_on() {
        Some(resolve_qemu_basic_block_coverage_apis()?)
    } else {
        None
    };
    let capabilities = crate::runtime::LiveInstallCapabilities {
        icount_raw: runtime_apis.icount_raw(),
        request_time_control: resolve_qemu_request_time_control_symbol(),
        clock_deadline_ns,
        advance_time_ns,
        register_time_advance_cb,
        register_wake_fd: runtime_apis.register_wake_fd(),
        request_shutdown,
        basic_block_coverage,
        register_vcpu_init,
        register_vcpu_idle_resume,
        register_sim_shmem_dispatch,
        register_net_tx,
        net_send,
        net_flush,
        register_block,
        register_block_wait,
        register_ninep,
    };
    let callback_registrar = crate::runtime::FailClosedOwnedCallbackRegistrar::production(
        plugin_id,
        boundary.execution_model,
        &capabilities,
    );
    crate::runtime::install_live_runtime(
        plugin_id,
        boundary.args,
        state,
        capabilities,
        &callback_registrar,
        reservation,
    )
    .map_err(Into::into)
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

/// QEMU plugin API version exported for QEMU's loader compatibility check.
#[unsafe(no_mangle)]
pub static qemu_plugin_version: c_int = QEMU_PLUGIN_API_VERSION;

/// QEMU `cdylib` install entry point.
///
/// The install path validates the raw ABI shape and execution model, requires
/// every deterministic QEMU capability, and executes the typed control/setup
/// sequence. It fails closed at callback registration until every plugin-owned
/// device adapter is live; only a fully registered runtime may acknowledge
/// readiness and be retained for process lifetime.
///
/// # Safety
///
/// `info` must point to a live QEMU 10.0.0 `qemu_info_t` for the duration of
/// this call. When `argc` is positive, `argv` must point to at least `argc`
/// live pointers to NUL-terminated C strings for the same duration.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qemu_plugin_install(
    id: QemuPluginId,
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    #[cfg(unix)]
    {
        run_install_trampoline(|| {
            let mut reservation = crate::runtime::reserve_runtime()?;
            // SAFETY: the exported function's caller contract guarantees the
            // QEMU info and argv allocations remain live for this call.
            let boundary = unsafe { copy_install_boundary(info, argc, argv) }?;
            let runtime = install_owned_boundary(id, boundary, &mut reservation)?;
            reservation.publish(runtime);
            Ok(())
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (id, info, argc, argv);
        QEMU_PLUGIN_INSTALL_ERROR
    }
}

#[cfg(unix)]
fn run_install_trampoline<F>(install: F) -> c_int
where
    F: FnOnce() -> Result<(), crate::runtime::PluginLiveBoundaryError>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(install)) {
        Ok(Ok(())) => QEMU_PLUGIN_INSTALL_OK,
        Ok(Err(error)) => {
            crate::runtime::emit_install_failure_diagnostic(&error);
            QEMU_PLUGIN_INSTALL_ERROR
        }
        Err(_panic) => {
            use std::io::Write as _;

            let _write_result = std::io::stderr()
                .lock()
                .write_all(b"crucible-qemu-plugin: install panicked; registration aborted\n");
            QEMU_PLUGIN_INSTALL_ERROR
        }
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
mod tests;
