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

use std::os::raw::{c_char, c_int, c_uint, c_void};

use crate::{
    ExactDeadlineError, ExactDeadlineReader, QemuAdvanceVirtualTimeDirectFn, QemuClockDeadlineFn,
    SynchronousIdleAdvance, SynchronousIdleAdvanceError,
};

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
/// QEMU 9.2.4. The scaffold copies only scalar ABI-version and vCPU-count
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
/// QEMU plugin API version exported by AOS QEMU 9.2.4.
pub const QEMU_PLUGIN_API_VERSION: c_int = 4;
/// The exported symbol QEMU resolves when loading this `cdylib`.
pub const QEMU_PLUGIN_INSTALL_SYMBOL: &str = "qemu_plugin_install";
/// The exported symbol QEMU checks before calling the install hook.
pub const QEMU_PLUGIN_VERSION_SYMBOL: &str = "qemu_plugin_version";
/// Compatibility label for RFC text that calls the install hook `Register`.
pub const QEMU_PLUGIN_REGISTER_ENTRYPOINT_SYMBOL: &str = QEMU_PLUGIN_INSTALL_SYMBOL;
/// Minimum supported vCPU count under single-threaded round-robin TCG.
pub const MIN_SUPPORTED_VCPU_COUNT: u32 = 1;
const QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL_C: &[u8] = b"qemu_plugin_clock_deadline_ns\0";
const QEMU_PLUGIN_ADVANCE_VIRTUAL_TIME_DIRECT_SYMBOL_C: &[u8] =
    b"qemu_plugin_advance_virtual_time_direct\0";

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

fn install_required_deadline_scaffold_from_boundary(
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> Result<PluginStatePartition, QemuPluginAbiError> {
    validate_install_boundary(info, argc, argv)?;
    // SAFETY: `validate_install_boundary` rejected null, and QEMU's plugin ABI
    // guarantees `info` points at a live `qemu_info_t` for this install call.
    // Only scalar fields are copied before the pointer lifetime ends.
    let info = unsafe { &*info };

    install_required_time_capability_scaffold_from_qemu_info(
        info,
        QemuTcgThreading::SingleThreadedRoundRobin,
        resolve_qemu_clock_deadline_symbol(),
        resolve_qemu_advance_virtual_time_direct_symbol(),
    )
}

/// QEMU plugin API version exported for QEMU's loader compatibility check.
#[unsafe(no_mangle)]
pub static qemu_plugin_version: c_int = QEMU_PLUGIN_API_VERSION;

/// QEMU `cdylib` install entry point.
///
/// The install path validates the raw ABI shape and execution model, then fails
/// closed unless QEMU exposes the required exact-deadline and synchronous
/// direct-advance capabilities. Device callbacks remain inert until later tasks
/// replace the callback bodies.
///
/// # Safety
///
/// QEMU must pass either a null `info` pointer for an error result, or a pointer
/// to a live `qemu_info_t` with the AOS QEMU 9.2.4 layout for the duration of
/// this call. When `argc` is positive, `argv` must be QEMU's plugin argument
/// vector for this loaded plugin.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qemu_plugin_install(
    _id: QemuPluginId,
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    match install_required_deadline_scaffold_from_boundary(info, argc, argv) {
        Ok(_state) => QEMU_PLUGIN_INSTALL_OK,
        Err(_error) => QEMU_PLUGIN_INSTALL_ERROR,
    }
}

/// Inert scaffold network-TX callback.
pub extern "C" fn crucible_qemu_plugin_inert_network_tx_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold network-RX callback.
pub extern "C" fn crucible_qemu_plugin_inert_network_rx_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold block-submit callback.
pub extern "C" fn crucible_qemu_plugin_inert_block_submit_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold block-poll callback.
pub extern "C" fn crucible_qemu_plugin_inert_block_poll_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold 9p-submit callback.
pub extern "C" fn crucible_qemu_plugin_inert_9p_submit_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold 9p-poll callback.
pub extern "C" fn crucible_qemu_plugin_inert_9p_poll_cb(_id: QemuPluginId, _userdata: *mut c_void) {
}

/// Inert scaffold white-box doorbell callback.
pub extern "C" fn crucible_qemu_plugin_inert_whitebox_doorbell_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold vCPU init callback.
pub extern "C" fn crucible_qemu_plugin_inert_vcpu_init_cb(_id: QemuPluginId, _vcpu_index: c_uint) {}

/// Inert scaffold vCPU idle callback.
pub extern "C" fn crucible_qemu_plugin_inert_vcpu_idle_cb(_id: QemuPluginId, _vcpu_index: c_uint) {}

/// Inert scaffold vCPU resume callback.
pub extern "C" fn crucible_qemu_plugin_inert_vcpu_resume_cb(
    _id: QemuPluginId,
    _vcpu_index: c_uint,
) {
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // SAFETY: tests pass either live fixture pointers or boundary cases that
        // `validate_install_boundary` rejects before `info` is dereferenced.
        unsafe { qemu_plugin_install(7, info, argc, argv) }
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
            call_qemu_plugin_install(&valid_info, 0, std::ptr::null_mut()),
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
            call_qemu_plugin_install(&valid_info, 0, std::ptr::null_mut()),
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
            call_qemu_plugin_install(&valid_info, 0, std::ptr::null_mut()),
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
        for kind in OWNED_DEVICE_CALLBACK_KINDS {
            let callback = state.device_callbacks().callback_for(kind);
            callback(7, std::ptr::null_mut());
        }
    }

    extern "C" fn abi_test_deadline() -> i64 {
        4096
    }

    extern "C" fn abi_test_direct_advance(_target_virtual_ns: i64) {}

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
