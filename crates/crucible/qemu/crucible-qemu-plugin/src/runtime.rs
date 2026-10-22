//! Live QEMU plugin installation and process-lifetime runtime ownership.
//!
//! This module joins the existing typed registration stages without weakening
//! their fail-stop boundaries. The active owner is published only after the
//! complete required callback set is registered, `SetupAck(0)` is sent, and the
//! mapped boot barrier releases. Production preflight validates every callback
//! required by the selected launch mode before the control handshake or any
//! QEMU callback registration; optional white-box mode remains closed until its
//! concrete trap and guest-memory callback ABI is available.

mod error;
pub(crate) use error::PluginLiveBoundaryError;
pub use error::{OwnedCallbackRegistrationError, PluginRuntimeInstallError};

mod callback_child;
pub(crate) mod callback_quiescence;
mod checkpoint;
mod command_receive;
mod command_storage;
mod control_component;
mod fingerprint;
mod registration_groups;
mod registration_owner;
mod publisher_service;
mod resource_manifest;
pub(crate) use checkpoint::reader::{
    CaptureLoan, HeldClaimCleanup, HeldReadContext, HeldReaderIdentity,
};
pub(crate) use fingerprint::{FingerprintApi, FingerprintBorrowContext, FingerprintLoan};
use resource_manifest::{plugin_resource_manifest, plugin_worker_mask};

pub(crate) use checkpoint::{LocalDisposition, NativeMailbox, NativeRoot, RootStage};
mod device_workspace;
mod hot_fork;
pub(crate) mod live_callbacks;
mod live_whitebox;
pub use live_whitebox::{GuestIntrospectionTransportError, LiveWhiteboxError};
pub(crate) mod required_workers;
pub use required_workers::{
    CleanupError as RequiredWorkerCleanupError, Error as RequiredWorkerError,
    Failure as RequiredWorkerFailure,
};
#[cfg(not(test))]
mod native_worker;
mod parent_park;
pub(crate) mod prebirth;
mod teardown_latch;
mod worker_quiescence;
mod workspace_mapping;
use teardown_latch::LiveRuntimeTeardownRouter;
use teardown_latch::{TriggerConsumer, TriggerPublisher};

use callback_quiescence::LiveCallbackQuiescence;
use hot_fork::{
    check_hot_fork_network_rx, crucible_qemu_plugin_hot_fork_barrier,
    crucible_qemu_plugin_hot_fork_child_runtime, hot_fork_child_process_generation_matches,
};

#[cfg(test)]
use hot_fork::{
    collect_hot_fork_state_with_network_rx_check, host_mapping_extent,
    hot_fork_child_endpoint_identity_matches, hot_fork_child_mapping_basis_matches,
    hot_fork_control_socket_cookie, hot_fork_eventfd_identity_token_from_fdinfo,
    hot_fork_wake_eventfd_id,
};

use worker_quiescence::{
    LiveWorkerQuiescence, WORKER_RUN_CONTROL, WORKER_TEARDOWN, WorkerQuiescenceSnapshot,
};
#[cfg(test)]
use worker_quiescence::{WORKER_FINGERPRINT, WORKER_REQUIRED};

#[cfg(test)]
use live_callbacks::clear_live_callback_registration_for_test;
pub use live_callbacks::{FingerprintWorkerFailure, LiveDeviceCallbackError, LiveVcpuTimeCallbackError};
use live_callbacks::{LiveVcpuTimeCallbackCapabilities, LiveVcpuTimeCallbackRegistrar};
#[cfg(test)]
use resource_manifest::{
    PLUGIN_CALLBACK_REQUIRED, PLUGIN_RESOURCE_FINGERPRINT, PLUGIN_RESOURCE_MANIFEST_VERSION,
    PLUGIN_RESOURCE_REQUIRED,
};

#[cfg(unix)]
use crate::startup_source::SetupControlSocket;
#[cfg(unix)]
use std::io::{self, Read as _, Write as _};
use std::marker::PhantomPinned;
#[cfg(unix)]
use std::os::fd::BorrowedFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
#[cfg(test)]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use thiserror::Error;

#[cfg(unix)]
use crucible_qemu_protocol::ControlLifecycleStream;
#[cfg(unix)]
use crucible_qemu_shmem::{NodeSlot, RegionHeader};

use crate::coverage::{LiveBasicBlockCoverage, LiveCoverageShmemProducer};
#[cfg(unix)]
use crate::setup::signal_teardown_wake_fd;
use crate::{
    BootBarrierRelease, CoverageCapabilities, CoverageError, PluginArgs, PluginRegistrationReady,
    PluginRegistrationSequence, PluginRegistrationSequenceError, PluginRegistrationStep,
    PluginSetupCompletion, PluginSetupError, PluginTimeControlOwnership, QemuAdvanceTimeTicksFn,
    QemuBasicBlockCoverageApis, QemuClockDeadlineFn, QemuPluginId, QemuRegisterWakeFdFn,
    QemuRequestShutdownFn, QemuRequestTimeControlFn, send_callback_registration_failure_ack,
};
use crate::{PluginHostQuit, PluginShutdownRequested};
#[cfg(unix)]
use crate::{PluginQemuShutdownError, PluginTeardown};

/// One production teardown proof delivered to the sole teardown worker.
pub(super) enum LiveRuntimeTeardownTrigger {
    /// The lifecycle reader consumed host `Quit` during RUN.
    HostQuit(PluginHostQuit),
    /// A live callback acquire-observed the shared shutdown flag.
    SharedShutdown(PluginShutdownRequested),
    /// RUN control was malformed, unsolicited, closed, or otherwise unreadable.
    RunControlFault { diagnostic: String },
}

/// Exact QEMU-staged resource basis installed into one fork child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HotForkChildResourceBinding {
    parent_process_generation: u64,
    child_process_generation: u64,
    template_generation: u64,
    private_ring_generation: u64,
    plugin_endpoint_generation: u64,
    plugin_barrier_generation: u64,
    control_socket_cookie: u64,
    wake_eventfd_id: u64,
    source_mapping_start: u64,
    source_mapping_length: u64,
    source_mapping_offset: u64,
    account_generation: u64,
    workspace_generation: u64,
    workspace_device: u64,
    workspace_inode: u64,
    workspace_length: u64,
    workspace_fd: i32,
}

impl Default for HotForkChildResourceBinding {
    fn default() -> Self {
        Self {
            parent_process_generation: 0,
            child_process_generation: 0,
            template_generation: 0,
            private_ring_generation: 0,
            plugin_endpoint_generation: 0,
            plugin_barrier_generation: 0,
            control_socket_cookie: 0,
            wake_eventfd_id: 0,
            source_mapping_start: 0,
            source_mapping_length: 0,
            source_mapping_offset: 0,
            account_generation: 0,
            workspace_generation: 0,
            workspace_device: 0,
            workspace_inode: 0,
            workspace_length: 0,
            workspace_fd: -1,
        }
    }
}

impl From<crate::QemuPluginHotForkChildPlan> for HotForkChildResourceBinding {
    fn from(plan: crate::QemuPluginHotForkChildPlan) -> Self {
        Self {
            parent_process_generation: plan.parent_process_generation,
            child_process_generation: plan.child_process_generation,
            template_generation: plan.template_generation,
            private_ring_generation: plan.private_ring_generation,
            plugin_endpoint_generation: plan.plugin_endpoint_generation,
            plugin_barrier_generation: plan.plugin_barrier_generation,
            control_socket_cookie: plan.control_socket_cookie,
            wake_eventfd_id: plan.wake_eventfd_id,
            source_mapping_start: plan.source_mapping_start,
            source_mapping_length: plan.source_mapping_length,
            source_mapping_offset: plan.source_mapping_offset,
            account_generation: plan.account_generation,
            workspace_generation: plan.workspace_generation,
            workspace_device: plan.workspace_device,
            workspace_inode: plan.workspace_inode,
            workspace_length: plan.workspace_length,
            workspace_fd: plan.workspace_fd,
        }
    }
}

/// Exact process-local state of the plugin fork-child transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HotForkChildRuntimeSnapshot {
    /// Closed internal lifecycle phase.
    phase: u8,
    /// Exact sealed worker accounting observed in this process.
    workers: WorkerQuiescenceSnapshot,
    /// Whether the retained callback barrier remains held.
    callbacks_held: bool,
    /// Whether the branch-private ring mapping has been installed.
    mapping_installed: bool,
    /// Exact staged resource basis installed in this process, if any.
    binding: HotForkChildResourceBinding,
}

/// Failure while replacing template-process resources in a fork child.
#[derive(Debug, Error)]
enum HotForkChildRuntimeError {
    /// Early inherited-workspace disposition or fresh claim failed.
    #[error("fork-child device workspace failed: {source}")]
    Workspace {
        source: crate::DeviceDigestWorkspaceError,
    },
    /// This process already attempted or completed child initialization.
    #[error("fork-child runtime initialization is unavailable in phase {phase}")]
    WrongPhase {
        /// Current closed child-runtime phase.
        phase: u8,
    },
    /// The callback, ring, or worker barrier was not fully quiescent.
    #[error("fork-child runtime requires the complete held template barrier")]
    TemplateNotQuiescent,
    /// The staged child generation was not the exact successor of this runtime.
    #[error("fork-child process generation did not exactly advance the template")]
    ProcessGeneration,
    /// Fresh workers have not all reached their held receive boundary.
    #[error("fork-child workers have not reached the complete parked set")]
    WorkersNotReady,
    /// The private ring mapping was not held and drained at release.
    #[error("fork-child private ring barrier is not quiescent")]
    RingBarrier,
}

/// Callback families that must be live before the plugin can acknowledge setup.
pub const REQUIRED_OWNED_CALLBACK_FAMILIES: &str = "vCPU init/resume/idle, network TX/RX, block submit/poll, 9p burst/submit/poll, and optional white-box doorbell";

const RUNTIME_VACANT: u8 = 0;
const RUNTIME_INSTALLING: u8 = 1;
const RUNTIME_ACTIVE: u8 = 2;
const RUNTIME_FAILED: u8 = 3;
const CHILD_RUNTIME_TEMPLATE: u8 = 0;
const CHILD_RUNTIME_INITIALIZING: u8 = 1;
const CHILD_RUNTIME_WORKERS_HELD: u8 = 2;
const CHILD_RUNTIME_ACTIVE: u8 = 3;
const CHILD_RUNTIME_FAILED: u8 = 4;
static RUNTIME_STATE: AtomicU8 = AtomicU8::new(RUNTIME_VACANT);
#[cfg(test)]
static RUNTIME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
static LIVE_COVERAGE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
extern "C" fn test_hot_fork_child_request_shutdown(_failure: i32) {}

#[cfg(test)]
pub(crate) struct RuntimeStateTestGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for RuntimeStateTestGuard {
    fn drop(&mut self) {
        clear_live_callback_registration_for_test();
        RUNTIME_STATE.store(RUNTIME_VACANT, Ordering::Release);
    }
}

#[cfg(test)]
pub(crate) fn isolate_runtime_state_for_test() -> RuntimeStateTestGuard {
    let lock = match RUNTIME_TEST_LOCK.lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };
    RUNTIME_STATE.store(RUNTIME_VACANT, Ordering::Release);
    RuntimeStateTestGuard { _lock: lock }
}

#[cfg(test)]
pub(crate) fn isolate_coverage_callback_model_for_test() -> std::sync::MutexGuard<'static, ()> {
    match LIVE_COVERAGE_TEST_LOCK.lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Formats a deterministic install diagnostic without host-clock input.
#[must_use]
pub(crate) fn install_failure_diagnostic(error: &PluginLiveBoundaryError) -> String {
    format!("crucible-qemu-plugin: install failed: {error}")
}

/// Writes a deterministic install failure to standard error.
pub(crate) fn emit_install_failure_diagnostic(error: &PluginLiveBoundaryError) {
    let diagnostic = install_failure_diagnostic(error);
    let _write_result = writeln!(std::io::stderr().lock(), "{diagnostic}");
}

/// Bit mask describing callback families owned by the installed plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedCallbackRegistrationMask {
    bits: u16,
}

impl OwnedCallbackRegistrationMask {
    const VCPU: u16 = 1 << 0;
    const NETWORK: u16 = 1 << 1;
    const BLOCK: u16 = 1 << 2;
    const NINEP: u16 = 1 << 3;
    const ACCELERATOR: u16 = 1 << 4;
    const WHITEBOX: u16 = 1 << 5;
    const BASE_REQUIRED: u16 =
        Self::VCPU | Self::NETWORK | Self::BLOCK | Self::NINEP | Self::ACCELERATOR;

    const fn base_required() -> Self {
        Self {
            bits: Self::BASE_REQUIRED,
        }
    }

    const fn with_whitebox(mut self) -> Self {
        self.bits |= Self::WHITEBOX;
        self
    }

    fn required_for(args: &PluginArgs) -> Self {
        let whitebox = if args.whitebox().is_on() {
            Self::WHITEBOX
        } else {
            0
        };
        Self {
            bits: Self::BASE_REQUIRED | whitebox,
        }
    }

    fn validate_for(self, args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
        let required = Self::required_for(args);
        if self == required {
            Ok(())
        } else {
            Err(OwnedCallbackRegistrationError::IncompleteRegistrationMask {
                required: required.bits(),
                actual: self.bits(),
            })
        }
    }

    /// Returns the raw stable bit representation used in diagnostics and tests.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.bits
    }
}

/// Reports completed nominal preparation without lending any child address.
struct PreparedLiveCallbacks {
    #[cfg(test)]
    fixture_pointer: *mut live_callbacks::LiveVcpuTimeCallbackState,
}

/// Heap-stable state addressed by future QEMU callback userdata pointers.
///
/// The setup mapping and wake descriptor move into this allocation before any
/// owned callback may be registered. The allocation remains pinned while the
/// proof is live, so moving the proof never moves callback-addressable state.
pub(crate) struct OwnedCallbackRuntimeState {
    quiescence: Arc<LiveCallbackQuiescence>,
    workers: Arc<LiveWorkerQuiescence>,
    teardown_router: Arc<LiveRuntimeTeardownRouter>,
    // Only explicit callback fixtures populate this Box model. Production
    // retains Source-owned child custody below and cannot publish a typed view.
    live_vcpu_time: Option<Pin<Box<live_callbacks::LiveVcpuTimeCallbackState>>>,
    live_whitebox: Option<Pin<Box<live_whitebox::LiveWhiteboxState>>>,
    setup: PluginSetupCompletion,
    coverage: Option<LiveBasicBlockCoverage>,
    mapping_excluded_from_child: AtomicBool,
    child_runtime_state: AtomicU8,
    child_mapping_installed: AtomicBool,
    process_generation: u64,
    slot_index: u32,
    control_fd: std::os::fd::RawFd,
    request_shutdown: QemuRequestShutdownFn,
    startup_failure: Option<crate::StartupSourceError>,
    plugin_id: Option<QemuPluginId>,
    original_owner: Option<crate::ram_fingerprint::NativeOriginalOwner>,
    control_component: control_component::ControlComponent,
    command_storage: command_storage::CommandStorage,
    command_receive: Mutex<command_receive::CommandReceive>,
    callback_child: callback_child::CallbackChild,
    registration_owner: registration_owner::RegistrationOwner,
    publisher_service: publisher_service::PublisherService,
    registration_groups: registration_groups::RegistrationGroups,
    workspace_mapping: workspace_mapping::WorkspaceMapping,
    #[cfg(not(test))]
    fingerprint_worker_owner: live_callbacks::SourceWorkerOwner,
    #[cfg(not(test))]
    required_workers: required_workers::RequiredWorkers,
    original_userdata_retained: AtomicBool,
    owner_process: u32,
    workspace_disarmed: bool,
    claimed_workspace_fd: i32,
    checkpoint_api: Option<checkpoint::NativeApi>,
    checkpoint: Mutex<checkpoint::Slot>,
    checkpoint_owner_retained: AtomicBool,
    checkpoint_registration_retained: AtomicBool,
    parent_park_api: Option<parent_park::NativeApi>,
    parent_park: Mutex<parent_park::Slot>,
    parent_park_retained: AtomicBool,
    parent_park_registration_retained: AtomicBool,
    #[cfg(test)]
    allow_missing_fault_command_state: bool,
    _pin: PhantomPinned,
}

fn check_fingerprint_setup_original(
    state: &mut OwnedCallbackRuntimeState,
) -> Result<(), LiveVcpuTimeCallbackError> {
    live_callbacks::fingerprint_worker::check_setup_before_birth(
        &mut || state.setup.original_startup_slice(),
        &mut state.startup_failure,
    )
}

impl OwnedCallbackRuntimeState {
    fn pin(
        worker_mask: u64,
        setup: PluginSetupCompletion,
        teardown_router: Arc<LiveRuntimeTeardownRouter>,
        process_generation: u64,
        slot_index: u32,
        control_fd: std::os::fd::RawFd,
        request_shutdown: QemuRequestShutdownFn,
    ) -> Pin<Box<Self>> {
        Box::pin(Self {
            quiescence: Arc::new(LiveCallbackQuiescence::new()),
            workers: LiveWorkerQuiescence::new(worker_mask),
            teardown_router,
            live_vcpu_time: None,
            live_whitebox: None,
            setup,
            coverage: None,
            mapping_excluded_from_child: AtomicBool::new(false),
            child_runtime_state: AtomicU8::new(CHILD_RUNTIME_TEMPLATE),
            child_mapping_installed: AtomicBool::new(false),
            process_generation,
            slot_index,
            control_fd,
            request_shutdown,
            startup_failure: None,
            plugin_id: None,
            original_owner: None,
            control_component: control_component::ControlComponent::new(),
            command_storage: command_storage::CommandStorage::new(),
            command_receive: Mutex::new(command_receive::CommandReceive::new()),
            callback_child: callback_child::CallbackChild::new(),
            registration_owner: registration_owner::RegistrationOwner::new(),
            publisher_service: publisher_service::PublisherService::new(),
            registration_groups: registration_groups::RegistrationGroups::new(),
            workspace_mapping: workspace_mapping::WorkspaceMapping::new(),
            #[cfg(not(test))]
            fingerprint_worker_owner: live_callbacks::SourceWorkerOwner::new(),
            #[cfg(not(test))]
            required_workers: required_workers::RequiredWorkers::new(),
            original_userdata_retained: AtomicBool::new(false),
            owner_process: std::process::id(),
            workspace_disarmed: false,
            claimed_workspace_fd: -1,
            checkpoint_api: None,
            checkpoint: Mutex::new(checkpoint::Slot::default()),
            checkpoint_owner_retained: AtomicBool::new(false),
            checkpoint_registration_retained: AtomicBool::new(false),
            parent_park_api: None,
            parent_park: Mutex::new(parent_park::Slot::new()),
            parent_park_retained: AtomicBool::new(false),
            parent_park_registration_retained: AtomicBool::new(false),
            #[cfg(test)]
            allow_missing_fault_command_state: false,
            _pin: PhantomPinned,
        })
    }

    fn control_teardown_handle(
        &self,
        process_generation: u64,
    ) -> Result<LiveControlTeardownHandle, crucible_qemu_shmem::MappedSetupRegionAccessError> {
        let slot = self.setup.mapped_region().node_slot(self.slot_index)?;
        Ok(LiveControlTeardownHandle {
            quiescence: Arc::clone(&self.quiescence),
            header_address: std::ptr::from_ref(self.setup.mapped_region().header()) as usize,
            slot_address: std::ptr::from_ref(slot) as usize,
            wake_fd: self.setup.wake_fd().as_raw_fd(),
            control_callback_witness: self
                .live_vcpu_time
                .as_ref()
                .map(|live| Arc::clone(&live.control_callback_witness)),
            region_identity: self.setup.mapped_region().backing_identity(),
            slot_index: self.slot_index,
            process_generation,
        })
    }

    /// Marks an isolated registration-order fixture that intentionally does
    /// not construct callback-addressable state.
    #[cfg(test)]
    fn allow_missing_fault_command_state_for_test(self: Pin<&mut Self>) {
        // SAFETY: the assignment does not move any field of the pinned owner.
        unsafe {
            self.get_unchecked_mut().allow_missing_fault_command_state = true;
        }
    }

    /// Initializes only the prepaid inline Source observer component.
    ///
    /// # Errors
    /// Refuses missing runtime purpose, duplicate initialization or unmatched SDK.
    fn prepare_original_owner(
        mut self: Pin<&mut Self>,
        plugin_id: QemuPluginId,
        placement: crate::ram_fingerprint::FingerprintPlacement,
    ) -> Result<crate::ram_fingerprint::NativeOriginalOwnerRef, crate::ram_error::RamError> {
        // The configured runtime Box includes the entire inline component;
        // the actual Source reserved that layout before this Box was born.
        let state = self.as_ref().get_ref();
        state
            .setup
            .check_runtime_installation()
            .map_err(crate::startup_source::InstallerStartupSource::retained_ram_error)?;
        if state.original_owner.is_some() {
            return Err(crate::ram_error::RamError::Invariant(
                "Original owner already initialized",
            ));
        }
        let userdata = self.as_mut().retain_original_userdata();
        // SAFETY: the exclusive installer initializes the inline member in place;
        // exposure retention already protects this Box on refusal or panic.
        let state = unsafe { self.get_unchecked_mut() };
        let preparation =
            crate::ram_fingerprint::NativeOriginalOwner::prepare(plugin_id, userdata, placement)
                .map(|owner| state.original_owner = Some(owner));
        let post = state
            .setup
            .check_runtime_installation()
            .map_err(crate::startup_source::InstallerStartupSource::retained_ram_error);
        preparation?;
        post?;
        let owner = state
            .original_owner
            .as_ref()
            .ok_or(crate::ram_error::RamError::Invariant(
                "Original owner absent",
            ))?;
        // SAFETY: exposure retention precedes this reference and prevents the
        // owning proof from freeing the pinned Box, including after refusal.
        Ok(unsafe { crate::ram_fingerprint::NativeOriginalOwnerRef::from_retained_runtime(owner) })
    }

    /// Enrolls only this real retained child under the prepaid Runtime holder.
    ///
    /// # Errors
    /// Refuses missing Original/runtime custody, a different child, or the
    /// authentic Native enrollment/observation result. Exposure stays retained.
    #[cfg(test)]
    fn enroll_control_component(
        self: Pin<&mut Self>,
        plugin_id: QemuPluginId,
        child: *mut live_callbacks::LiveVcpuTimeCallbackState,
        callback: control_component::ControlCallback,
        facts: control_component::FactsCallback,
    ) -> Result<(), crate::ram_error::RamError> {
        let runtime_userdata = std::ptr::from_ref(self.as_ref().get_ref())
            .cast_mut()
            .cast();
        // SAFETY: this exclusive installer projection initializes the inline
        // member without moving the pinned Runtime or its independently pinned
        // child. The real Original exposure already retains both on failure.
        let state = unsafe { self.get_unchecked_mut() };
        state
            .setup
            .check_runtime_installation()
            .map_err(crate::startup_source::InstallerStartupSource::retained_ram_error)?;
        let retained_child = state
            .live_vcpu_time
            .as_ref()
            .map(|live| std::ptr::from_ref(live.as_ref().get_ref()).cast_mut());
        if state.original_owner.is_none()
            || !state.original_userdata_retained.load(Ordering::Acquire)
            || retained_child != Some(child)
        {
            return Err(crate::ram_error::RamError::Invariant(
                "control enrollment lacks its actual retained owning child",
            ));
        }
        let enrollment = state.control_component.enroll(
            plugin_id,
            runtime_userdata,
            callback,
            child.cast(),
            facts,
        );
        let post = state
            .setup
            .check_runtime_installation()
            .map_err(crate::startup_source::InstallerStartupSource::retained_ram_error);
        enrollment?;
        post
    }

    /// Verifies actual registration without treating the void registrar as proof.
    ///
    /// # Errors
    /// Preserves the actual Source/Native registration result and retained field.
    fn verify_control_component(self: Pin<&mut Self>) -> Result<(), crate::ram_error::RamError> {
        // SAFETY: no pinned field moves; the same inline field is lent to the
        // pure Native registration query after actual callback publication.
        let state = unsafe { self.get_unchecked_mut() };
        state
            .setup
            .check_runtime_installation()
            .map_err(crate::startup_source::InstallerStartupSource::retained_ram_error)?;
        let registration = state.control_component.verify_registered();
        let post = state
            .setup
            .check_runtime_installation()
            .map_err(crate::startup_source::InstallerStartupSource::retained_ram_error);
        registration?;
        post?;
        if let Some(installer) = state.setup.publisher_installer() {
            let plugin_id = state
                .plugin_id
                .ok_or(crate::ram_error::RamError::Invariant(
                    "publisher Runtime has no installed plugin id",
                ))?;
            let owner = state
                .registration_owner
                .native_owner()
                .map_err(crate::startup_source::InstallerStartupSource::retained_ram_error)?;
            state
                .publisher_service
                .transfer(plugin_id, owner, installer)?;
        }
        Ok(())
    }

    /// Retains the pinned allocation before exposing Original callback userdata.
    ///
    /// This records reference lifetime, not successful native registration.
    /// A fallible preparation may retain the pointer, so retention is permanent.
    fn retain_original_userdata(self: Pin<&mut Self>) -> *mut std::ffi::c_void {
        let state = self.as_ref().get_ref();
        state
            .original_userdata_retained
            .store(true, Ordering::Release);
        std::ptr::from_ref(state).cast_mut().cast()
    }

    /// Returns the stable opaque pointer supplied as QEMU callback userdata.
    pub(crate) fn userdata(self: Pin<&mut Self>) -> *mut std::ffi::c_void {
        // SAFETY: obtaining a pointer does not move the `!Unpin` state. The
        // caller may register it only while the owning pinned allocation is
        // retained for at least as long as QEMU can invoke the callback.
        let state = unsafe { self.get_unchecked_mut() };
        std::ptr::from_mut(state).cast()
    }

    // crucible-lint: allow rust-allow -- the bridge transfers the fixed QEMU, clock, slot, and RX capabilities.
    #[allow(
        clippy::too_many_arguments,
        reason = "the registration bridge transfers fixed QEMU, clock, slot, and RX capabilities into pinned state"
    )]
    fn prepare_live_vcpu_time_state(
        self: Pin<&mut Self>,
        plugin_id: QemuPluginId,
        vcpu_count: u32,
        slot_index: u32,
        fault_node_hash: [u8; 32],
        icount_raw: crate::QemuIcountRawFn,
        force_vcpu_exit: crate::QemuForceVcpuExitFn,
        request_vmstop: crate::QemuRequestVmstopFn,
        preemption_injector: crate::PluginPreemptionInjector,
        initial_raw_icount: u64,
        exact_deadline: crate::ExactDeadlineReader,
        queued_idle_advance: crate::QueuedIdleAdvance,
        virtual_timer_witness: crate::QemuVirtualTimerWitness,
        idle_wake_wait: crate::QemuIdleWakeWait,
        network_rx: crate::QemuCanonicalNetworkRx,
        network_tx_next_seq: u32,
        storage_history_limits: crate::PluginStorageHistoryLimits,
        process_generation: u64,
        fault_command_apis: crate::fault_command::QemuFaultCommandApis,
        fingerprint: Option<crate::fingerprint_sampler::PluginFingerprintSampling>,
        control_callback: control_component::ControlCallback,
        facts_callback: control_component::FactsCallback,
    ) -> Result<PreparedLiveCallbacks, LiveVcpuTimeCallbackError> {
        // SAFETY: this projection does not move the pinned parent or any
        // independently pinned callback allocation. The new allocation is
        // installed before its address becomes observable to QEMU.
        let state = unsafe { self.get_unchecked_mut() };
        #[cfg(not(test))]
        let runtime_userdata = std::ptr::from_mut(&mut *state).cast::<std::ffi::c_void>();
        #[cfg(test)]
        let _model_callbacks = (control_callback, facts_callback);
        if state.live_vcpu_time.is_some() || state.callback_child.retains_storage() {
            return Err(LiveVcpuTimeCallbackError::CallbackStateAlreadyPublished);
        }
        state.plugin_id = Some(plugin_id);
        if fingerprint.is_some() {
            check_fingerprint_setup_original(state)?;
        }
        let stop_backing_identity = state.setup.mapped_region().backing_identity();
        let header = std::ptr::NonNull::from(state.setup.mapped_region().header());
        #[cfg(not(test))]
        let fault_commands = {
            let material = state.setup.command_storage_material().map_err(|source| {
                LiveVcpuTimeCallbackError::FaultCommands {
                    source: crate::fault_command::FaultCommandBridgeError::StorageSource { source },
                }
            })?;
            // SAFETY: the parent is already prepaid/pinned and observer completion
            // enrolled. Its actual storage field never moves after Native transfer.
            unsafe {
                state.command_storage.create(material, || {
                    crate::fault_command::FaultCommandBridge::new(
                        fault_command_apis,
                        fault_node_hash,
                        state.setup.mapped_region_mut(),
                        slot_index,
                    )
                })
            }
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?;
            // SAFETY: the actual retained parent contains the stable owner and
            // keeps it alive for the independently pinned callback child.
            let adapter = unsafe { command_storage::Adapter::new(&state.command_storage) };
            live_callbacks::FaultCommandControl::Native(adapter)
        };
        #[cfg(test)]
        let fault_commands = live_callbacks::FaultCommandControl::from(Box::new(
            crate::fault_command::FaultCommandBridge::new(
                fault_command_apis,
                fault_node_hash,
                state.setup.mapped_region_mut(),
                slot_index,
            )
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?,
        ));
        #[cfg(not(test))]
        let child_material = state
            .setup
            .callback_child_material()
            .map_err(|source| LiveVcpuTimeCallbackError::CallbackChildStorage { source })?;
        #[cfg(not(test))]
        let bridge = state
            .command_storage
            .native_parent()
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?;
        let router_slot = crucible_qemu_shmem::SLOT_NET_ROUTER as u32;
        #[cfg(not(test))]
        let (mapped_view, installing) = state
            .setup
            .mapped_region_with_installer()
            .map_err(|source| LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source })?;
        #[cfg(test)]
        let mapped_view = state.setup.mapped_region_mut();
        let mapped = mapped_view
            .node_directed_ring_pair_mut(
                slot_index,
                slot_index,
                router_slot,
                router_slot,
                slot_index,
            )
            .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
        // SAFETY: `header` points into the same setup-owned mapping as the
        // validated pair and remains live while callback state is retained.
        let header = unsafe { header.as_ref() };
        #[cfg(not(test))]
        {
            // SAFETY: the containing Runtime is already paid/pinned and its
            // distinct canonical child field never moves. Source entered
            // creation retains the real Bridge parent before allocation/post.
            unsafe {
                state
                    .callback_child
                    .create(child_material, bridge, |span, progress| {
                        let child =
                            live_callbacks::LiveVcpuTimeCallbackState::initialize_with_allocation(
                                icount_raw,
                                force_vcpu_exit,
                                idle_wake_wait,
                                request_vmstop,
                                preemption_injector,
                                vcpu_count,
                                initial_raw_icount,
                                exact_deadline,
                                queued_idle_advance,
                                virtual_timer_witness,
                                fault_commands,
                                header,
                                mapped.node_slot,
                                Arc::clone(&state.quiescence),
                                Arc::clone(&state.teardown_router),
                                || callback_child::EnteredAllocation::new(span, progress),
                            )?;
                        // This immediately follows all forty complete field writes.
                        // A negative acknowledgement retains a fully written body.
                        progress.initialized()?;
                        child.rebind_stop_caller_identity(
                            stop_backing_identity,
                            slot_index,
                            process_generation,
                        );
                        child.rebind_control_stage_identity(
                            stop_backing_identity,
                            slot_index,
                            process_generation,
                        );
                        Ok(())
                    })
            }?;
            // The fixed Source registration owner is a distinct borrower of
            // this complete child and its independently owned Bridge. Its keeper
            // was included in Runtime request0 before reserve and Box birth.
            installing.check_runtime_installation().map_err(|source| {
                LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source }
            })?;
            let child = state.callback_child.nominal_storage()?;
            // SAFETY: this is the same paid pinned Runtime and the child came
            // from its protected actual canonical-field getter, not a raw tuple.
            let owner = unsafe { state.registration_owner.create(plugin_id, child) };
            let owner_post = installing
                .check_runtime_installation()
                .map_err(|source| LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source });
            owner?;
            owner_post?;

            // SAFETY: Source current lends the complete initialized child only
            // for this entered family preparation. The loan is not a Native
            // callback binding and no pointer escapes into global storage.
            unsafe {
                state.callback_child.prepare_publication(|child| {
                    child.attach_network_in_place(
                        slot_index,
                        mapped.first,
                        mapped.second,
                        network_rx,
                        network_tx_next_seq,
                    )
                })
            }?;
            // SAFETY: end the network-ring borrow before asking the same setup
            // owner for distinct device views. Each new typed access obtains its
            // own genuine Source current and preserves its negative loan outputs.
            unsafe {
                state.callback_child.prepare_publication(|child| {
                    let block_slot = crucible_qemu_shmem::SLOT_BLK_IO as u32;
                    let block = state
                        .setup
                        .mapped_region_mut()
                        .node_directed_ring_pair_mut(
                            slot_index, slot_index, block_slot, block_slot, slot_index,
                        )
                        .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
                    let block_rings =
                        live_callbacks::LiveDirectedRingPair::new(block.first, block.second)?;
                    let ninep_slot = crucible_qemu_shmem::SLOT_9P_IO as u32;
                    let ninep = state
                        .setup
                        .mapped_region_mut()
                        .node_directed_ring_pair_mut(
                            slot_index, slot_index, ninep_slot, ninep_slot, slot_index,
                        )
                        .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
                    let ninep_rings =
                        live_callbacks::LiveDirectedRingPair::new(ninep.first, ninep.second)?;
                    let accelerator = state
                        .setup
                        .mapped_region_mut()
                        .plugin_accelerator_rings_mut(slot_index)
                        .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
                    // SAFETY: the same retained mapping remains live through all
                    // child/Bridge/material users; this changes no VMA owner.
                    let accelerator = accelerator.detach_for_mapping_lifetime();
                    child.attach_devices_with_history_limits_in_place(
                        slot_index,
                        block_rings,
                        ninep_rings,
                        storage_history_limits,
                        process_generation,
                        accelerator,
                    )?;
                    Ok(())
                })
            }?;
            // Actual component construction consumes the transferred nominal
            // owner and full child span in Source. This is physical enrollment,
            // not Native family registration or callback activation.
            state.setup.check_runtime_installation().map_err(|source| {
                LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source }
            })?;
            state.registration_owner.current()?;
            let receiver = std::ptr::NonNull::from(&state.command_receive);
            // SAFETY: the only typed address is obtained in the genuine entered
            // span. Source independently retains its owner dependency before the
            // component output/post; no borrowed Rust reference escapes.
            let enrollment = unsafe {
                state.callback_child.prepare_publication(|child| {
                    // SAFETY: this genuine complete typed child and paid pinned
                    // Runtime remain retained through every member/ready loan.
                    child.bind_command_receiver(receiver)?;
                    state
                        .control_component
                        .enroll(
                            plugin_id,
                            runtime_userdata,
                            control_callback,
                            std::ptr::from_mut(child).cast(),
                            facts_callback,
                        )
                        .map_err(|source| LiveVcpuTimeCallbackError::ControlComponent { source })
                })
            };
            let enrollment_post = state
                .setup
                .check_runtime_installation()
                .map_err(|source| LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source });
            enrollment?;
            enrollment_post?;

            let component = state
                .control_component
                .nominal_projection()
                .map_err(|source| LiveVcpuTimeCallbackError::ControlComponent { source })?;
            state.setup.check_runtime_installation().map_err(|source| {
                LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source }
            })?;
            let mut receiver = state.command_receive.try_lock().map_err(|_| {
                LiveVcpuTimeCallbackError::CallbackRegistrationOwner {
                    source: crate::StartupSourceError::Ownership {
                        reason: "command receive keeper is busy or poisoned",
                    },
                }
            })?;
            // SAFETY: actual pinned Runtime owns this prepaid inline field; the
            // protected Source projection binds its true child/Bridge/slot tree.
            let membership = unsafe {
                receiver.enroll(
                    plugin_id,
                    component,
                    live_callbacks::protected_request_snapshot,
                    live_callbacks::protected_park_return_writer,
                    command_receive::PayloadCallbacks {
                        claim: live_callbacks::protected_payload_claim,
                        release: live_callbacks::protected_payload_return,
                        borrow_acquire: live_callbacks::protected_payload_borrow_acquire,
                        borrow_release: live_callbacks::protected_payload_borrow_release,
                        action_enter: live_callbacks::fingerprint_action_enter,
                        action_current: live_callbacks::fingerprint_action_current,
                        action_post: live_callbacks::fingerprint_action_post,
                        action_return: live_callbacks::fingerprint_action_return,
                    },
                )
            };
            drop(receiver);
            let membership_post = state.setup.check_runtime_installation();
            membership.map_err(
                |source| LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source },
            )?;
            membership_post.map_err(|source| {
                LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source }
            })?;

            // The complete Runtime includes the reader ledger and both paid
            // journals. Enroll only after its real callback owner exists, and
            // retain any born Source owner before interpreting either result.
            state.setup.check_runtime_installation().map_err(|source| {
                LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source }
            })?;
            if let Some(owner) = state.original_owner.as_ref() {
                let (_, runtime, _) = state.setup.callback_child_material().map_err(|source| {
                    LiveVcpuTimeCallbackError::CallbackChildStorage { source }
                })?;
                // SAFETY: the actual paid pinned Runtime was exposed before
                // enrollment and remains retained on every failure path.
                let owner = unsafe {
                    crate::ram_fingerprint::NativeOriginalOwnerRef::from_retained_runtime(owner)
                };
                let enrollment = owner.enroll_reader(runtime);
                let post = state.setup.check_runtime_installation();
                enrollment.map_err(|message| LiveVcpuTimeCallbackError::RamObserverSetup { message })?;
                post.map_err(|source| LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source })?;
            }

            if let Some(sampling) = fingerprint {
                // The whole keeper belongs to Runtime request0. Source's
                // constructor consumes its actual optional role, then transfer
                // binds this fixed field to the genuine completed child owner.
                let (id, runtime, _) = state.setup.callback_child_material().map_err(|source| {
                    LiveVcpuTimeCallbackError::DeviceDigestWorkspace {
                        source: crate::DeviceDigestWorkspaceError::StartupSource { source },
                    }
                })?;
                // SAFETY: the actual paid/pinned Runtime and transferred child
                // stay retained through every born output and negative post.
                let mapping = unsafe { state.workspace_mapping.create(id, runtime) };
                let mapping_post = state.setup.check_runtime_installation();
                mapping.map_err(|source| LiveVcpuTimeCallbackError::DeviceDigestWorkspace {
                    source,
                })?;
                mapping_post.map_err(|source| {
                    LiveVcpuTimeCallbackError::DeviceDigestWorkspace {
                        source: crate::DeviceDigestWorkspaceError::StartupSource { source },
                    }
                })?;
                let material = state
                    .setup
                    .fingerprint_worker_material()
                    .map_err(|source| LiveVcpuTimeCallbackError::CallbackChildStorage { source })?;
                let child_owner = state.registration_owner.native_projection()?;
                let workspace = state
                    .workspace_mapping
                    .native_projection()
                    .map_err(|source| LiveVcpuTimeCallbackError::DeviceDigestWorkspace {
                        source,
                    })?;
                let slot = state
                    .setup
                    .mapped_region()
                    .fingerprint_sample(slot_index)
                    .map_err(|source| LiveVcpuTimeCallbackError::MappedFingerprintSlot {
                        source,
                    })?;
                let slot = live_callbacks::StableFingerprintSlotHandle::new(slot);
                // SAFETY: this actual worker keeper is part of the prepaid pinned
                // Runtime. Source authenticates the same child/mapping and owns
                // all stack/task/control outputs before its independent post.
                let birth = unsafe {
                    state.fingerprint_worker_owner.create(
                        material,
                        child_owner,
                        workspace,
                        slot,
                        Arc::clone(&state.workers),
                    )
                };
                let birth_post = state.setup.check_runtime_installation();
                state
                    .fingerprint_worker_owner
                    .record_installation_post(birth_post);
                birth?;
                birth_post
                    .map_err(|source| LiveVcpuTimeCallbackError::CallbackChildStorage { source })?;
                state
                    .fingerprint_worker_owner
                    .wait_registered(|| state.setup.original_startup_slice())?;
                // SAFETY: the genuine family loan lends the completed child only
                // for this entered preparation. The worker's inputs and control
                // are owned allocations, and no borrowed span escapes.
                unsafe {
                    state.callback_child.prepare_publication(|child| {
                        child.attach_source_fingerprint(
                            sampling,
                            slot,
                            state.fingerprint_worker_owner.take_worker()?,
                        )
                    })
                }?;
            }
            Ok(PreparedLiveCallbacks {})
        }
        #[cfg(test)]
        {
            let mut callback_state = live_callbacks::LiveVcpuTimeCallbackState::new_boxed(
                icount_raw,
                force_vcpu_exit,
                idle_wake_wait,
                request_vmstop,
                preemption_injector,
                vcpu_count,
                initial_raw_icount,
                exact_deadline,
                queued_idle_advance,
                virtual_timer_witness,
                fault_commands,
                header,
                mapped.node_slot,
                Arc::clone(&state.quiescence),
                Arc::clone(&state.teardown_router),
            )?;
            callback_state.rebind_stop_caller_identity(
                stop_backing_identity,
                slot_index,
                process_generation,
            );
            callback_state.attach_network_in_place(
                slot_index,
                mapped.first,
                mapped.second,
                network_rx,
                network_tx_next_seq,
            )?;
            let block_slot = crucible_qemu_shmem::SLOT_BLK_IO as u32;
            let mapped = state
                .setup
                .mapped_region_mut()
                .node_directed_ring_pair_mut(
                    slot_index, slot_index, block_slot, block_slot, slot_index,
                )
                .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
            let block_rings =
                live_callbacks::LiveDirectedRingPair::new(mapped.first, mapped.second)?;
            let ninep_slot = crucible_qemu_shmem::SLOT_9P_IO as u32;
            let mapped = state
                .setup
                .mapped_region_mut()
                .node_directed_ring_pair_mut(
                    slot_index, slot_index, ninep_slot, ninep_slot, slot_index,
                )
                .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
            let ninep_rings =
                live_callbacks::LiveDirectedRingPair::new(mapped.first, mapped.second)?;
            let accelerator_rings = state
                .setup
                .mapped_region_mut()
                .plugin_accelerator_rings_mut(slot_index)
                .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
            // SAFETY: the pinned runtime retains this unique plugin role and its
            // owning mapping for every QEMU callback.
            let accelerator_rings = unsafe { accelerator_rings.detach_for_mapping_lifetime() };
            callback_state.attach_devices_with_history_limits_in_place(
                slot_index,
                block_rings,
                ninep_rings,
                storage_history_limits,
                process_generation,
                accelerator_rings,
            )?;
            if let Some(sampling) = fingerprint {
                let slot = state
                    .setup
                    .mapped_region()
                    .fingerprint_sample(slot_index)
                    .map_err(|source| LiveVcpuTimeCallbackError::MappedFingerprintSlot {
                        source,
                    })?;
                let slot = live_callbacks::StableFingerprintSlotHandle::new(slot);
                check_fingerprint_setup_original(state)?;
                let workspace = state
                    .setup
                    .take_device_digest_workspace(plugin_id, process_generation)
                    .map_err(|source| LiveVcpuTimeCallbackError::DeviceDigestWorkspace {
                        source,
                    })?;
                callback_state.attach_fingerprint_in_place(
                    sampling,
                    slot,
                    Arc::clone(&state.workers),
                    workspace,
                    &mut || state.setup.original_startup_slice(),
                    &mut state.startup_failure,
                )?;
            }
            callback_state.rebind_control_stage_identity(
                state.setup.mapped_region().backing_identity(),
                slot_index,
                process_generation,
            );
            let callback_state = Pin::from(callback_state);
            let callback_pointer = std::ptr::from_ref(callback_state.as_ref().get_ref()).cast_mut();
            state.live_vcpu_time = Some(callback_state);
            Ok(PreparedLiveCallbacks {
                fixture_pointer: callback_pointer,
            })
        }
    }

    /// Performs one physical group effect without returning an ended span.
    ///
    /// # Errors
    /// Preserves installing, group, registrar and independent post failures.
    #[cfg(not(test))]
    fn install_registration_group(
        self: Pin<&mut Self>,
        plugin_id: QemuPluginId,
        kind: registration_groups::Kind,
        registrar: impl FnOnce(
            &mut live_callbacks::LiveVcpuTimeCallbackState,
        ) -> Result<(), LiveVcpuTimeCallbackError>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        // SAFETY: this projection moves no pinned field. Each canonical keeper
        // already belongs to Runtime request0 before reserve and parent birth.
        let state = unsafe { self.get_unchecked_mut() };
        state
            .setup
            .check_runtime_installation()
            .map_err(|source| LiveVcpuTimeCallbackError::CallbackRegistrationGroup { source })?;
        state.registration_owner.current()?;
        let child = state.callback_child.nominal_storage()?;
        // SAFETY: actual protected nominal child plus prepaid pinned keeper;
        // the matching Native registrar independently lends its member parent.
        let installed = unsafe {
            state
                .registration_groups
                .install(plugin_id, child, kind, registrar)
        };
        let post = state
            .setup
            .check_runtime_installation()
            .map_err(|source| LiveVcpuTimeCallbackError::CallbackRegistrationGroup { source });
        installed.and(post)
    }

    fn prepare_live_whitebox_state(
        self: Pin<&mut Self>,
        apis: live_whitebox::LiveWhiteboxApis,
        args: &crate::PluginArgs,
        target_architecture: crate::abi::QemuPluginTargetArchitecture,
        vcpu_count: u32,
        request_shutdown: QemuRequestShutdownFn,
    ) -> Result<&mut live_whitebox::LiveWhiteboxState, live_whitebox::LiveWhiteboxError> {
        // SAFETY: assigning an independently heap-owned callback runtime does
        // not move the pinned parent or its setup mapping.
        let state = unsafe { self.get_unchecked_mut() };
        let live_vcpu_time = state
            .live_vcpu_time
            .as_ref()
            .ok_or(live_whitebox::LiveWhiteboxError::VcpuCallbackStateMissing)?;
        let selectable_vmstop = live_vcpu_time
            .as_ref()
            .get_ref()
            .selectable_vmstop_handoff();
        let logical_icount_offset = live_vcpu_time.as_ref().get_ref().logical_icount_offset();
        let selectable_catalog_plan = state.setup.take_selectable_catalog_plan();
        let marker_ring = state
            .setup
            .mapped_region_mut()
            .whitebox_marker_ring_mut(args.slot())
            .map_err(|source| live_whitebox::LiveWhiteboxError::MappedMarkerQueue { source })?;
        // SAFETY: `state.setup` owns the mapping for at least as long as the
        // sibling live white-box callback owner. The mapped accessor returns
        // the unique per-VM producer slice; the host is its sole SPSC consumer.
        let marker_output = unsafe {
            live_whitebox::LiveWhiteboxMarkerShmemProducer::from_raw_parts(
                std::ptr::from_ref(marker_ring.header),
                marker_ring.entries.as_mut_ptr(),
                marker_ring.entries.len(),
            )
        };
        let selectable_reply_ring = state
            .setup
            .mapped_region_mut()
            .selectable_reply_ring_mut(args.slot())
            .map_err(
                |source| live_whitebox::LiveWhiteboxError::MappedSelectableReplyQueue { source },
            )?;
        // SAFETY: the setup mapping is retained beside the pinned live
        // white-box owner. The host is the sole SPSC producer and this plugin
        // state is the sole consumer for the VM-local ring.
        let selectable_reply_input = unsafe {
            live_whitebox::LiveSelectableReplyShmemConsumer::from_raw_parts(
                std::ptr::from_ref(selectable_reply_ring.header),
                selectable_reply_ring.entries.as_mut_ptr(),
                selectable_reply_ring.entries.len(),
            )
        };
        let guest_introspection_rings = state
            .setup
            .mapped_region_mut()
            .plugin_guest_introspection_rings_mut(args.slot())
            .map_err(
                |source| live_whitebox::LiveWhiteboxError::MappedGuestIntrospectionRings { source },
            )?;
        let guest_introspection_rings = {
            // SAFETY: the pinned runtime retains the setup mapping for the
            // entire callback lifetime and installs exactly one plugin-side
            // role handle.
            unsafe { guest_introspection_rings.detach_for_mapping_lifetime() }
        };
        let callback_state = live_whitebox::LiveWhiteboxState::new(
            apis,
            live_whitebox::LiveWhiteboxTarget::new(target_architecture, args.whitebox_setup()),
            vcpu_count,
            live_whitebox::LiveWhiteboxProcessControl::new(
                request_shutdown,
                selectable_vmstop,
                logical_icount_offset,
            ),
            live_whitebox::LiveWhiteboxShmem::new(
                marker_output,
                selectable_reply_input,
                guest_introspection_rings,
            ),
            live_whitebox::LiveWhiteboxLaunchPlans::new(
                args.app_random(),
                state.setup.app_random_branch_plan(),
                selectable_catalog_plan.as_ref(),
                args.campaign_marker_parking().is_on(),
            ),
        )?;
        let mut callback_state = Box::pin(callback_state);
        // SAFETY: the independently boxed state is pinned and retained by this
        // process-lifetime owner before its address is registered with QEMU.
        let callback_pointer = unsafe {
            callback_state.as_mut().get_unchecked_mut() as *mut live_whitebox::LiveWhiteboxState
        };
        state.live_whitebox = Some(callback_state);
        // SAFETY: `callback_pointer` points into the pinned allocation just
        // retained by `state.live_whitebox`.
        Ok(unsafe { &mut *callback_pointer })
    }

    fn register_basic_block_coverage(
        self: Pin<&mut Self>,
        plugin_id: QemuPluginId,
        slot_index: u32,
        callback: crate::CoverageCallback,
        apis: QemuBasicBlockCoverageApis,
    ) -> Result<(), CoverageError> {
        // SAFETY: assigning an independently heap-owned callback runtime does
        // not move `setup` or the pinned outer state. The callback runtime is
        // installed at most once during the ordered registration sequence.
        let state = unsafe { self.get_unchecked_mut() };
        if state.coverage.is_some() {
            return Err(CoverageError::LiveRegistrationAlreadyExists { plugin_id });
        }
        let coverage_ring = state
            .setup
            .mapped_region_mut()
            .coverage_ring_mut(slot_index)
            .map_err(|source| CoverageError::MappedCoverageQueue { source })?;
        // SAFETY: `state.setup` owns the mapping for at least as long as the
        // sibling `state.coverage` owner. The validated accessor returns the
        // unique per-VM producer slice; the host maps it separately as the sole
        // SPSC consumer. Pinning prevents the owner relationship from changing.
        let output = unsafe {
            LiveCoverageShmemProducer::from_raw_parts(
                std::ptr::from_ref(coverage_ring.header),
                coverage_ring.entries.as_mut_ptr(),
                coverage_ring.entries.len(),
            )
        };
        let whitebox_translation = state
            .live_whitebox
            .as_mut()
            .map(|whitebox| whitebox.as_mut().get_mut().translation_consumer());
        state.coverage = Some(LiveBasicBlockCoverage::register_with_whitebox(
            plugin_id,
            callback,
            apis,
            output,
            Arc::clone(&state.quiescence),
            whitebox_translation,
        )?);
        Ok(())
    }
}

/// Typed proof that every required plugin-owned callback was registered.
///
/// This proof owns the pinned callback runtime state rather than merely marking
/// a logical milestone. It can be constructed only after the exact callback
/// mask for the selected launch mode is complete.
pub struct RequiredOwnedCallbacksRegistered {
    state: std::mem::ManuallyDrop<Pin<Box<OwnedCallbackRuntimeState>>>,
    registration_mask: OwnedCallbackRegistrationMask,
    #[cfg(test)]
    _teardown_receiver: Option<mpsc::Receiver<LiveRuntimeTeardownTrigger>>,
}

impl Drop for RequiredOwnedCallbacksRegistered {
    fn drop(&mut self) {
        // SAFETY: this exclusive owner does not move any pinned field. Native
        // independently requires actual detach and all reader/snapshot returns;
        // refusal keeps the same holder and entire Runtime/child allocation.
        let state = unsafe { self.state.as_mut().get_unchecked_mut() };
        #[cfg(not(test))]
        {
            let result = state.required_workers.identity_return(&mut state.setup);
            if result.is_err() && !state.required_workers.identities_returned() {
                return;
            }
        }
        if state.registration_groups.close_spans().is_err() {
            return;
        }
        if state.original_owner.as_ref().is_some_and(|owner| {
            owner.return_reader_registration().is_err()
        }) {
            return;
        }
        let Ok(mut receiver) = state.command_receive.try_lock() else {
            return;
        };
        if receiver.identity_return().is_err() {
            return;
        }
        drop(receiver);
        if !state
            .checkpoint_registration_retained
            .load(Ordering::Acquire)
            && !state.checkpoint_owner_retained.load(Ordering::Acquire)
            && !state.original_userdata_retained.load(Ordering::Acquire)
            && !state.parent_park_retained.load(Ordering::Acquire)
            && !state
                .parent_park_registration_retained
                .load(Ordering::Acquire)
        {
            // An exposed child can still own pending payload/publication users.
            // The complete semantic member/Root last-use join is not supplied by
            // this physical subset, so retain its containing Runtime until reap.
            // Temporary span users close first; nominal owner return is still
            // blocked by real component/registrar/Native/material dependencies.
            #[cfg(not(test))]
            let fingerprint_return = state.fingerprint_worker_owner.identity_return();
            #[cfg(not(test))]
            if fingerprint_return.is_err() && !state.fingerprint_worker_owner.identity_is_returned()
            {
                return;
            }
            // Negative worker health remains retained independently of exact
            // consumed identity. It cannot prevent the remaining physical owner
            // returns once that worker no longer pins the child or workspace.
            if state.callback_child.close_publication().is_err() {
                return;
            }
            if state.registration_groups.identity_return().is_err() {
                return;
            }
            // Mapping custody independently pins the actual child owner. The
            // current Source contract retains transferred mapping debt until a
            // genuine worker/material terminal producer supplies its last use.
            if state.workspace_mapping.identity_return().is_err() {
                return;
            }
            // Source group owners must consume their Native terminal receipts
            // before component drain revokes the registry and returns Setup6.
            // A refused or uncertain return retains this same entire Runtime.
            if state.control_component.identity_return().is_err() {
                return;
            }
            if state.registration_owner.retained()
                && state.registration_owner.identity_return().is_err()
            {
                return;
            }
            if state.callback_child.retains_storage() && !state.callback_child.identity_return() {
                return;
            }
            if state.command_storage.retains_storage()
                && (state.live_vcpu_time.is_some() || !state.command_storage.identity_return())
            {
                return;
            }
            // SAFETY: these actual retained-userdata guards have cleared. Native
            // independently checks detached observers/readers/material before
            // unmapping. Refusal retains the canonical field and entire Box.
            if !unsafe { state.setup.return_setup_mapping() } {
                return;
            }
            // SAFETY: this is the sole owning Box; neither a companion borrow nor
            // a registrar's retained userdata remains. ManuallyDrop prevents a
            // second automatic destruction.
            unsafe { std::mem::ManuallyDrop::drop(&mut self.state) };
        }
    }
}

impl std::fmt::Debug for RequiredOwnedCallbacksRegistered {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequiredOwnedCallbacksRegistered")
            .field("registration_mask", &self.registration_mask())
            .finish_non_exhaustive()
    }
}

impl RequiredOwnedCallbacksRegistered {
    /// Observes actual fingerprint registration before publishing SetupAck(0).
    fn wait_fingerprint_ready(&self) -> Result<(), PluginRuntimeInstallError> {
        let state = self.state.as_ref().get_ref();
        if let Some(live) = state.live_vcpu_time.as_ref() {
            live.as_ref()
                .get_ref()
                .wait_fingerprint_registered(|| state.setup.original_startup_slice())
                .map_err(
                    |source| PluginRuntimeInstallError::FingerprintWorkerReadiness { source },
                )?;
        }
        #[cfg(not(test))]
        state
            .fingerprint_worker_owner
            .check_registered()
            .map_err(|source| PluginRuntimeInstallError::FingerprintWorkerReadiness { source })?;
        state
            .setup
            .check_original_startup()
            .map_err(|source| PluginRuntimeInstallError::StartupSource { source })
    }

    #[cfg(not(test))]
    fn create_required_workers(&mut self) -> Result<(), PluginRuntimeInstallError> {
        // SAFETY: the state remains pinned; only disjoint inline keepers change.
        let state = unsafe { self.state.as_mut().get_unchecked_mut() };
        let child = state
            .registration_owner
            .native_projection()
            .map_err(|source| PluginRuntimeInstallError::OwnedCallbacks {
                source: OwnedCallbackRegistrationError::LiveVcpuTime { source },
            })?;
        state
            .required_workers
            .create(&state.setup, child, &state.workers, &state.teardown_router)
            .map_err(|source| PluginRuntimeInstallError::RequiredWorkers { source })?;
        state
            .required_workers
            .wait_ready(&state.setup)
            .map_err(|source| PluginRuntimeInstallError::RequiredWorkers { source })
    }

    #[cfg(not(test))]
    fn handoff_run_control(
        &mut self,
        stream: &mut Option<ControlLifecycleStream<SetupControlSocket>>,
    ) -> Result<(), PluginRuntimeInstallError> {
        // SAFETY: the actual paid Runtime and canonical fields do not move.
        let state = unsafe { self.state.as_mut().get_unchecked_mut() };
        state
            .setup
            .check_original_startup()
            .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
        let result = state.required_workers.handoff(stream);
        let post = state.setup.check_original_startup();
        state.required_workers.record_handoff_post(&post);
        result.map_err(|source| PluginRuntimeInstallError::RequiredWorkers { source })?;
        post.map_err(|source| PluginRuntimeInstallError::StartupSource { source })
    }

    #[cfg(not(test))]
    fn retire_required_workers(&mut self) -> Result<(), RequiredWorkerCleanupError> {
        // SAFETY: physical return changes no pinned callback body address.
        let state = unsafe { self.state.as_mut().get_unchecked_mut() };
        state.required_workers.identity_return(&mut state.setup)
    }

    #[cfg(not(test))]
    fn original_startup_slice(&self) -> Result<std::time::Duration, crate::ram_error::RamError> {
        self.state
            .as_ref()
            .get_ref()
            .setup
            .original_startup_slice()
            .map_err(crate::startup_source::InstallerStartupSource::retained_ram_error)
    }

    #[cfg(not(test))]
    fn complete_original_startup_registration(&mut self) -> Result<(), crate::ram_error::RamError> {
        // SAFETY: this mutates only the inline Source completion bit/owner,
        // without moving the pinned callback state or mapping.
        unsafe { self.state.as_mut().get_unchecked_mut() }
            .setup
            .complete_original_startup_registration()
            .map_err(crate::startup_source::InstallerStartupSource::retained_ram_error)
    }

    fn from_registered(
        state: Pin<Box<OwnedCallbackRuntimeState>>,
        registration_mask: OwnedCallbackRegistrationMask,
    ) -> Self {
        Self {
            state: std::mem::ManuallyDrop::new(state),
            registration_mask,
            #[cfg(test)]
            _teardown_receiver: None,
        }
    }

    /// Returns the exact callback-family mask proven by this owner.
    #[must_use]
    pub fn registration_mask(&self) -> OwnedCallbackRegistrationMask {
        self.registration_mask
    }

    pub(crate) fn setup(&self) -> &PluginSetupCompletion {
        &self.state.as_ref().get_ref().setup
    }

    fn userdata(&mut self) -> *mut std::ffi::c_void {
        self.state.as_mut().userdata()
    }

    /// Processes the mandatory setup-time fault capability query.
    ///
    /// # Errors
    ///
    /// Returns [`LiveVcpuTimeCallbackError`] when command transport, QEMU
    /// capability enumeration, or result publication fails.
    pub(crate) fn admit_fault_capabilities(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        #[cfg(test)]
        if self
            .state
            .as_ref()
            .get_ref()
            .allow_missing_fault_command_state
        {
            return Ok(());
        }
        self.state
            .as_ref()
            .get_ref()
            .live_vcpu_time
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::FaultCommandStateUnavailable)?
            .admit_fault_capabilities()
    }

    /// Installs live basic-block coverage into the pinned callback state.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageError`] when the slot ring cannot be mapped, its
    /// capacity is invalid, or coverage was already registered.
    pub(crate) fn register_basic_block_coverage(
        &mut self,
        plugin_id: QemuPluginId,
        slot_index: u32,
        callback: crate::CoverageCallback,
        apis: QemuBasicBlockCoverageApis,
    ) -> Result<(), CoverageError> {
        self.state
            .as_mut()
            .register_basic_block_coverage(plugin_id, slot_index, callback, apis)
    }

    /// Registers the setup wake fd after every owned callback is live.
    ///
    /// # Errors
    ///
    /// Returns [`PluginSetupError`] when the setup sequence is out of order,
    /// QEMU rejects the wake fd, or the failure acknowledgement cannot be sent.
    pub(crate) fn register_wake_fd_after_callbacks<W>(
        &mut self,
        writer: &mut W,
        register_wake_fd: QemuRegisterWakeFdFn,
    ) -> Result<(), PluginSetupError>
    where
        W: std::io::Write,
    {
        // SAFETY: this projection does not move `setup` out of the pinned state;
        // the called method only mutates fields in place.
        let state = unsafe { self.state.as_mut().get_unchecked_mut() };
        state
            .setup
            .register_wake_fd_after_callbacks(writer, register_wake_fd)
    }

    /// Waits for the scheduler's initial ceiling after the ready acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`crate::PluginSetupBootBarrierError`] when the acknowledgement
    /// is invalid, the slot does not match, or the shared-memory barrier fails.
    pub(crate) fn wait_boot_barrier(
        &mut self,
        setup_ack: crate::PluginReadySetupAck,
        slot_index: u32,
    ) -> Result<BootBarrierRelease, crate::PluginSetupBootBarrierError> {
        // SAFETY: this projection keeps `setup` at its pinned address and the
        // barrier implementation only borrows its mapping in place.
        let state = unsafe { self.state.as_mut().get_unchecked_mut() };
        state.setup.wait_boot_barrier(setup_ack, slot_index)
    }

    #[cfg(test)]
    pub(crate) fn for_test(args: &PluginArgs, setup: PluginSetupCompletion) -> Self {
        let mask = OwnedCallbackRegistrationMask::required_for(args);
        let (teardown_sender, teardown_receiver) = mpsc::channel();
        let mut registered = Self::from_registered(
            OwnedCallbackRuntimeState::pin(
                plugin_worker_mask(args),
                setup,
                LiveRuntimeTeardownRouter::new(teardown_sender),
                args.process_generation(),
                args.slot(),
                args.sim_fd(),
                test_hot_fork_child_request_shutdown,
            ),
            mask,
        );
        registered._teardown_receiver = Some(teardown_receiver);
        registered
    }

    #[cfg(test)]
    fn state_address_for_test(&self) -> usize {
        std::ptr::from_ref(self.state.as_ref().get_ref()) as usize
    }

    #[cfg(test)]
    fn coverage_is_registered_for_test(&self) -> bool {
        self.state.as_ref().get_ref().coverage.is_some()
    }

    #[cfg(all(unix, test))]
    fn control_teardown_handle(
        &self,
        slot_index: u32,
    ) -> Result<LiveControlTeardownHandle, PluginRuntimeInstallError> {
        let state = self.state.as_ref().get_ref();
        debug_assert_eq!(slot_index, state.slot_index);
        state
            .control_teardown_handle(state.process_generation)
            .map_err(|source| PluginRuntimeInstallError::TeardownSlot { source })
    }

    #[cfg(not(test))]
    fn worker_quiescence(&self) -> Arc<LiveWorkerQuiescence> {
        Arc::clone(&self.state.as_ref().get_ref().workers)
    }
}

#[cfg(unix)]
struct PluginSetupWriter<'a, S>(&'a mut ControlLifecycleStream<S>);

#[cfg(unix)]
impl<S> std::io::Write for PluginSetupWriter<'_, S>
where
    S: std::io::Write,
{
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .plugin_setup_io_mut()
            .map_err(io::Error::other)?
            .write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .plugin_setup_io_mut()
            .map_err(io::Error::other)?
            .flush()
    }
}

#[cfg(unix)]
struct LiveControlTeardownHandle {
    quiescence: Arc<LiveCallbackQuiescence>,
    header_address: usize,
    slot_address: usize,
    wake_fd: i32,
    control_callback_witness: Option<Arc<live_callbacks::ControlCallbackWitness>>,
    region_identity: crucible_qemu_shmem::SetupRegionBackingIdentity,
    slot_index: u32,
    process_generation: u64,
}

#[cfg(unix)]
impl LiveControlTeardownHandle {
    fn quiesce(&self) -> &NodeSlot {
        self.quiescence.close();
        let header = self.header();
        let slot = self.slot();
        if let Err(error) = header.request_shutdown([slot]) {
            emit_control_worker_diagnostic(&format!("shared-memory teardown wake failed: {error}"));
        }
        if let Err(error) = signal_teardown_wake_fd(self.wake_fd) {
            emit_control_worker_diagnostic(&format!("QEMU teardown wake failed: {error}"));
        }
        self.quiescence.wait_until_drained();
        slot
    }

    fn header(&self) -> &RegionHeader {
        // SAFETY: the active runtime owns the mapping and its `Drop` joins the
        // control worker before dropping callback state. Production leaks that
        // owner for QEMU's process lifetime.
        unsafe { &*(self.header_address as *const RegionHeader) }
    }

    fn slot(&self) -> &NodeSlot {
        // SAFETY: construction validated this slot in the same mapping whose
        // owner is retained until after the worker joins.
        unsafe { &*(self.slot_address as *const NodeSlot) }
    }

    fn report_final_control_callback(&self, teardown: &'static str) {
        if let Some(witness) = &self.control_callback_witness
            && witness.is_enabled()
        {
            // crucible-lint: allow direct-diagnostic -- This fixed final witness is advisory and uses the original joined teardown owner.
            let _result = witness.write_final_to(
                &mut std::io::stderr().lock(),
                self.region_identity,
                self.slot_index,
                self.process_generation,
                teardown,
                self.slot().control_boundary_token(),
            );
        }
    }
}

#[cfg(unix)]
fn read_run_control_trigger_retaining<S: std::io::Read + std::io::Write>(
    control: &mut ControlLifecycleStream<S>,
    retain_error: impl FnOnce(crate::PluginTeardownError) -> String,
) -> LiveRuntimeTeardownTrigger {
    match PluginHostQuit::read_from_run_control(control) {
        Ok(host_quit) => LiveRuntimeTeardownTrigger::HostQuit(host_quit),
        Err(error) => LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: retain_error(error),
        },
    }
}

#[cfg(all(unix, test))]
fn read_run_control_trigger<S: std::io::Read + std::io::Write>(
    mut control: ControlLifecycleStream<S>,
) -> LiveRuntimeTeardownTrigger {
    read_run_control_trigger_retaining(&mut control, |error| error.to_string())
}

#[cfg(all(unix, test))]
fn run_control_reader<S: std::io::Read + std::io::Write>(
    control: ControlLifecycleStream<S>,
    teardown_sender: impl TriggerPublisher,
    workers: Arc<LiveWorkerQuiescence>,
) -> bool {
    let Ok(_identity) = workers.register_current(WORKER_RUN_CONTROL) else {
        return false;
    };
    let idle = workers.idle(WORKER_RUN_CONTROL);
    let trigger = read_run_control_trigger(control);
    let pending = idle.received();
    let _operation = pending.enter();
    // A send failure means the sole teardown worker already selected another
    // concurrently delivered proof and returned. No second shutdown may run.
    teardown_sender.publish(trigger).is_ok()
}

#[cfg(all(unix, test))]
fn run_teardown_worker(
    teardown_receiver: impl TriggerConsumer,
    teardown_handle: LiveControlTeardownHandle,
    request_shutdown: QemuRequestShutdownFn,
    workers: Arc<LiveWorkerQuiescence>,
) {
    let Ok(_identity) = workers.register_current(WORKER_TEARDOWN) else {
        return;
    };
    let idle = workers.idle(WORKER_TEARDOWN);
    let trigger = match teardown_receiver.receive_trigger() {
        Ok(trigger) => trigger,
        Err(()) => {
            emit_control_worker_diagnostic(
                "teardown trigger owner closed before selecting a trigger",
            );
            std::process::abort();
        }
    };
    let pending = idle.received();
    let _operation = pending.enter();
    complete_live_teardown(trigger, teardown_handle, request_shutdown);
}

#[cfg(unix)]
fn perform_live_teardown(
    trigger: &LiveRuntimeTeardownTrigger,
    teardown_handle: &LiveControlTeardownHandle,
    request_shutdown: QemuRequestShutdownFn,
) -> Result<(), crate::PluginTeardownError> {
    let slot = teardown_handle.quiesce();
    let teardown_class = match &trigger {
        LiveRuntimeTeardownTrigger::HostQuit(_) => "host-quit",
        LiveRuntimeTeardownTrigger::SharedShutdown(_) => "shared-shutdown",
        LiveRuntimeTeardownTrigger::RunControlFault { .. } => "run-control-fault",
    };
    teardown_handle.report_final_control_callback(teardown_class);
    let mut teardown = PluginTeardown::new();
    let failure = matches!(trigger, LiveRuntimeTeardownTrigger::RunControlFault { .. });
    if let LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } = &trigger {
        emit_control_worker_diagnostic(&format!(
            "rejected run control and selected fail-loud shutdown: {diagnostic}"
        ));
    }
    let mut shutdown = LiveQemuShutdown {
        request_shutdown,
        failure,
    };
    let result = match trigger {
        LiveRuntimeTeardownTrigger::HostQuit(host_quit) => {
            teardown.teardown_after_host_quit(*host_quit, slot, &mut shutdown)
        }
        LiveRuntimeTeardownTrigger::SharedShutdown(shutdown_requested) => {
            teardown.teardown_after_shutdown_requested(*shutdown_requested, slot, &mut shutdown)
        }
        LiveRuntimeTeardownTrigger::RunControlFault { .. } => {
            teardown.teardown_after_run_control_fault(slot, &mut shutdown)
        }
    };
    result.map(|_| ())
}

#[cfg(test)]
fn complete_live_teardown(
    trigger: LiveRuntimeTeardownTrigger,
    teardown_handle: LiveControlTeardownHandle,
    request_shutdown: QemuRequestShutdownFn,
) {
    if let Err(error) = perform_live_teardown(&trigger, &teardown_handle, request_shutdown) {
        emit_control_worker_diagnostic(&format!("control teardown failed: {error}"));
        std::process::abort();
    }
}

#[cfg(all(unix, test))]
fn run_control_worker(
    control: ControlLifecycleStream<std::os::unix::net::UnixStream>,
    teardown_handle: LiveControlTeardownHandle,
    request_shutdown: QemuRequestShutdownFn,
) {
    complete_live_teardown(
        read_run_control_trigger(control),
        teardown_handle,
        request_shutdown,
    );
}

#[cfg(unix)]
struct LiveQemuShutdown {
    request_shutdown: QemuRequestShutdownFn,
    failure: bool,
}

#[cfg(unix)]
impl crate::PluginQemuShutdown for LiveQemuShutdown {
    fn initiate_orderly_qemu_shutdown(&mut self) -> Result<(), PluginQemuShutdownError> {
        (self.request_shutdown)(i32::from(self.failure));
        Ok(())
    }
}

#[cfg(unix)]
fn emit_control_worker_diagnostic(message: &str) {
    use std::io::Write as _;

    let _write_result = writeln!(std::io::stderr().lock(), "crucible-qemu-plugin: {message}");
}

/// QEMU functions needed by the live registration sequence.
#[derive(Clone, Copy)]
pub(crate) struct LiveInstallCapabilities {
    pub(crate) icount_raw: crate::QemuIcountRawFn,
    pub(crate) force_vcpu_exit: crate::QemuForceVcpuExitFn,
    pub(crate) idle_wake_wait: crate::QemuIdleWakeWait,
    pub(crate) request_vmstop: crate::QemuRequestVmstopFn,
    pub(crate) inject_preemption: Option<crate::QemuInjectPreemptionFn>,
    pub(crate) request_time_control: Option<QemuRequestTimeControlFn>,
    pub(crate) clock_deadline_ps: Option<QemuClockDeadlineFn>,
    pub(crate) advance_time_ticks: Option<QemuAdvanceTimeTicksFn>,
    pub(crate) register_time_advance_cb: Option<crate::QemuRegisterTimeAdvanceCbFn>,
    pub(crate) arm_virtual_timer_witness: Option<crate::QemuArmVirtualTimerWitnessFn>,
    pub(crate) query_virtual_timer_witness: Option<crate::QemuQueryVirtualTimerWitnessFn>,
    pub(crate) register_wake_fd: QemuRegisterWakeFdFn,
    pub(crate) register_resource_manifest: crate::QemuRegisterResourceManifestFn,
    pub(crate) register_hot_fork_barrier: crate::QemuRegisterHotForkBarrierFn,
    pub(crate) register_hot_fork_child_runtime: crate::QemuRegisterHotForkChildRuntimeFn,
    pub(crate) request_shutdown: QemuRequestShutdownFn,
    pub(crate) basic_block_coverage: Option<QemuBasicBlockCoverageApis>,
    pub(crate) register_vcpu_init: Option<crate::QemuRegisterVcpuInitCbFn>,
    pub(crate) register_vcpu_idle_resume: Option<crate::QemuRegisterVcpuIdleResumeCbFn>,
    pub(crate) register_control_boundary: Option<crate::QemuRegisterControlBoundaryCbFn>,
    pub(crate) register_sim_shmem_dispatch: Option<crate::QemuRegisterSimShmemDispatchCbFn>,
    pub(crate) register_net_tx: Option<crate::QemuRegisterNetTxCbFn>,
    pub(crate) net_inject: Option<crate::QemuPluginNetInjectFn>,
    pub(crate) register_block: Option<crate::QemuRegisterBlkCbFn>,
    pub(crate) register_block_event: Option<crate::QemuRegisterBlkEventCbFn>,
    pub(crate) register_block_wait: Option<crate::QemuRegisterBlkWaitCbFn>,
    pub(crate) register_ninep: Option<crate::QemuRegisterNinePCbFn>,
    pub(crate) register_accelerator: Option<crate::QemuRegisterAcceleratorCbFn>,
    pub(crate) fault_commands: crate::fault_command::QemuFaultCommandApis,
}

/// Registers the callback families whose C adapters own live device behavior.
///
/// `preflight` must not register callbacks or perform another irreversible QEMU
/// action because its failures return as ordinary install errors. Once
/// `register` is entered, QEMU may store a callback immediately, so every later
/// failure or panic is routed through [`PostRegistrationFatalPolicy`].
pub(crate) trait OwnedCallbackRegistrar {
    /// Describes actual configured allocations without creating resource authority.
    ///
    /// # Errors
    /// Refuses a registrar without a genuine configured-type producer.
    fn runtime_allocation_requests(
        &self,
        args: &PluginArgs,
    ) -> Result<prebirth::RuntimeAllocationRequests, crate::StartupSourceError> {
        #[cfg(test)]
        {
            // Isolated ordering fixtures describe their one-CPU model only.
            // The live registrar overrides this from its actual execution model.
            prebirth::RuntimeAllocationRequests::configured(1, args.fingerprint().is_on())
        }
        #[cfg(not(test))]
        {
            let _args = args;
            Err(crate::StartupSourceError::Ownership {
                reason: "callback registrar lacks its configured allocation producer",
            })
        }
    }

    fn preflight(&self, args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError>;

    fn register(
        &self,
        args: &PluginArgs,
        state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError>;
}

/// Terminates the process after callback installation may have begun.
///
/// Returning a nonzero value from `qemu_plugin_install` asks QEMU to uninstall
/// and unload the plugin. Crucible's custom QEMU callback slots are not yet
/// transactionally tied to that uninstall path, so no Rust function pointer may
/// have been stored before an ordinary install error returns.
trait PostRegistrationFatalPolicy {
    fn terminate(&self, error: PluginRuntimeInstallError) -> !;
}

struct AbortPostRegistrationFailure;

impl PostRegistrationFatalPolicy for AbortPostRegistrationFailure {
    fn terminate(&self, error: PluginRuntimeInstallError) -> ! {
        use std::io::Write as _;

        let _write_result = writeln!(
            std::io::stderr().lock(),
            "crucible-qemu-plugin: fatal failure after callback registration began: {error}"
        );
        std::process::abort();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum PostRegistrationStage {
    RegisterCallbacks,
    RequireCallbackCapabilities,
    RegisterWakeFd,
    AdmitFaultCapabilities,
    RegisterHotForkBarrier,
    RegisterHotForkChildRuntime,
    SealResourceManifest,
    SendReadyAck,
    WaitBootBarrier,
    Finalize,
}

#[cfg(test)]
static TEST_POST_REGISTRATION_PANIC_STAGE: AtomicU8 = AtomicU8::new(u8::MAX);

#[cfg(test)]
fn maybe_inject_post_registration_panic(stage: PostRegistrationStage) {
    if TEST_POST_REGISTRATION_PANIC_STAGE.load(Ordering::Relaxed) == stage as u8 {
        panic!(
            "injected panic at post-registration stage {}",
            stage.diagnostic()
        );
    }
}

#[cfg(not(test))]
const fn maybe_inject_post_registration_panic(_stage: PostRegistrationStage) {}

impl PostRegistrationStage {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::RegisterCallbacks => "RegisterCallbacks",
            Self::RequireCallbackCapabilities => "RequireCallbackCapabilities",
            Self::RegisterWakeFd => "RegisterWakeFd",
            Self::AdmitFaultCapabilities => "AdmitFaultCapabilities",
            Self::RegisterHotForkBarrier => "RegisterHotForkBarrier",
            Self::RegisterHotForkChildRuntime => "RegisterHotForkChildRuntime",
            Self::SealResourceManifest => "SealResourceManifest",
            Self::SendReadyAck => "SendReadyAck",
            Self::WaitBootBarrier => "WaitBootBarrier",
            Self::Finalize => "Finalize",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PostRegistrationAckState {
    Pending,
    FailureAttempted,
    ReadyAttempted,
    ReadySent,
}

/// Owns callback-addressable state until it moves into the active runtime.
///
/// Any other exit intentionally leaks the pinned allocation. This includes
/// unwinding: QEMU may already hold its address, and dropping it before the
/// process-fatal policy runs would create a dangling userdata pointer.
struct CallbackStateRetention {
    registering: Option<Pin<Box<OwnedCallbackRuntimeState>>>,
    registered: Option<RequiredOwnedCallbacksRegistered>,
}

impl CallbackStateRetention {
    fn new(state: Pin<Box<OwnedCallbackRuntimeState>>) -> Self {
        Self {
            registering: Some(state),
            registered: None,
        }
    }

    fn registering_mut(
        &mut self,
    ) -> Result<Pin<&mut OwnedCallbackRuntimeState>, PluginRuntimeInstallError> {
        self.registering
            .as_mut()
            .map(|state| state.as_mut())
            .ok_or(PluginRuntimeInstallError::CallbackRegistrationAlreadyPromoted)
    }

    fn promote(
        &mut self,
        registration_mask: OwnedCallbackRegistrationMask,
    ) -> Result<(), PluginRuntimeInstallError> {
        let state = self
            .registering
            .take()
            .ok_or(PluginRuntimeInstallError::CallbackRegistrationAlreadyPromoted)?;
        self.registered = Some(RequiredOwnedCallbacksRegistered::from_registered(
            state,
            registration_mask,
        ));
        Ok(())
    }

    fn registered(&self) -> Result<&RequiredOwnedCallbacksRegistered, PluginRuntimeInstallError> {
        self.registered
            .as_ref()
            .ok_or(PluginRuntimeInstallError::CallbackRegistrationProofUnavailable)
    }

    fn registered_mut(
        &mut self,
    ) -> Result<&mut RequiredOwnedCallbacksRegistered, PluginRuntimeInstallError> {
        self.registered
            .as_mut()
            .ok_or(PluginRuntimeInstallError::CallbackRegistrationProofUnavailable)
    }

    fn into_registered(
        mut self,
    ) -> Result<RequiredOwnedCallbacksRegistered, PluginRuntimeInstallError> {
        self.registered
            .take()
            .ok_or(PluginRuntimeInstallError::CallbackRegistrationProofUnavailable)
    }
}

impl Drop for CallbackStateRetention {
    fn drop(&mut self) {
        if let Some(mut state) = self.registering.take() {
            #[cfg(not(test))]
            {
                // SAFETY: the same retained Runtime remains pinned through rollback.
                let state = unsafe { state.as_mut().get_unchecked_mut() };
                let _rollback = state.required_workers.identity_return(&mut state.setup);
            }
            std::mem::forget(state);
        }
        if let Some(mut registered) = self.registered.take() {
            #[cfg(not(test))]
            let _rollback = registered.retire_required_workers();
            std::mem::forget(registered);
        }
    }
}

/// Production callback registrar with reversible capability preflight.
///
/// Default launches install the full vCPU, time, network, block, and 9p set.
/// White-box launches fail during side-effect-free preflight until the required
/// trap and guest-memory callback ABI is represented by concrete function types.
pub(crate) struct FailClosedOwnedCallbackRegistrar {
    live_vcpu_time: LiveVcpuTimeCallbackRegistrar,
}

impl FailClosedOwnedCallbackRegistrar {
    pub(crate) const fn production(
        plugin_id: QemuPluginId,
        execution_model: crate::QemuPluginExecutionModel,
        target_architecture: crate::abi::QemuPluginTargetArchitecture,
        capabilities: &LiveInstallCapabilities,
    ) -> Self {
        Self {
            live_vcpu_time: LiveVcpuTimeCallbackRegistrar::new(
                plugin_id,
                execution_model,
                target_architecture,
                LiveVcpuTimeCallbackCapabilities {
                    icount_raw: capabilities.icount_raw,
                    force_vcpu_exit: capabilities.force_vcpu_exit,
                    idle_wake_wait: capabilities.idle_wake_wait,
                    request_vmstop: capabilities.request_vmstop,
                    inject_preemption: capabilities.inject_preemption,
                    clock_deadline_ps: capabilities.clock_deadline_ps,
                    advance_time_ticks: capabilities.advance_time_ticks,
                    register_vcpu_init: capabilities.register_vcpu_init,
                    register_vcpu_idle_resume: capabilities.register_vcpu_idle_resume,
                    register_control_boundary: capabilities.register_control_boundary,
                    register_sim_shmem_dispatch: capabilities.register_sim_shmem_dispatch,
                    register_time_advance_cb: capabilities.register_time_advance_cb,
                    arm_virtual_timer_witness: capabilities.arm_virtual_timer_witness,
                    query_virtual_timer_witness: capabilities.query_virtual_timer_witness,
                    register_net_tx: capabilities.register_net_tx,
                    net_inject: capabilities.net_inject,
                    register_block: capabilities.register_block,
                    register_block_event: capabilities.register_block_event,
                    register_block_wait: capabilities.register_block_wait,
                    register_ninep: capabilities.register_ninep,
                    register_accelerator: capabilities.register_accelerator,
                    fault_commands: capabilities.fault_commands,
                    request_shutdown: capabilities.request_shutdown,
                },
            ),
        }
    }
}

impl OwnedCallbackRegistrar for FailClosedOwnedCallbackRegistrar {
    fn preflight(&self, args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
        self.live_vcpu_time.preflight(args)
    }

    fn register(
        &self,
        args: &PluginArgs,
        state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
        self.live_vcpu_time.register(args, state)
    }
}

/// Process-lifetime state retained after a successful plugin installation.
///
/// Native borrowed endpoints are interrupted only by their authentic owner.
/// Callback-addressable resources remain retained through process containment;
/// successful native interruption proves only that worker joins may proceed.
pub struct PluginRuntimeOwner {
    resources: std::mem::ManuallyDrop<RuntimeResources>,
}

struct RuntimeResources {
    plugin_id: QemuPluginId,
    args: PluginArgs,
    #[cfg(test)]
    _retained_control: Option<ControlLifecycleStream<SetupControlSocket>>,
    #[cfg(test)]
    _retained_teardown_receiver: Option<mpsc::Receiver<LiveRuntimeTeardownTrigger>>,
    _time_control: PluginTimeControlOwnership,
    _callbacks: RequiredOwnedCallbacksRegistered,
    _boot_release: BootBarrierRelease,
    _ready: PluginRegistrationReady,
}

#[cfg(test)]
fn join_finished_worker(worker: &mut Option<std::thread::JoinHandle<()>>) {
    // Socket interruption permits a return, but a held barrier can still park
    // the same worker. Observe its actual completion before any blocking join.
    if worker
        .as_ref()
        .is_some_and(std::thread::JoinHandle::is_finished)
        && let Some(worker) = worker.take()
    {
        let _joined = worker.join();
    }
}

impl Drop for PluginRuntimeOwner {
    fn drop(&mut self) {
        // This calls the native creating-thread cut on the SAME holder.
        // Expiry/refusal never authorizes shutdown of Rust's borrowed view.
        let _interruption = self.resources._callbacks.setup().interrupt_runtime_reader();
        #[cfg(not(test))]
        let _required_return = self.resources._callbacks.retire_required_workers();
        // ManuallyDrop retains parked/unreturned workers, mappings, callbacks
        // and native-purpose custody. Completed joins do not retire them.
    }
}

impl PluginRuntimeOwner {
    fn resources(&self) -> &RuntimeResources {
        &self.resources
    }

    /// Returns the QEMU-assigned plugin identifier.
    #[must_use]
    pub fn plugin_id(&self) -> QemuPluginId {
        self.resources().plugin_id
    }

    /// Returns the validated launch arguments retained by this runtime.
    #[must_use]
    pub fn args(&self) -> &PluginArgs {
        &self.resources().args
    }
}

/// Returns whether a fully active runtime has been retained for process lifetime.
#[must_use]
pub fn active_runtime_is_published() -> bool {
    RUNTIME_STATE.load(Ordering::Acquire) == RUNTIME_ACTIVE
}

/// Exclusive ownership of the singleton runtime installation slot.
///
/// The reservation is acquired before protocol I/O. Dropping a reversible
/// reservation makes the slot vacant again. After an irreversible protocol or
/// QEMU side effect, dropping the reservation permanently marks the singleton
/// failed.
pub(crate) struct PluginRuntimeReservation {
    irreversible: bool,
    finished: bool,
    #[cfg(unix)]
    startup_source: Option<crate::startup_source::InstallerStartupSource>,
    #[cfg(all(test, unix))]
    startup_source_model: Option<crate::startup_source::test_support::InstallerStartupSourceModel>,
}

impl PluginRuntimeReservation {
    pub(crate) const fn mark_irreversible(&mut self) {
        self.irreversible = true;
    }

    /// Retains the completed runtime and publishes the active state infallibly.
    ///
    /// Forgetting the owner is the production process-lifetime guarantee for
    /// QEMU callback userdata and for any worker that has not yet returned.
    /// The process exits after the worker's shutdown request, so neither the
    /// completed nor active worker can outlive the retained mapping.
    pub(crate) fn publish(mut self, runtime: PluginRuntimeOwner) {
        std::mem::forget(runtime);
        RUNTIME_STATE.store(RUNTIME_ACTIVE, Ordering::Release);
        self.finished = true;
    }
}

impl Drop for PluginRuntimeReservation {
    fn drop(&mut self) {
        if !self.finished {
            let terminal = if self.irreversible {
                RUNTIME_FAILED
            } else {
                RUNTIME_VACANT
            };
            RUNTIME_STATE.store(terminal, Ordering::Release);
        }
    }
}

/// Reserves the singleton runtime before any handshake or setup I/O.
///
/// # Errors
///
/// Returns [`PluginRuntimeInstallError::RuntimeAlreadyReserved`] when another
/// install is active or in progress, or an earlier install failed after an
/// irreversible protocol or QEMU side effect.
pub(crate) fn reserve_runtime() -> Result<PluginRuntimeReservation, PluginRuntimeInstallError> {
    RUNTIME_STATE
        .compare_exchange(
            RUNTIME_VACANT,
            RUNTIME_INSTALLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_state| PluginRuntimeInstallError::RuntimeAlreadyReserved)?;
    Ok(PluginRuntimeReservation {
        irreversible: false,
        finished: false,
        #[cfg(unix)]
        startup_source: None,
        #[cfg(all(test, unix))]
        startup_source_model: None,
    })
}

/// Runs the fixed registration sequence and builds an active runtime owner.
///
/// # Errors
///
/// Returns [`PluginRuntimeInstallError`] only for failures proven to occur before
/// callback registration begins. Once the registrar is entered, any failure or
/// unwind retains callback-addressable state and terminates the process so QEMU
/// cannot unload a cdylib whose functions may remain in custom callback slots.
#[cfg(unix)]
pub(crate) fn install_live_runtime<R>(
    plugin_id: QemuPluginId,
    args: PluginArgs,
    capabilities: LiveInstallCapabilities,
    callback_registrar: &R,
    reservation: &mut PluginRuntimeReservation,
) -> Result<PluginRuntimeOwner, PluginRuntimeInstallError>
where
    R: OwnedCallbackRegistrar,
{
    install_live_runtime_with_fatal_policy(
        plugin_id,
        args,
        capabilities,
        callback_registrar,
        reservation,
        &AbortPostRegistrationFailure,
    )
}

#[cfg(unix)]
fn install_live_runtime_with_fatal_policy<R, F>(
    plugin_id: QemuPluginId,
    args: PluginArgs,
    capabilities: LiveInstallCapabilities,
    callback_registrar: &R,
    reservation: &mut PluginRuntimeReservation,
    fatal_policy: &F,
) -> Result<PluginRuntimeOwner, PluginRuntimeInstallError>
where
    R: OwnedCallbackRegistrar,
    F: PostRegistrationFatalPolicy,
{
    let mut sequence = PluginRegistrationSequence::new();
    sequence
        .record_step(PluginRegistrationStep::ParseArguments)
        .map_err(registration_error)?;
    callback_registrar
        .preflight(&args)
        .map_err(|source| PluginRuntimeInstallError::OwnedCallbacks { source })?;

    #[cfg(not(test))]
    let selected = crate::startup_source::native_setup_selected()
        .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
    #[cfg(test)]
    let selected = if reservation
        .startup_source_model
        .as_ref()
        .is_some_and(|model| model.has_setup())
    {
        true
    } else {
        crate::startup_source::native_setup_selected()
            .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?
    };
    if !selected {
        return Err(PluginRuntimeInstallError::StartupSource {
            source: crate::StartupSourceError::Ownership {
                reason: "current native setup carrier is required",
            },
        });
    }
    // Retain the Source before its acquisition; neither refusal nor unwind
    // can turn native-owned aliases into Rust close/re-receive custody.
    reservation.startup_source =
        Some(crate::startup_source::InstallerStartupSource::retain_native_setup(plugin_id));
    reservation.mark_irreversible();
    let original =
        reservation
            .startup_source
            .as_mut()
            .ok_or(PluginRuntimeInstallError::StartupSource {
                source: crate::StartupSourceError::Ownership {
                    reason: "selected original startup custody is absent",
                },
            })?;
    #[cfg(test)]
    if let Some(model) = reservation.startup_source_model.take() {
        original.inject_model(model);
    }
    original
        .acquire_native_setup()
        .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
    let control_stream = original
        .control_socket()
        .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
    if std::os::fd::AsRawFd::as_raw_fd(&control_stream) != args.sim_fd() {
        return Err(PluginRuntimeInstallError::StartupSource {
            source: crate::StartupSourceError::Ownership {
                reason: "selected control differs from launch arguments",
            },
        });
    }
    let mut control_stream = ControlLifecycleStream::connected_unix_stream(control_stream)
        .map_err(|source| PluginRuntimeInstallError::ControlLifecycle { source })?;
    #[cfg(test)]
    let handshake_result = sequence.perform_control_handshake_lifecycle(&mut control_stream, &args);
    #[cfg(not(test))]
    let handshake_result =
        sequence.perform_source_control_handshake(&mut control_stream, &args, original);
    // Observe the postcut even on primary I/O failure; it cannot replace the
    // first handshake cause. Native retains any original refusal independently.
    let handshake_post = reservation
        .startup_source
        .as_ref()
        .map(|original| original.check());
    let handshake = handshake_result.map_err(registration_error)?;
    if let Some(post) = handshake_post {
        post.map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
    }
    let time_control = sequence
        .request_time_control(capabilities.request_time_control)
        .map_err(registration_error)?;
    let original =
        reservation
            .startup_source
            .as_ref()
            .ok_or(PluginRuntimeInstallError::StartupSource {
                source: crate::StartupSourceError::Ownership {
                    reason: "selected original startup custody is absent",
                },
            })?;
    let input = sequence
        .accept_native_setup(&mut control_stream, original)
        .map_err(registration_error)?;
    let original =
        reservation
            .startup_source
            .as_ref()
            .ok_or(PluginRuntimeInstallError::StartupSource {
                source: crate::StartupSourceError::Ownership {
                    reason: "original startup custody is absent before mapping",
                },
            })?;
    let mut setup = {
        let mut setup_writer = PluginSetupWriter(&mut control_stream);
        sequence
            .prepare_setup_completion_under_original(&mut setup_writer, input, original, handshake)
            .map_err(registration_error)?
    };
    let original =
        reservation
            .startup_source
            .take()
            .ok_or(PluginRuntimeInstallError::StartupSource {
                source: crate::StartupSourceError::Ownership {
                    reason: "original startup custody was already transferred",
                },
            })?;
    setup.retain_startup_source(original);
    // Fixed-control admission precedes runtime birth and stays with the same
    // Source for the later controller and initial pager prebirth check.
    setup
        .reserve_installer_control_purpose()
        .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
    let runtime_requests = callback_registrar
        .runtime_allocation_requests(&args)
        .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
    setup
        .reserve_runtime_allocations(&runtime_requests)
        .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;

    setup
        .check_runtime_installation()
        .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
    #[cfg(not(test))]
    let (teardown_router, teardown_receiver) = LiveRuntimeTeardownRouter::owned();
    #[cfg(test)]
    let (teardown_sender, teardown_receiver) = mpsc::channel();
    #[cfg(test)]
    let teardown_router = LiveRuntimeTeardownRouter::new(teardown_sender);
    setup
        .check_runtime_installation()
        .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
    let callback_state = OwnedCallbackRuntimeState::pin(
        plugin_worker_mask(&args),
        setup,
        Arc::clone(&teardown_router),
        args.process_generation(),
        args.slot(),
        args.sim_fd(),
        capabilities.request_shutdown,
    );
    let mut post_registration_stage = PostRegistrationStage::RegisterCallbacks;
    let mut acknowledgement_state = PostRegistrationAckState::Pending;
    let post_registration = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut retained = CallbackStateRetention::new(callback_state);
        #[cfg(not(test))]
        {
            let mut pinned = retained.registering_mut()?;
            // SAFETY: construction only fills the prepaid inline input holder.
            let state = unsafe { pinned.as_mut().get_unchecked_mut() };
            let handle = state
                .control_teardown_handle(state.process_generation)
                .map_err(|source| PluginRuntimeInstallError::TeardownSlot { source })?;
            state
                .required_workers
                .prepare(teardown_receiver, handle, state.request_shutdown);
        }
        // Retain the born pinned Runtime before its independent installing postcut.
        retained
            .registering_mut()?
            .as_ref()
            .get_ref()
            .setup
            .check_runtime_installation()
            .map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
        maybe_inject_post_registration_panic(post_registration_stage);
        // Registration retains this same pinned allocation before the RAM
        // actor can be born. It acquires no controller or service proof here.
        if args.ram_control().is_some() {
            if let Err(status) = checkpoint::register(plugin_id, retained.registering_mut()?) {
                return Err(fail_post_registration_before_ready_ack_lifecycle(
                    &mut control_stream,
                    PluginRuntimeInstallError::CheckpointPagerRejected { status },
                    &mut acknowledgement_state,
                ));
            }
        }
        let registration_mask =
            match callback_registrar.register(&args, retained.registering_mut()?) {
                Ok(registration_mask) => registration_mask,
                Err(source) => {
                    return Err(fail_owned_callback_registration_lifecycle(
                        &mut sequence,
                        &mut control_stream,
                        source,
                        &mut acknowledgement_state,
                    ));
                }
            };
        if let Err(source) = registration_mask.validate_for(&args) {
            return Err(fail_owned_callback_registration_lifecycle(
                &mut sequence,
                &mut control_stream,
                source,
                &mut acknowledgement_state,
            ));
        }
        retained.promote(registration_mask)?;

        post_registration_stage = PostRegistrationStage::RequireCallbackCapabilities;
        maybe_inject_post_registration_panic(post_registration_stage);
        let coverage_capabilities = if let Some(apis) = capabilities.basic_block_coverage {
            CoverageCapabilities::basic_blocks(apis)
        } else {
            CoverageCapabilities::none()
        };
        let callback_capabilities = match sequence.register_callbacks_with_exact_deadline(
            plugin_id,
            &args,
            retained.registered_mut()?,
            capabilities.clock_deadline_ps,
            capabilities.advance_time_ticks,
            coverage_capabilities,
        ) {
            Ok(capabilities) => capabilities,
            Err(source) => {
                return Err(fail_post_registration_before_ready_ack_lifecycle(
                    &mut control_stream,
                    registration_error(source),
                    &mut acknowledgement_state,
                ));
            }
        };

        post_registration_stage = PostRegistrationStage::RegisterWakeFd;
        maybe_inject_post_registration_panic(post_registration_stage);
        let wake_registration = {
            let mut setup_writer = PluginSetupWriter(&mut control_stream);
            sequence.register_wake_fd_after_callbacks(
                &mut setup_writer,
                retained.registered_mut()?,
                capabilities.register_wake_fd,
            )
        };
        if let Err(source) = wake_registration {
            acknowledgement_state = PostRegistrationAckState::FailureAttempted;
            return Err(registration_error(source));
        }

        post_registration_stage = PostRegistrationStage::AdmitFaultCapabilities;
        maybe_inject_post_registration_panic(post_registration_stage);
        if let Err(source) = retained.registered()?.admit_fault_capabilities() {
            return Err(fail_post_registration_before_ready_ack_lifecycle(
                &mut control_stream,
                PluginRuntimeInstallError::FaultCapabilityAdmission { source },
                &mut acknowledgement_state,
            ));
        }

        post_registration_stage = PostRegistrationStage::RegisterHotForkBarrier;
        maybe_inject_post_registration_panic(post_registration_stage);
        let barrier_status = (capabilities.register_hot_fork_barrier)(
            plugin_id,
            Some(crucible_qemu_plugin_hot_fork_barrier),
            retained.registered_mut()?.userdata(),
        );
        if barrier_status != 0 {
            return Err(fail_post_registration_before_ready_ack_lifecycle(
                &mut control_stream,
                PluginRuntimeInstallError::HotForkBarrierRejected {
                    status: barrier_status,
                },
                &mut acknowledgement_state,
            ));
        }

        if let Err(status) =
            parent_park::register(plugin_id, retained.registered_mut()?.state.as_mut())
        {
            return Err(fail_post_registration_before_ready_ack_lifecycle(
                &mut control_stream,
                PluginRuntimeInstallError::ParentParkDrainRejected { status },
                &mut acknowledgement_state,
            ));
        }

        post_registration_stage = PostRegistrationStage::RegisterHotForkChildRuntime;
        maybe_inject_post_registration_panic(post_registration_stage);
        let child_runtime_status = (capabilities.register_hot_fork_child_runtime)(
            plugin_id,
            Some(crucible_qemu_plugin_hot_fork_child_runtime),
            retained.registered_mut()?.userdata(),
        );
        if child_runtime_status != 0 {
            return Err(fail_post_registration_before_ready_ack_lifecycle(
                &mut control_stream,
                PluginRuntimeInstallError::HotForkChildRuntimeRejected {
                    status: child_runtime_status,
                },
                &mut acknowledgement_state,
            ));
        }

        post_registration_stage = PostRegistrationStage::SealResourceManifest;
        maybe_inject_post_registration_panic(post_registration_stage);
        let resource_manifest =
            match plugin_resource_manifest(plugin_id, &args, retained.registered()?) {
                Ok(manifest) => manifest,
                Err(error) => {
                    return Err(fail_post_registration_before_ready_ack_lifecycle(
                        &mut control_stream,
                        error,
                        &mut acknowledgement_state,
                    ));
                }
            };
        let manifest_status = (capabilities.register_resource_manifest)(&resource_manifest);
        if manifest_status != 0 {
            return Err(fail_post_registration_before_ready_ack_lifecycle(
                &mut control_stream,
                PluginRuntimeInstallError::ResourceManifestRejected {
                    status: manifest_status,
                },
                &mut acknowledgement_state,
            ));
        }

        post_registration_stage = PostRegistrationStage::SendReadyAck;
        maybe_inject_post_registration_panic(post_registration_stage);
        if let Err(error) = retained.registered()?.wait_fingerprint_ready() {
            return Err(fail_post_registration_before_ready_ack_lifecycle(
                &mut control_stream,
                error,
                &mut acknowledgement_state,
            ));
        }
        #[cfg(not(test))]
        if let Err(error) = retained.registered_mut()?.create_required_workers() {
            return Err(fail_post_registration_before_ready_ack_lifecycle(
                &mut control_stream,
                error,
                &mut acknowledgement_state,
            ));
        }
        acknowledgement_state = PostRegistrationAckState::ReadyAttempted;
        let setup_ack = {
            let mut setup_writer = PluginSetupWriter(&mut control_stream);
            sequence
                .send_ready_setup_ack(
                    &mut setup_writer,
                    &callback_capabilities,
                    retained.registered()?,
                )
                .map_err(registration_error)?
        };
        control_stream
            .plugin_commit_ready_setup_ack()
            .map_err(|source| PluginRuntimeInstallError::ControlLifecycle { source })?;
        acknowledgement_state = PostRegistrationAckState::ReadySent;

        post_registration_stage = PostRegistrationStage::WaitBootBarrier;
        maybe_inject_post_registration_panic(post_registration_stage);
        let boot_release = sequence
            .wait_mapped_boot_barrier(setup_ack, retained.registered_mut()?, args.slot())
            .map_err(registration_error)?;

        post_registration_stage = PostRegistrationStage::Finalize;
        maybe_inject_post_registration_panic(post_registration_stage);
        sequence
            .record_step(PluginRegistrationStep::FirstVisibleInstruction)
            .map_err(registration_error)?;
        let ready = sequence.finish().map_err(registration_error)?;
        let callbacks_registered = retained.into_registered()?;

        Ok((callbacks_registered, boot_release, ready))
    }));

    match post_registration {
        Ok(Ok((callbacks_registered, boot_release, ready))) => {
            if let Err(source) = control_stream.enter_run_via_shared_memory() {
                fatal_policy.terminate(PluginRuntimeInstallError::ControlLifecycle { source });
            }
            match control_stream.plugin_run_io_mut() {
                Ok(control) => control.enter_run(),
                Err(source) => {
                    fatal_policy.terminate(PluginRuntimeInstallError::ControlLifecycle { source })
                }
            }
            #[cfg(not(test))]
            let mut callbacks_registered = callbacks_registered;
            #[cfg(not(test))]
            {
                let mut stream = Some(control_stream);
                if let Err(error) = callbacks_registered.handoff_run_control(&mut stream) {
                    fatal_policy.terminate(error);
                }
                let workers = callbacks_registered.worker_quiescence();
                if let Err(source) = workers
                    .wait_initial_ready(|| callbacks_registered.original_startup_slice())
                    .and_then(|()| callbacks_registered.complete_original_startup_registration())
                {
                    fatal_policy
                        .terminate(PluginRuntimeInstallError::WorkerIdentityAdmission { source });
                }
            }
            #[cfg(test)]
            let retained_control = Some(control_stream);
            let resources = RuntimeResources {
                plugin_id,
                args,
                #[cfg(test)]
                _retained_control: retained_control,
                #[cfg(test)]
                _retained_teardown_receiver: Some(teardown_receiver),
                _time_control: time_control,
                _callbacks: callbacks_registered,
                _boot_release: boot_release,
                _ready: ready,
            };
            Ok(PluginRuntimeOwner {
                resources: std::mem::ManuallyDrop::new(resources),
            })
        }
        Ok(Err(error)) => {
            let error = if acknowledgement_state == PostRegistrationAckState::Pending {
                fail_post_registration_before_ready_ack_lifecycle(
                    &mut control_stream,
                    error,
                    &mut acknowledgement_state,
                )
            } else {
                error
            };
            fatal_policy.terminate(error)
        }
        Err(_panic) => {
            let error = post_registration_panic_error_lifecycle(
                &mut control_stream,
                post_registration_stage,
                &mut acknowledgement_state,
            );
            fatal_policy.terminate(error)
        }
    }
}

fn registration_error(source: PluginRegistrationSequenceError) -> PluginRuntimeInstallError {
    PluginRuntimeInstallError::Registration { source }
}

fn fail_owned_callback_registration<W>(
    sequence: &mut PluginRegistrationSequence,
    control_stream: &mut W,
    source: OwnedCallbackRegistrationError,
    acknowledgement_state: &mut PostRegistrationAckState,
) -> PluginRuntimeInstallError
where
    W: std::io::Write,
{
    let _failure = sequence.fail_step(
        PluginRegistrationStep::RegisterCallbacks,
        source.to_string(),
    );
    *acknowledgement_state = PostRegistrationAckState::FailureAttempted;
    match send_callback_registration_failure_ack(control_stream) {
        Ok(()) => PluginRuntimeInstallError::OwnedCallbacks { source },
        Err(ack_source) => PluginRuntimeInstallError::CallbackFailureAck {
            callback_source: Box::new(source),
            ack_source,
        },
    }
}

#[cfg(unix)]
fn fail_owned_callback_registration_lifecycle<S>(
    sequence: &mut PluginRegistrationSequence,
    control_stream: &mut ControlLifecycleStream<S>,
    source: OwnedCallbackRegistrationError,
    acknowledgement_state: &mut PostRegistrationAckState,
) -> PluginRuntimeInstallError
where
    S: std::io::Write,
{
    let mut writer = PluginSetupWriter(control_stream);
    fail_owned_callback_registration(sequence, &mut writer, source, acknowledgement_state)
}

fn fail_post_registration_before_ready_ack<W>(
    control_stream: &mut W,
    error: PluginRuntimeInstallError,
    acknowledgement_state: &mut PostRegistrationAckState,
) -> PluginRuntimeInstallError
where
    W: std::io::Write,
{
    let failure = error.to_string();
    *acknowledgement_state = PostRegistrationAckState::FailureAttempted;
    match send_callback_registration_failure_ack(control_stream) {
        Ok(()) => error,
        Err(ack_source) => PluginRuntimeInstallError::PostRegistrationFailureAck {
            failure,
            ack_source,
        },
    }
}

#[cfg(unix)]
fn fail_post_registration_before_ready_ack_lifecycle<S>(
    control_stream: &mut ControlLifecycleStream<S>,
    error: PluginRuntimeInstallError,
    acknowledgement_state: &mut PostRegistrationAckState,
) -> PluginRuntimeInstallError
where
    S: std::io::Write,
{
    let mut writer = PluginSetupWriter(control_stream);
    fail_post_registration_before_ready_ack(&mut writer, error, acknowledgement_state)
}

fn post_registration_panic_error<W>(
    control_stream: &mut W,
    stage: PostRegistrationStage,
    acknowledgement_state: &mut PostRegistrationAckState,
) -> PluginRuntimeInstallError
where
    W: std::io::Write,
{
    let panic_error = || {
        if stage == PostRegistrationStage::RegisterCallbacks {
            PluginRuntimeInstallError::CallbackRegistrationPanicked
        } else {
            PluginRuntimeInstallError::PostRegistrationPanicked {
                stage: stage.diagnostic(),
            }
        }
    };
    if *acknowledgement_state != PostRegistrationAckState::Pending {
        return panic_error();
    }

    *acknowledgement_state = PostRegistrationAckState::FailureAttempted;
    match send_callback_registration_failure_ack(control_stream) {
        Ok(()) => panic_error(),
        Err(ack_source) if stage == PostRegistrationStage::RegisterCallbacks => {
            PluginRuntimeInstallError::CallbackPanicFailureAck { ack_source }
        }
        Err(ack_source) => PluginRuntimeInstallError::PostRegistrationPanicFailureAck {
            stage: stage.diagnostic(),
            ack_source,
        },
    }
}

#[cfg(unix)]
fn post_registration_panic_error_lifecycle<S>(
    control_stream: &mut ControlLifecycleStream<S>,
    stage: PostRegistrationStage,
    acknowledgement_state: &mut PostRegistrationAckState,
) -> PluginRuntimeInstallError
where
    S: std::io::Write,
{
    let mut writer = PluginSetupWriter(control_stream);
    post_registration_panic_error(&mut writer, stage, acknowledgement_state)
}

#[cfg(all(test, unix))]
mod tests;
