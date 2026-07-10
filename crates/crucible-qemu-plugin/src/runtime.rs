//! Live QEMU plugin installation and process-lifetime runtime ownership.
//!
//! This module joins the existing typed registration stages without weakening
//! their fail-stop boundaries. The active owner is published only after the
//! complete required callback set is registered, `SetupAck(0)` is sent, and the
//! mapped boot barrier releases. Production preflight validates every callback
//! required by the selected launch mode before the control handshake or any
//! QEMU callback registration; optional white-box mode remains closed until its
//! concrete trap and guest-memory callback ABI is available.

mod live_callbacks;

#[cfg(test)]
use live_callbacks::clear_live_vcpu_time_state_for_test;
pub use live_callbacks::{LiveDeviceCallbackError, LiveVcpuTimeCallbackError};
use live_callbacks::{LiveVcpuTimeCallbackCapabilities, LiveVcpuTimeCallbackRegistrar};

use std::marker::PhantomPinned;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};

use thiserror::Error;

use crate::coverage::{LiveBasicBlockCoverage, LiveCoverageShmemProducer};
use crate::{
    BootBarrierRelease, CoverageCapabilities, CoverageError, PluginArgs, PluginLifecyclePhase,
    PluginRegistrationReady, PluginRegistrationSequence, PluginRegistrationSequenceError,
    PluginRegistrationStep, PluginSetupCompletion, PluginSetupError, PluginStatePartition,
    PluginTimeControlOwnership, QemuAdvanceTimeNsFn, QemuBasicBlockCoverageApis,
    QemuClockDeadlineFn, QemuPluginId, QemuRegisterWakeFdFn, QemuRequestTimeControlFn,
    send_callback_registration_failure_ack,
};

/// Callback families that must be live before the plugin can acknowledge setup.
pub const REQUIRED_OWNED_CALLBACK_FAMILIES: &str = "vCPU init/resume/idle, network TX/RX, block submit/poll, 9p burst/submit/poll, and optional white-box doorbell";

const RUNTIME_VACANT: u8 = 0;
const RUNTIME_INSTALLING: u8 = 1;
const RUNTIME_ACTIVE: u8 = 2;
const RUNTIME_FAILED: u8 = 3;
static RUNTIME_STATE: AtomicU8 = AtomicU8::new(RUNTIME_VACANT);
#[cfg(test)]
static RUNTIME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
static LIVE_COVERAGE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) struct RuntimeStateTestGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for RuntimeStateTestGuard {
    fn drop(&mut self) {
        clear_live_vcpu_time_state_for_test();
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
    use std::io::Write as _;

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
    const WHITEBOX: u16 = 1 << 4;
    const BASE_REQUIRED: u16 = Self::VCPU | Self::NETWORK | Self::BLOCK | Self::NINEP;

    const fn base_required() -> Self {
        Self {
            bits: Self::BASE_REQUIRED,
        }
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

/// Heap-stable state addressed by future QEMU callback userdata pointers.
///
/// The setup mapping and wake descriptor move into this allocation before any
/// owned callback may be registered. The allocation remains pinned while the
/// proof is live, so moving the proof never moves callback-addressable state.
pub(crate) struct OwnedCallbackRuntimeState {
    live_vcpu_time: Option<Pin<Box<live_callbacks::LiveVcpuTimeCallbackState>>>,
    setup: PluginSetupCompletion,
    coverage: Option<LiveBasicBlockCoverage>,
    _pin: PhantomPinned,
}

impl OwnedCallbackRuntimeState {
    fn pin(setup: PluginSetupCompletion) -> Pin<Box<Self>> {
        Box::pin(Self {
            live_vcpu_time: None,
            setup,
            coverage: None,
            _pin: PhantomPinned,
        })
    }

    /// Returns the stable opaque pointer supplied as QEMU callback userdata.
    // crucible-lint: allow rust-allow -- test registration probes inspect the stable pinned owner address.
    #[allow(
        dead_code,
        reason = "test registration probes inspect this stable owner"
    )]
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
        icount_raw: crate::QemuIcountRawFn,
        initial_raw_icount: u64,
        exact_deadline: crate::ExactDeadlineReader,
        queued_idle_advance: crate::QueuedIdleAdvance,
        network_rx: crate::QemuLosslessNetworkRxQueue,
    ) -> Result<*mut live_callbacks::LiveVcpuTimeCallbackState, LiveVcpuTimeCallbackError> {
        // SAFETY: this projection does not move the pinned parent or any
        // independently pinned callback allocation. The new allocation is
        // installed before its address becomes observable to QEMU.
        let state = unsafe { self.get_unchecked_mut() };
        let layout = state.setup.mapped_region().layout().map_err(|source| {
            LiveVcpuTimeCallbackError::MappedNodeSlot {
                source: crucible_shmem::MappedSetupRegionAccessError::Header { source },
            }
        })?;
        let icount_shift = u8::try_from(layout.icount_shift).map_err(|_error| {
            LiveVcpuTimeCallbackError::IcountShiftOutOfRange {
                icount_shift: layout.icount_shift,
            }
        })?;
        let header = std::ptr::NonNull::from(state.setup.mapped_region().header());
        let router_slot = crucible_shmem::SLOT_NET_ROUTER as u32;
        let mapped = state
            .setup
            .mapped_region_mut()
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
        let callback_state = live_callbacks::LiveVcpuTimeCallbackState::new(
            plugin_id,
            icount_raw,
            vcpu_count,
            icount_shift,
            initial_raw_icount,
            exact_deadline,
            queued_idle_advance,
            header,
            mapped.node_slot,
        )?
        .attach_network(slot_index, mapped.first, mapped.second, network_rx)?;
        let block_slot = crucible_shmem::SLOT_BLK_IO as u32;
        let mapped = state
            .setup
            .mapped_region_mut()
            .node_directed_ring_pair_mut(slot_index, slot_index, block_slot, block_slot, slot_index)
            .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
        let block_rings = live_callbacks::LiveDirectedRingPair::new(mapped.first, mapped.second)?;
        let ninep_slot = crucible_shmem::SLOT_9P_IO as u32;
        let mapped = state
            .setup
            .mapped_region_mut()
            .node_directed_ring_pair_mut(slot_index, slot_index, ninep_slot, ninep_slot, slot_index)
            .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
        let ninep_rings = live_callbacks::LiveDirectedRingPair::new(mapped.first, mapped.second)?;
        let callback_state = callback_state.attach_devices(slot_index, block_rings, ninep_rings)?;
        let callback_state = Box::pin(callback_state);
        let callback_pointer = std::ptr::from_ref(callback_state.as_ref().get_ref()).cast_mut();
        state.live_vcpu_time = Some(callback_state);
        Ok(callback_pointer)
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
        state.coverage = Some(LiveBasicBlockCoverage::register(
            plugin_id, callback, apis, output,
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
    state: Pin<Box<OwnedCallbackRuntimeState>>,
    registration_mask: OwnedCallbackRegistrationMask,
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
    fn from_registered(
        state: Pin<Box<OwnedCallbackRuntimeState>>,
        registration_mask: OwnedCallbackRegistrationMask,
    ) -> Self {
        Self {
            state,
            registration_mask,
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
        Self::from_registered(OwnedCallbackRuntimeState::pin(setup), mask)
    }

    #[cfg(test)]
    fn state_address_for_test(&self) -> usize {
        std::ptr::from_ref(self.state.as_ref().get_ref()) as usize
    }

    #[cfg(test)]
    fn coverage_is_registered_for_test(&self) -> bool {
        self.state.as_ref().get_ref().coverage.is_some()
    }
}

/// QEMU functions needed by the live registration sequence.
#[derive(Clone, Copy)]
pub(crate) struct LiveInstallCapabilities {
    pub(crate) icount_raw: crate::QemuIcountRawFn,
    pub(crate) request_time_control: Option<QemuRequestTimeControlFn>,
    pub(crate) clock_deadline_ns: Option<QemuClockDeadlineFn>,
    pub(crate) advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    pub(crate) register_time_advance_cb: Option<crate::QemuRegisterTimeAdvanceCbFn>,
    pub(crate) register_wake_fd: QemuRegisterWakeFdFn,
    pub(crate) basic_block_coverage: Option<QemuBasicBlockCoverageApis>,
    pub(crate) register_vcpu_init: Option<crate::QemuRegisterVcpuInitCbFn>,
    pub(crate) register_vcpu_idle_resume: Option<crate::QemuRegisterVcpuIdleResumeCbFn>,
    pub(crate) register_sim_shmem_dispatch: Option<crate::QemuRegisterSimShmemDispatchCbFn>,
    pub(crate) register_net_tx: Option<crate::QemuRegisterNetTxCbFn>,
    pub(crate) net_send: Option<crate::QemuPluginNetSendFn>,
    pub(crate) net_flush: Option<crate::QemuPluginNetFlushFn>,
    pub(crate) register_block: Option<crate::QemuRegisterBlkCbFn>,
    pub(crate) register_ninep: Option<crate::QemuRegisterNinePCbFn>,
}

/// Registers the callback families whose C adapters own live device behavior.
///
/// `preflight` must not register callbacks or perform another irreversible QEMU
/// action because its failures return as ordinary install errors. Once
/// `register` is entered, QEMU may store a callback immediately, so every later
/// failure or panic is routed through [`PostRegistrationFatalPolicy`].
pub(crate) trait OwnedCallbackRegistrar {
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

    fn registering_mut(&mut self) -> Pin<&mut OwnedCallbackRuntimeState> {
        match self.registering.as_mut() {
            Some(state) => state.as_mut(),
            None => panic!("callback registration state was already promoted"),
        }
    }

    fn promote(&mut self, registration_mask: OwnedCallbackRegistrationMask) {
        let state = match self.registering.take() {
            Some(state) => state,
            None => panic!("callback registration state was already promoted"),
        };
        self.registered = Some(RequiredOwnedCallbacksRegistered::from_registered(
            state,
            registration_mask,
        ));
    }

    fn registered(&self) -> &RequiredOwnedCallbacksRegistered {
        match self.registered.as_ref() {
            Some(registered) => registered,
            None => panic!("callback registration proof is not available"),
        }
    }

    fn registered_mut(&mut self) -> &mut RequiredOwnedCallbacksRegistered {
        match self.registered.as_mut() {
            Some(registered) => registered,
            None => panic!("callback registration proof is not available"),
        }
    }

    fn into_registered(mut self) -> RequiredOwnedCallbacksRegistered {
        match self.registered.take() {
            Some(registered) => registered,
            None => panic!("callback registration proof is not available"),
        }
    }
}

impl Drop for CallbackStateRetention {
    fn drop(&mut self) {
        if let Some(state) = self.registering.take() {
            std::mem::forget(state);
        }
        if let Some(registered) = self.registered.take() {
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
        capabilities: &LiveInstallCapabilities,
    ) -> Self {
        Self {
            live_vcpu_time: LiveVcpuTimeCallbackRegistrar::new(
                plugin_id,
                execution_model,
                LiveVcpuTimeCallbackCapabilities {
                    icount_raw: capabilities.icount_raw,
                    clock_deadline_ns: capabilities.clock_deadline_ns,
                    advance_time_ns: capabilities.advance_time_ns,
                    register_vcpu_init: capabilities.register_vcpu_init,
                    register_vcpu_idle_resume: capabilities.register_vcpu_idle_resume,
                    register_sim_shmem_dispatch: capabilities.register_sim_shmem_dispatch,
                    register_time_advance_cb: capabilities.register_time_advance_cb,
                    register_net_tx: capabilities.register_net_tx,
                    net_send: capabilities.net_send,
                    net_flush: capabilities.net_flush,
                    register_block: capabilities.register_block,
                    register_ninep: capabilities.register_ninep,
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
pub struct PluginRuntimeOwner {
    plugin_id: QemuPluginId,
    args: PluginArgs,
    state: PluginStatePartition,
    _control_stream: UnixStream,
    _time_control: PluginTimeControlOwnership,
    _callbacks: RequiredOwnedCallbacksRegistered,
    _boot_release: BootBarrierRelease,
    _ready: PluginRegistrationReady,
}

impl PluginRuntimeOwner {
    /// Returns the QEMU-assigned plugin identifier.
    #[must_use]
    pub const fn plugin_id(&self) -> QemuPluginId {
        self.plugin_id
    }

    /// Returns the validated launch arguments retained by this runtime.
    #[must_use]
    pub const fn args(&self) -> &PluginArgs {
        &self.args
    }

    /// Returns the active lifecycle phase.
    #[must_use]
    pub const fn lifecycle_phase(&self) -> PluginLifecyclePhase {
        self.state.lifecycle_core().phase()
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
}

impl PluginRuntimeReservation {
    pub(crate) const fn mark_irreversible(&mut self) {
        self.irreversible = true;
    }

    /// Retains the completed runtime and publishes the active state infallibly.
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
    state: PluginStatePartition,
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
        state,
        capabilities,
        callback_registrar,
        reservation,
        &AbortPostRegistrationFailure,
    )
}

#[cfg(unix)]
// crucible-lint: allow rust-allow -- the testable fatal policy extends the fixed live-install boundary.
#[allow(
    clippy::too_many_arguments,
    reason = "the testable fatal policy extends the fixed live-install boundary"
)]
fn install_live_runtime_with_fatal_policy<R, F>(
    plugin_id: QemuPluginId,
    args: PluginArgs,
    mut state: PluginStatePartition,
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

    let mut control_stream =
        crate::abi::duplicate_control_stream(args.sim_fd()).map_err(|source| {
            PluginRuntimeInstallError::DuplicateControlFd {
                fd: args.sim_fd(),
                source,
            }
        })?;
    reservation.mark_irreversible();
    let handshake = sequence
        .perform_control_handshake(&mut control_stream, &args)
        .map_err(registration_error)?;
    let time_control = sequence
        .request_time_control(capabilities.request_time_control)
        .map_err(registration_error)?;
    let setup = sequence
        .receive_setup_with_descriptors(&mut control_stream)
        .map_err(registration_error)?;
    let setup = sequence
        .prepare_setup_completion(&mut control_stream, setup, handshake)
        .map_err(registration_error)?;

    let callback_state = OwnedCallbackRuntimeState::pin(setup);
    let mut post_registration_stage = PostRegistrationStage::RegisterCallbacks;
    let mut acknowledgement_state = PostRegistrationAckState::Pending;
    let post_registration = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut retained = CallbackStateRetention::new(callback_state);
        maybe_inject_post_registration_panic(post_registration_stage);
        let registration_mask = match callback_registrar.register(&args, retained.registering_mut())
        {
            Ok(registration_mask) => registration_mask,
            Err(source) => {
                return Err(fail_owned_callback_registration(
                    &mut sequence,
                    &mut control_stream,
                    source,
                    &mut acknowledgement_state,
                ));
            }
        };
        if let Err(source) = registration_mask.validate_for(&args) {
            return Err(fail_owned_callback_registration(
                &mut sequence,
                &mut control_stream,
                source,
                &mut acknowledgement_state,
            ));
        }
        retained.promote(registration_mask);

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
            retained.registered_mut(),
            capabilities.clock_deadline_ns,
            capabilities.advance_time_ns,
            coverage_capabilities,
        ) {
            Ok(capabilities) => capabilities,
            Err(source) => {
                return Err(fail_post_registration_before_ready_ack(
                    &mut control_stream,
                    registration_error(source),
                    &mut acknowledgement_state,
                ));
            }
        };

        post_registration_stage = PostRegistrationStage::RegisterWakeFd;
        maybe_inject_post_registration_panic(post_registration_stage);
        if let Err(source) = sequence.register_wake_fd_after_callbacks(
            &mut control_stream,
            retained.registered_mut(),
            capabilities.register_wake_fd,
        ) {
            acknowledgement_state = PostRegistrationAckState::FailureAttempted;
            return Err(registration_error(source));
        }

        post_registration_stage = PostRegistrationStage::SendReadyAck;
        maybe_inject_post_registration_panic(post_registration_stage);
        acknowledgement_state = PostRegistrationAckState::ReadyAttempted;
        let setup_ack = sequence
            .send_ready_setup_ack(
                &mut control_stream,
                &callback_capabilities,
                retained.registered(),
            )
            .map_err(registration_error)?;
        acknowledgement_state = PostRegistrationAckState::ReadySent;

        post_registration_stage = PostRegistrationStage::WaitBootBarrier;
        maybe_inject_post_registration_panic(post_registration_stage);
        let boot_release = sequence
            .wait_mapped_boot_barrier(setup_ack, retained.registered_mut(), args.slot())
            .map_err(registration_error)?;

        post_registration_stage = PostRegistrationStage::Finalize;
        maybe_inject_post_registration_panic(post_registration_stage);
        sequence
            .record_step(PluginRegistrationStep::FirstVisibleInstruction)
            .map_err(registration_error)?;
        let ready = sequence.finish().map_err(registration_error)?;
        state.activate(&ready, retained.registered());
        let callbacks_registered = retained.into_registered();

        Ok((callbacks_registered, boot_release, ready))
    }));

    match post_registration {
        Ok(Ok((callbacks_registered, boot_release, ready))) => Ok(PluginRuntimeOwner {
            plugin_id,
            args,
            state,
            _control_stream: control_stream,
            _time_control: time_control,
            _callbacks: callbacks_registered,
            _boot_release: boot_release,
            _ready: ready,
        }),
        Ok(Err(error)) => fatal_policy.terminate(error),
        Err(_panic) => {
            let error = post_registration_panic_error(
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
            callback_source: source,
            ack_source,
        },
    }
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

/// An error produced while registering plugin-owned callbacks.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum OwnedCallbackRegistrationError {
    /// One or more required live callback adapters do not exist yet.
    #[error("required callback adapters are unavailable: {families}")]
    AdaptersUnavailable {
        /// Callback families that still need live QEMU-facing adapters.
        families: &'static str,
    },
    /// The live vCPU-boundary, sim-time, or network callback slice failed.
    #[error("live production callback registration failed: {source}")]
    LiveVcpuTime {
        /// Underlying capability, mapping, or dispatch-state failure.
        source: LiveVcpuTimeCallbackError,
    },
    /// The registrar did not prove every callback required by the selected mode.
    #[error(
        "owned callback registration mask is incomplete: required {required:#06x}, got {actual:#06x}"
    )]
    IncompleteRegistrationMask {
        /// Exact mask required by the launch arguments.
        required: u16,
        /// Mask actually installed by the registrar.
        actual: u16,
    },
}

/// A failure crossing from QEMU's raw install boundary into live registration.
#[derive(Debug, Error)]
pub(crate) enum PluginLiveBoundaryError {
    /// Raw ABI validation or deterministic capability resolution failed.
    #[error("QEMU plugin ABI validation failed: {0}")]
    Abi(#[from] crate::QemuPluginAbiError),
    /// The ordered live registration sequence failed.
    #[error("QEMU plugin live registration failed: {0}")]
    Runtime(#[from] PluginRuntimeInstallError),
}

/// An error produced while building or publishing the live plugin runtime.
#[derive(Debug, Error)]
pub enum PluginRuntimeInstallError {
    /// The inherited control descriptor could not be duplicated safely.
    #[error("duplicating plugin control fd {fd} failed: {source}")]
    DuplicateControlFd {
        /// Rejected inherited descriptor.
        fd: i32,
        /// Underlying descriptor error.
        source: std::io::Error,
    },
    /// A typed registration step failed.
    #[error("live plugin registration failed: {source}")]
    Registration {
        /// Underlying fail-stop sequence error.
        source: PluginRegistrationSequenceError,
    },
    /// The complete required callback set was unavailable.
    #[error("live plugin callback registration failed at RegisterCallbacks: {source}")]
    OwnedCallbacks {
        /// Underlying callback registration error.
        source: OwnedCallbackRegistrationError,
    },
    /// The callback failure could not be acknowledged to the host.
    #[error(
        "callback registration failed at RegisterCallbacks ({callback_source}); acknowledging that failure also failed: {ack_source}"
    )]
    CallbackFailureAck {
        /// Original callback registration failure.
        callback_source: OwnedCallbackRegistrationError,
        /// Underlying setup acknowledgement failure.
        ack_source: PluginSetupError,
    },
    /// Callback registration panicked after pinned userdata became observable.
    #[error("live plugin callback registration panicked at RegisterCallbacks")]
    CallbackRegistrationPanicked,
    /// Callback registration panicked and its failure acknowledgement also failed.
    #[error(
        "live plugin callback registration panicked; acknowledging that failure also failed: {ack_source}"
    )]
    CallbackPanicFailureAck {
        /// Underlying setup acknowledgement failure.
        ack_source: PluginSetupError,
    },
    /// A non-panic failure after callback registration could not be acknowledged.
    #[error(
        "post-registration failure ({failure}); acknowledging that failure also failed: {ack_source}"
    )]
    PostRegistrationFailureAck {
        /// Original post-registration failure diagnostic.
        failure: String,
        /// Underlying setup acknowledgement failure.
        ack_source: PluginSetupError,
    },
    /// Installation panicked after callback registration had begun.
    #[error("live plugin installation panicked after callback registration at {stage}")]
    PostRegistrationPanicked {
        /// Registration stage active when the panic was caught.
        stage: &'static str,
    },
    /// A post-registration panic and its failure acknowledgement both failed.
    #[error(
        "live plugin installation panicked after callback registration at {stage}; acknowledging that failure also failed: {ack_source}"
    )]
    PostRegistrationPanicFailureAck {
        /// Registration stage active when the panic was caught.
        stage: &'static str,
        /// Underlying setup acknowledgement failure.
        ack_source: PluginSetupError,
    },
    /// Another install owns, published, or irreversibly failed the singleton slot.
    #[error("the plugin runtime singleton is unavailable: installing, active, or failed")]
    RuntimeAlreadyReserved,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;

    use crucible_protocol::{SETUP_ACK_STATUS_READY, SETUP_ACK_STATUS_SETUP_FAILED};

    mod support;
    use support::*;

    struct PanickingPostRegistrationFatalPolicy;

    struct TestFatalTermination(PluginRuntimeInstallError);

    impl PostRegistrationFatalPolicy for PanickingPostRegistrationFatalPolicy {
        fn terminate(&self, error: PluginRuntimeInstallError) -> ! {
            std::panic::panic_any(TestFatalTermination(error));
        }
    }

    struct TestPostRegistrationPanicGuard;

    impl TestPostRegistrationPanicGuard {
        fn install(stage: PostRegistrationStage) -> Self {
            TEST_POST_REGISTRATION_PANIC_STAGE.store(stage as u8, Ordering::Relaxed);
            Self
        }
    }

    impl Drop for TestPostRegistrationPanicGuard {
        fn drop(&mut self) {
            TEST_POST_REGISTRATION_PANIC_STAGE.store(u8::MAX, Ordering::Relaxed);
        }
    }

    fn install_expecting_post_registration_fatal<R>(
        plugin_id: QemuPluginId,
        fixture: &LiveInstallFixture,
        capabilities: LiveInstallCapabilities,
        callback_registrar: &R,
        reservation: &mut PluginRuntimeReservation,
    ) -> PluginRuntimeInstallError
    where
        R: OwnedCallbackRegistrar,
    {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            install_live_runtime_with_fatal_policy(
                plugin_id,
                fixture.args(),
                test_state(),
                capabilities,
                callback_registrar,
                reservation,
                &PanickingPostRegistrationFatalPolicy,
            )
        }));
        match result {
            Ok(Ok(_runtime)) => panic!("post-registration failure unexpectedly activated runtime"),
            Ok(Err(error)) => {
                panic!("post-registration failure returned to QEMU instead of terminating: {error}")
            }
            Err(payload) => match payload.downcast::<TestFatalTermination>() {
                Ok(termination) => termination.0,
                Err(payload) => std::panic::resume_unwind(payload),
            },
        }
    }

    struct SuccessfulCallbackRegistrar;

    static CALLBACK_MODEL_REGISTERED_PLUGIN_ID: AtomicU64 = AtomicU64::new(0);

    impl OwnedCallbackRegistrar for SuccessfulCallbackRegistrar {
        fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
            Ok(())
        }

        fn register(
            &self,
            args: &PluginArgs,
            _state: Pin<&mut OwnedCallbackRuntimeState>,
        ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
            Ok(OwnedCallbackRegistrationMask::required_for(args))
        }
    }

    fn coverage_callback_model_apis() -> crate::QemuBasicBlockCoverageApis {
        crate::QemuBasicBlockCoverageApis::new(
            coverage_callback_model_register_tb_trans_cb,
            coverage_callback_model_register_tb_exec_cb,
            coverage_callback_model_tb_vaddr,
            coverage_callback_model_tb_n_insns,
            coverage_callback_model_tb_get_insn,
            coverage_callback_model_insn_size,
            coverage_callback_model_icount_at_tb_entry,
            coverage_callback_model_register_flush_cb,
        )
    }

    extern "C" fn coverage_callback_model_register_tb_trans_cb(
        plugin_id: QemuPluginId,
        callback: Option<crate::QemuVcpuTbTransCbFn>,
    ) {
        assert!(callback.is_some());
        CALLBACK_MODEL_REGISTERED_PLUGIN_ID.store(plugin_id, Ordering::SeqCst);
    }

    extern "C" fn coverage_callback_model_register_tb_exec_cb(
        _tb: *mut crate::QemuPluginTb,
        _callback: Option<crate::QemuVcpuTbExecCbFn>,
        _flags: std::os::raw::c_int,
        _userdata: *mut std::os::raw::c_void,
    ) {
    }

    extern "C" fn coverage_callback_model_tb_vaddr(_tb: *const crate::QemuPluginTb) -> u64 {
        0
    }

    extern "C" fn coverage_callback_model_tb_n_insns(_tb: *const crate::QemuPluginTb) -> usize {
        0
    }

    extern "C" fn coverage_callback_model_tb_get_insn(
        _tb: *const crate::QemuPluginTb,
        _index: usize,
    ) -> *mut crate::QemuPluginInsn {
        std::ptr::null_mut()
    }

    extern "C" fn coverage_callback_model_insn_size(_insn: *const crate::QemuPluginInsn) -> usize {
        0
    }

    extern "C" fn coverage_callback_model_icount_at_tb_entry(
        _tb_insns: u64,
        entry_icount: *mut u64,
    ) -> std::os::raw::c_int {
        if entry_icount.is_null() {
            return -1;
        }
        // SAFETY: this test stub just validated the output pointer.
        unsafe { *entry_icount = 0 };
        0
    }

    extern "C" fn coverage_callback_model_register_flush_cb(
        _plugin_id: QemuPluginId,
        _callback: crate::QemuPluginSimpleCbFn,
    ) {
    }

    #[derive(Clone, Copy)]
    struct RegisteredLiveVcpuTimeCallbacks {
        publish: crate::QemuSimShmemPublishIcountCbFn,
        ceiling: crate::QemuSimShmemMaxAdvanceIcountCbFn,
        userdata: usize,
    }

    static REGISTERED_LIVE_VCPU_TIME_CALLBACKS: Mutex<Option<RegisteredLiveVcpuTimeCallbacks>> =
        Mutex::new(None);
    static LIVE_VCPU_INIT_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
    static LIVE_IDLE_RESUME_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
    static LIVE_SIM_DISPATCH_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
    static LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
    static LIVE_NETWORK_TX_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
    static LIVE_BLOCK_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
    static LIVE_NINEP_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);

    fn live_registration_counts() -> [u64; 7] {
        [
            LIVE_VCPU_INIT_REGISTRATIONS.load(Ordering::SeqCst),
            LIVE_IDLE_RESUME_REGISTRATIONS.load(Ordering::SeqCst),
            LIVE_SIM_DISPATCH_REGISTRATIONS.load(Ordering::SeqCst),
            LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS.load(Ordering::SeqCst),
            LIVE_NETWORK_TX_REGISTRATIONS.load(Ordering::SeqCst),
            LIVE_BLOCK_REGISTRATIONS.load(Ordering::SeqCst),
            LIVE_NINEP_REGISTRATIONS.load(Ordering::SeqCst),
        ]
    }

    struct LiveVcpuTimeThenTestCompletionRegistrar {
        live: LiveVcpuTimeCallbackRegistrar,
    }

    impl OwnedCallbackRegistrar for LiveVcpuTimeThenTestCompletionRegistrar {
        fn preflight(&self, args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
            self.live.preflight(args)
        }

        fn register(
            &self,
            args: &PluginArgs,
            mut state: Pin<&mut OwnedCallbackRuntimeState>,
        ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
            let vcpu = self.live.register(args, state.as_mut())?;
            assert_eq!(vcpu, OwnedCallbackRegistrationMask::base_required());
            Ok(OwnedCallbackRegistrationMask::required_for(args))
        }
    }

    extern "C" fn capture_vcpu_init_registration(
        plugin_id: QemuPluginId,
        callback: crate::QemuVcpuSimpleCbFn,
    ) {
        LIVE_VCPU_INIT_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
        callback(plugin_id, 0);
    }

    extern "C" fn capture_vcpu_idle_resume_registration(
        idle_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
        resume_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
        userdata: *mut std::ffi::c_void,
    ) {
        assert!(idle_callback.is_some());
        assert!(resume_callback.is_some());
        assert!(!userdata.is_null());
        LIVE_IDLE_RESUME_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn capture_sim_dispatch_registration(
        publish: Option<crate::QemuSimShmemPublishIcountCbFn>,
        ceiling: Option<crate::QemuSimShmemMaxAdvanceIcountCbFn>,
        userdata: *mut std::ffi::c_void,
    ) {
        let Some(publish) = publish else {
            panic!("live registrar must install the sim publish callback");
        };
        let Some(ceiling) = ceiling else {
            panic!("live registrar must install the sim ceiling callback");
        };
        LIVE_SIM_DISPATCH_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
        let mut capture = REGISTERED_LIVE_VCPU_TIME_CALLBACKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = capture.get_or_insert(RegisteredLiveVcpuTimeCallbacks {
            publish,
            ceiling,
            userdata: userdata as usize,
        });
        assert_eq!(current.userdata, userdata as usize);
        current.publish = publish;
        current.ceiling = ceiling;
    }

    extern "C" fn capture_time_advance_completion_registration(
        callback: Option<crate::QemuTimeAdvanceCompletionCbFn>,
        userdata: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int {
        assert!(callback.is_some());
        assert!(!userdata.is_null());
        LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
        0
    }

    extern "C" fn capture_network_tx_registration(
        callback: Option<crate::QemuNetTxCbFn>,
        userdata: *mut std::ffi::c_void,
    ) {
        assert!(callback.is_some());
        assert!(!userdata.is_null());
        LIVE_NETWORK_TX_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn capture_block_registration(
        submit: Option<crate::QemuBlkSubmitCbFn>,
        poll: Option<crate::QemuBlkPollCbFn>,
        userdata: *mut std::ffi::c_void,
    ) {
        assert!(submit.is_some());
        assert!(poll.is_some());
        assert!(!userdata.is_null());
        LIVE_BLOCK_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn capture_ninep_registration(
        burst_start: Option<crate::QemuNinePBurstCbFn>,
        submit: Option<crate::QemuNinePSubmitCbFn>,
        poll: Option<crate::QemuNinePPollCbFn>,
        burst_done: Option<crate::QemuNinePBurstCbFn>,
        userdata: *mut std::ffi::c_void,
    ) {
        assert!(burst_start.is_some());
        assert!(submit.is_some());
        assert!(poll.is_some());
        assert!(burst_done.is_some());
        assert!(!userdata.is_null());
        LIVE_NINEP_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn live_network_send_ok(
        _payload: *const u8,
        _payload_len: usize,
    ) -> std::os::raw::c_int {
        0
    }

    extern "C" fn live_network_flush_ok() -> std::os::raw::c_int {
        0
    }

    struct RecordingSuccessfulCallbackRegistrar {
        state_address: Cell<usize>,
        wake_fd: Cell<i32>,
    }

    impl RecordingSuccessfulCallbackRegistrar {
        const fn new() -> Self {
            Self {
                state_address: Cell::new(0),
                wake_fd: Cell::new(-1),
            }
        }
    }

    impl OwnedCallbackRegistrar for RecordingSuccessfulCallbackRegistrar {
        fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
            Ok(())
        }

        fn register(
            &self,
            args: &PluginArgs,
            mut state: Pin<&mut OwnedCallbackRuntimeState>,
        ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
            let userdata = state.as_mut().userdata();
            let state = state.as_ref().get_ref();
            self.state_address.set(userdata as usize);
            self.wake_fd.set(state.setup.wake_fd().as_raw_fd());
            Ok(OwnedCallbackRegistrationMask::required_for(args))
        }
    }

    struct LateFailingCallbackRegistrar;

    impl OwnedCallbackRegistrar for LateFailingCallbackRegistrar {
        fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
            Ok(())
        }

        fn register(
            &self,
            _args: &PluginArgs,
            _state: Pin<&mut OwnedCallbackRuntimeState>,
        ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
            Err(OwnedCallbackRegistrationError::AdaptersUnavailable {
                families: REQUIRED_OWNED_CALLBACK_FAMILIES,
            })
        }
    }

    struct PartiallyFailingCallbackRegistrar {
        state_address: Cell<usize>,
        wake_fd: Cell<i32>,
    }

    impl PartiallyFailingCallbackRegistrar {
        const fn new() -> Self {
            Self {
                state_address: Cell::new(0),
                wake_fd: Cell::new(-1),
            }
        }
    }

    impl OwnedCallbackRegistrar for PartiallyFailingCallbackRegistrar {
        fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
            Ok(())
        }

        fn register(
            &self,
            _args: &PluginArgs,
            mut state: Pin<&mut OwnedCallbackRuntimeState>,
        ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
            let userdata = state.as_mut().userdata();
            let state = state.as_ref().get_ref();
            self.state_address.set(userdata as usize);
            assert_eq!(userdata.cast_const(), std::ptr::from_ref(state).cast());
            self.wake_fd.set(state.setup.wake_fd().as_raw_fd());
            Err(OwnedCallbackRegistrationError::AdaptersUnavailable {
                families: REQUIRED_OWNED_CALLBACK_FAMILIES,
            })
        }
    }

    struct PartiallyPanickingCallbackRegistrar {
        state_address: Cell<usize>,
        wake_fd: Cell<i32>,
    }

    impl PartiallyPanickingCallbackRegistrar {
        const fn new() -> Self {
            Self {
                state_address: Cell::new(0),
                wake_fd: Cell::new(-1),
            }
        }
    }

    impl OwnedCallbackRegistrar for PartiallyPanickingCallbackRegistrar {
        fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
            Ok(())
        }

        fn register(
            &self,
            _args: &PluginArgs,
            mut state: Pin<&mut OwnedCallbackRuntimeState>,
        ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
            let userdata = state.as_mut().userdata();
            let state = state.as_ref().get_ref();
            self.state_address.set(userdata as usize);
            self.wake_fd.set(state.setup.wake_fd().as_raw_fd());
            panic!("injected panic after partial callback registration")
        }
    }

    #[test]
    fn live_install_retains_active_state_only_after_complete_ordered_sequence() {
        let _runtime_state = isolate_runtime_state_for_test();
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
        let runtime = install_live_runtime(
            41,
            fixture.args(),
            test_state(),
            test_capabilities(),
            &SuccessfulCallbackRegistrar,
            &mut reservation,
        )
        .unwrap_or_else(|error| panic!("live install should complete: {error}"));

        assert_eq!(runtime.plugin_id(), 41);
        assert_eq!(runtime.args().slot(), 0);
        assert_eq!(runtime.lifecycle_phase(), PluginLifecyclePhase::Active);
        let callback_state_address = runtime._callbacks.state_address_for_test();
        let runtime = (runtime,);
        assert_eq!(
            runtime.0._callbacks.state_address_for_test(),
            callback_state_address
        );
        assert_eq!(
            runtime.0._callbacks.registration_mask().bits(),
            OwnedCallbackRegistrationMask::BASE_REQUIRED
        );
        reservation.publish(runtime.0);
        assert!(active_runtime_is_published());
        join_host(host);
    }

    #[test]
    fn install_coverage_on_owns_callback_model_registration() {
        let _runtime_state = isolate_runtime_state_for_test();
        let _callback_model_guard = isolate_coverage_callback_model_for_test();
        CALLBACK_MODEL_REGISTERED_PLUGIN_ID.store(0, Ordering::SeqCst);
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
        let mut capabilities = test_capabilities();
        capabilities.basic_block_coverage = Some(coverage_callback_model_apis());
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

        let runtime = install_live_runtime(
            0xC0E0,
            fixture.coverage_args(),
            test_state(),
            capabilities,
            &SuccessfulCallbackRegistrar,
            &mut reservation,
        )
        .unwrap_or_else(|error| panic!("coverage callback model should install: {error}"));

        assert_eq!(
            CALLBACK_MODEL_REGISTERED_PLUGIN_ID.load(Ordering::SeqCst),
            0xC0E0
        );
        assert!(runtime._callbacks.coverage_is_registered_for_test());
        drop(runtime);
        join_host(host);
    }

    #[test]
    fn live_vcpu_time_slice_registers_idle_resume_and_normal_loop_completion() {
        let _runtime_state = isolate_runtime_state_for_test();
        *REGISTERED_LIVE_VCPU_TIME_CALLBACKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        LIVE_IDLE_RESUME_REGISTRATIONS.store(0, Ordering::SeqCst);
        LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS.store(0, Ordering::SeqCst);
        LIVE_NETWORK_TX_REGISTRATIONS.store(0, Ordering::SeqCst);
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
        let execution_model = crate::QemuPluginExecutionModel::validate(
            1,
            crate::QemuTcgThreading::SingleThreadedRoundRobin,
        )
        .unwrap_or_else(|error| panic!("test execution model should validate: {error}"));
        let state = test_state();
        let registrar = LiveVcpuTimeThenTestCompletionRegistrar {
            live: LiveVcpuTimeCallbackRegistrar::new(
                51,
                execution_model,
                LiveVcpuTimeCallbackCapabilities {
                    icount_raw: test_icount_raw,
                    clock_deadline_ns: Some(test_deadline),
                    advance_time_ns: Some(test_direct_advance),
                    register_vcpu_init: Some(capture_vcpu_init_registration),
                    register_vcpu_idle_resume: Some(capture_vcpu_idle_resume_registration),
                    register_sim_shmem_dispatch: Some(capture_sim_dispatch_registration),
                    register_time_advance_cb: Some(capture_time_advance_completion_registration),
                    register_net_tx: Some(capture_network_tx_registration),
                    net_send: Some(live_network_send_ok),
                    net_flush: Some(live_network_flush_ok),
                    register_block: Some(capture_block_registration),
                    register_ninep: Some(capture_ninep_registration),
                },
            ),
        };
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
        let runtime = install_live_runtime(
            51,
            fixture.args(),
            state,
            test_capabilities(),
            &registrar,
            &mut reservation,
        )
        .unwrap_or_else(|error| panic!("live callback slice should install: {error}"));

        let callbacks = REGISTERED_LIVE_VCPU_TIME_CALLBACKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .unwrap_or_else(|| panic!("live callback registrations should be captured"));
        let userdata = callbacks.userdata as *mut std::ffi::c_void;
        assert_ne!(callbacks.userdata, 0);
        assert_eq!((callbacks.ceiling)(userdata), 1);
        (callbacks.publish)(1, userdata);
        assert_eq!(LIVE_IDLE_RESUME_REGISTRATIONS.load(Ordering::SeqCst), 1);
        assert_eq!(
            LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS.load(Ordering::SeqCst),
            1
        );
        assert_eq!(LIVE_NETWORK_TX_REGISTRATIONS.load(Ordering::SeqCst), 1);
        assert_eq!(
            runtime._callbacks.registration_mask(),
            OwnedCallbackRegistrationMask::required_for(&fixture.args())
        );

        drop(runtime);
        join_host(host);
    }

    #[test]
    fn late_callback_failure_sends_nonzero_setup_ack_then_invokes_fatal_policy() {
        let _runtime_state = isolate_runtime_state_for_test();
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
        let error = install_expecting_post_registration_fatal(
            42,
            &fixture,
            test_capabilities(),
            &LateFailingCallbackRegistrar,
            &mut reservation,
        );

        assert!(matches!(
            error,
            PluginRuntimeInstallError::OwnedCallbacks { .. }
        ));
        join_host(host);
    }

    #[test]
    fn partial_callback_failure_retains_the_pinned_userdata_owner() {
        let _runtime_state = isolate_runtime_state_for_test();
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
        let registrar = PartiallyFailingCallbackRegistrar::new();
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
        let error = install_expecting_post_registration_fatal(
            44,
            &fixture,
            test_capabilities(),
            &registrar,
            &mut reservation,
        );

        assert!(matches!(
            error,
            PluginRuntimeInstallError::OwnedCallbacks { .. }
        ));
        assert_ne!(registrar.state_address.get(), 0);
        // SAFETY: `F_GETFD` only observes whether the registrar-recorded
        // descriptor remains owned by the intentionally leaked pinned state.
        assert!(unsafe { libc::fcntl(registrar.wake_fd.get(), libc::F_GETFD) } >= 0);
        join_host(host);
    }

    #[test]
    fn partial_callback_panic_retains_userdata_and_sends_one_failure_ack() {
        let _runtime_state = isolate_runtime_state_for_test();
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
        let registrar = PartiallyPanickingCallbackRegistrar::new();
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
        let error = install_expecting_post_registration_fatal(
            45,
            &fixture,
            test_capabilities(),
            &registrar,
            &mut reservation,
        );

        assert!(matches!(
            error,
            PluginRuntimeInstallError::CallbackRegistrationPanicked
        ));
        assert_ne!(registrar.state_address.get(), 0);
        // SAFETY: `F_GETFD` observes that the panic path retained the pinned
        // owner before invoking the fatal policy.
        assert!(unsafe { libc::fcntl(registrar.wake_fd.get(), libc::F_GETFD) } >= 0);
        join_host(host);
    }

    #[test]
    fn callback_capability_failure_is_fatal_after_registration_begins() {
        let _runtime_state = isolate_runtime_state_for_test();
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
        let mut capabilities = test_capabilities();
        capabilities.clock_deadline_ns = None;
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

        let error = install_expecting_post_registration_fatal(
            46,
            &fixture,
            capabilities,
            &SuccessfulCallbackRegistrar,
            &mut reservation,
        );

        assert!(matches!(
            error,
            PluginRuntimeInstallError::Registration { .. }
        ));
        join_host(host);
    }

    #[test]
    fn finalize_panic_is_fatal_without_dropping_userdata_or_sending_a_second_ack() {
        let _runtime_state = isolate_runtime_state_for_test();
        let _panic_stage = TestPostRegistrationPanicGuard::install(PostRegistrationStage::Finalize);
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
        let registrar = RecordingSuccessfulCallbackRegistrar::new();
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

        let error = install_expecting_post_registration_fatal(
            47,
            &fixture,
            test_capabilities(),
            &registrar,
            &mut reservation,
        );

        assert!(matches!(
            error,
            PluginRuntimeInstallError::PostRegistrationPanicked { stage: "Finalize" }
        ));
        assert_ne!(registrar.state_address.get(), 0);
        // SAFETY: `F_GETFD` observes that the whole post-registration unwind
        // scope retained the pinned owner before invoking the fatal policy.
        assert!(unsafe { libc::fcntl(registrar.wake_fd.get(), libc::F_GETFD) } >= 0);
        join_host(host);
    }

    #[test]
    fn enabled_whitebox_without_live_abi_fails_before_control_or_qemu_side_effects() {
        let _runtime_state = isolate_runtime_state_for_test();
        reset_capability_call_counts();
        let registrations_before = live_registration_counts();
        let fixture = LiveInstallFixture::new();
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
        let state = test_state();
        let capabilities = test_capabilities();
        let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
            43,
            state.lifecycle_core().execution_model(),
            &capabilities,
        );
        let error = install_live_runtime(
            43,
            fixture.whitebox_args(),
            state,
            capabilities,
            &callback_registrar,
            &mut reservation,
        )
        .err()
        .unwrap_or_else(|| panic!("missing white-box ABI must fail preflight"));

        assert!(matches!(
            error,
            PluginRuntimeInstallError::OwnedCallbacks {
                source: OwnedCallbackRegistrationError::LiveVcpuTime {
                    source: LiveVcpuTimeCallbackError::WhiteboxCallbackAbiUnavailable { .. },
                },
            }
        ));
        fixture.assert_control_silent();
        assert_eq!(live_registration_counts(), registrations_before);
        assert_eq!(time_control_request_count(), 0);
        assert_eq!(wake_registration_count(), 0);
        drop(reservation);
        assert!(reserve_runtime().is_ok());
    }

    #[test]
    fn production_registrar_installs_default_block_ninep_and_network_families() {
        let _runtime_state = isolate_runtime_state_for_test();
        *REGISTERED_LIVE_VCPU_TIME_CALLBACKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        let registrations_before = live_registration_counts();
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
        let state = test_state();
        let mut capabilities = test_capabilities();
        capabilities.register_vcpu_init = Some(capture_vcpu_init_registration);
        capabilities.register_vcpu_idle_resume = Some(capture_vcpu_idle_resume_registration);
        capabilities.register_sim_shmem_dispatch = Some(capture_sim_dispatch_registration);
        capabilities.register_time_advance_cb = Some(capture_time_advance_completion_registration);
        capabilities.register_net_tx = Some(capture_network_tx_registration);
        capabilities.net_send = Some(live_network_send_ok);
        capabilities.net_flush = Some(live_network_flush_ok);
        capabilities.register_block = Some(capture_block_registration);
        capabilities.register_ninep = Some(capture_ninep_registration);
        let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
            54,
            state.lifecycle_core().execution_model(),
            &capabilities,
        );
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

        let runtime = install_live_runtime(
            54,
            fixture.args(),
            state,
            capabilities,
            &callback_registrar,
            &mut reservation,
        )
        .unwrap_or_else(|error| panic!("default production callbacks should install: {error}"));

        assert_eq!(
            runtime._callbacks.registration_mask(),
            OwnedCallbackRegistrationMask::base_required()
        );
        let registrations_after = live_registration_counts();
        for (before, after) in registrations_before.into_iter().zip(registrations_after) {
            assert_eq!(after, before + 1);
        }
        drop(runtime);
        join_host(host);
    }

    #[test]
    fn missing_live_vcpu_time_capability_fails_preflight_before_control_io() {
        let _runtime_state = isolate_runtime_state_for_test();
        reset_capability_call_counts();
        let fixture = LiveInstallFixture::new();
        let state = test_state();
        let mut capabilities = test_capabilities();
        capabilities.register_sim_shmem_dispatch = None;
        let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
            52,
            state.lifecycle_core().execution_model(),
            &capabilities,
        );
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

        let error = install_live_runtime(
            52,
            fixture.args(),
            state,
            capabilities,
            &callback_registrar,
            &mut reservation,
        )
        .err()
        .unwrap_or_else(|| panic!("missing live callback capability must fail preflight"));

        assert!(matches!(
            error,
            PluginRuntimeInstallError::OwnedCallbacks {
                source: OwnedCallbackRegistrationError::LiveVcpuTime {
                    source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                        symbol: crate::QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL,
                    },
                },
            }
        ));
        fixture.assert_control_silent();
        assert_eq!(time_control_request_count(), 0);
        assert_eq!(wake_registration_count(), 0);
    }

    #[test]
    fn missing_live_network_capability_fails_preflight_before_control_io() {
        let _runtime_state = isolate_runtime_state_for_test();
        reset_capability_call_counts();
        let fixture = LiveInstallFixture::new();
        let state = test_state();
        let mut capabilities = test_capabilities();
        capabilities.net_send = None;
        let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
            53,
            state.lifecycle_core().execution_model(),
            &capabilities,
        );
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

        let error = install_live_runtime(
            53,
            fixture.args(),
            state,
            capabilities,
            &callback_registrar,
            &mut reservation,
        )
        .err()
        .unwrap_or_else(|| panic!("missing live network capability must fail preflight"));

        assert!(matches!(
            error,
            PluginRuntimeInstallError::OwnedCallbacks {
                source: OwnedCallbackRegistrationError::LiveVcpuTime {
                    source: LiveVcpuTimeCallbackError::NetworkRx {
                        source: crate::NetworkRxError::CapabilityUnavailable {
                            symbol: crate::QEMU_PLUGIN_NET_SEND_SYMBOL,
                        },
                    },
                },
            }
        ));
        fixture.assert_control_silent();
        assert_eq!(time_control_request_count(), 0);
        assert_eq!(wake_registration_count(), 0);
    }

    #[test]
    fn missing_live_ninep_capability_prevents_every_qemu_registration() {
        let _runtime_state = isolate_runtime_state_for_test();
        reset_capability_call_counts();
        let registrations_before = live_registration_counts();
        let fixture = LiveInstallFixture::new();
        let state = test_state();
        let mut capabilities = test_capabilities();
        capabilities.register_ninep = None;
        let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
            55,
            state.lifecycle_core().execution_model(),
            &capabilities,
        );
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

        let error = install_live_runtime(
            55,
            fixture.args(),
            state,
            capabilities,
            &callback_registrar,
            &mut reservation,
        )
        .err()
        .unwrap_or_else(|| panic!("missing live 9p capability must fail preflight"));

        assert!(matches!(
            error,
            PluginRuntimeInstallError::OwnedCallbacks {
                source: OwnedCallbackRegistrationError::LiveVcpuTime {
                    source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                        symbol: crate::QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL,
                    },
                },
            }
        ));
        fixture.assert_control_silent();
        assert_eq!(live_registration_counts(), registrations_before);
        assert_eq!(time_control_request_count(), 0);
        assert_eq!(wake_registration_count(), 0);
    }

    #[test]
    fn handshake_failure_marks_the_singleton_failed_before_second_install_attempt() {
        let _runtime_state = isolate_runtime_state_for_test();
        let fixture = LiveInstallFixture::new();
        let host = fixture.spawn_mismatched_handshake_host();
        let mut reservation = reserve_runtime()
            .unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

        let error = install_live_runtime(
            48,
            fixture.args(),
            test_state(),
            test_capabilities(),
            &SuccessfulCallbackRegistrar,
            &mut reservation,
        )
        .err()
        .unwrap_or_else(|| panic!("mismatched handshake must fail install"));

        assert!(matches!(
            error,
            PluginRuntimeInstallError::Registration { .. }
        ));
        drop(reservation);
        assert_eq!(RUNTIME_STATE.load(Ordering::Acquire), RUNTIME_FAILED);
        assert!(matches!(
            reserve_runtime(),
            Err(PluginRuntimeInstallError::RuntimeAlreadyReserved)
        ));
        join_host(host);
    }

    #[test]
    fn duplicate_reservation_fails_before_protocol_io_can_begin() {
        let _runtime_state = isolate_runtime_state_for_test();
        let _first = reserve_runtime()
            .unwrap_or_else(|error| panic!("first runtime should reserve: {error}"));

        assert!(matches!(
            reserve_runtime(),
            Err(PluginRuntimeInstallError::RuntimeAlreadyReserved)
        ));
    }

    #[test]
    fn irreversible_reservation_failure_blocks_second_install_attempt() {
        let _runtime_state = isolate_runtime_state_for_test();
        {
            let mut reservation =
                reserve_runtime().unwrap_or_else(|error| panic!("runtime should reserve: {error}"));
            reservation.mark_irreversible();
        }

        assert_eq!(RUNTIME_STATE.load(Ordering::Acquire), RUNTIME_FAILED);
        assert!(matches!(
            reserve_runtime(),
            Err(PluginRuntimeInstallError::RuntimeAlreadyReserved)
        ));
    }
}
