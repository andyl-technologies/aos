//! Live QEMU plugin installation and process-lifetime runtime ownership.
//!
//! This module joins the existing typed registration stages without weakening
//! their fail-stop boundaries. The active owner is published only after the
//! complete required callback set is registered, `SetupAck(0)` is sent, and the
//! mapped boot barrier releases. Production preflight validates every callback
//! required by the selected launch mode before the control handshake or any
//! QEMU callback registration; optional white-box mode remains closed until its
//! concrete trap and guest-memory callback ABI is available.

pub(crate) mod callback_quiescence;
mod live_callbacks;
mod live_whitebox;
mod worker_quiescence;

use callback_quiescence::LiveCallbackQuiescence;
use worker_quiescence::{
    LiveWorkerQuiescence, WORKER_FINGERPRINT, WORKER_REQUIRED, WORKER_RUN_CONTROL, WORKER_TEARDOWN,
};

#[cfg(test)]
use live_callbacks::clear_live_vcpu_time_state_for_test;
pub use live_callbacks::{LiveDeviceCallbackError, LiveVcpuTimeCallbackError};
use live_callbacks::{LiveVcpuTimeCallbackCapabilities, LiveVcpuTimeCallbackRegistrar};

#[cfg(unix)]
use std::io::{self, Write as _};
use std::marker::PhantomPinned;
#[cfg(unix)]
use std::net::Shutdown;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, mpsc};

use thiserror::Error;

#[cfg(unix)]
use crucible_protocol::ControlLifecycleStream;
#[cfg(unix)]
use crucible_shmem::{NodeSlot, RegionHeader};

use crate::coverage::{LiveBasicBlockCoverage, LiveCoverageShmemProducer};
#[cfg(unix)]
use crate::setup::signal_teardown_wake_fd;
use crate::{
    BootBarrierRelease, CoverageCapabilities, CoverageError, PluginArgs, PluginLifecyclePhase,
    PluginRegistrationReady, PluginRegistrationSequence, PluginRegistrationSequenceError,
    PluginRegistrationStep, PluginSetupCompletion, PluginSetupError, PluginStatePartition,
    PluginTimeControlOwnership, QemuAdvanceTimeNsFn, QemuBasicBlockCoverageApis,
    QemuClockDeadlineFn, QemuPluginId, QemuRegisterWakeFdFn, QemuRequestShutdownFn,
    QemuRequestTimeControlFn, send_callback_registration_failure_ack,
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

/// Heap-stable state addressed by future QEMU callback userdata pointers.
///
/// The setup mapping and wake descriptor move into this allocation before any
/// owned callback may be registered. The allocation remains pinned while the
/// proof is live, so moving the proof never moves callback-addressable state.
pub(crate) struct OwnedCallbackRuntimeState {
    quiescence: Arc<LiveCallbackQuiescence>,
    workers: Arc<LiveWorkerQuiescence>,
    teardown_sender: mpsc::Sender<LiveRuntimeTeardownTrigger>,
    live_vcpu_time: Option<Pin<Box<live_callbacks::LiveVcpuTimeCallbackState>>>,
    live_whitebox: Option<Pin<Box<live_whitebox::LiveWhiteboxState>>>,
    setup: PluginSetupCompletion,
    coverage: Option<LiveBasicBlockCoverage>,
    #[cfg(test)]
    allow_missing_fault_command_state: bool,
    _pin: PhantomPinned,
}

impl OwnedCallbackRuntimeState {
    fn pin(
        worker_mask: u64,
        setup: PluginSetupCompletion,
        teardown_sender: mpsc::Sender<LiveRuntimeTeardownTrigger>,
    ) -> Pin<Box<Self>> {
        Box::pin(Self {
            quiescence: Arc::new(LiveCallbackQuiescence::new()),
            workers: LiveWorkerQuiescence::new(worker_mask),
            teardown_sender,
            live_vcpu_time: None,
            live_whitebox: None,
            setup,
            coverage: None,
            #[cfg(test)]
            allow_missing_fault_command_state: false,
            _pin: PhantomPinned,
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
        fault_node_hash: [u8; 32],
        icount_raw: crate::QemuIcountRawFn,
        force_vcpu_exit: crate::QemuForceVcpuExitFn,
        request_vmstop: crate::QemuRequestVmstopFn,
        preemption_injector: crate::PluginPreemptionInjector,
        initial_raw_icount: u64,
        exact_deadline: crate::ExactDeadlineReader,
        queued_idle_advance: crate::QueuedIdleAdvance,
        network_rx: crate::QemuCanonicalNetworkRx,
        network_tx_next_seq: u32,
        storage_history_limits: crate::PluginStorageHistoryLimits,
        process_generation: u64,
        fault_command_apis: crate::fault_command::QemuFaultCommandApis,
        fingerprint: Option<crate::PluginFingerprintSampling>,
        fingerprint_oracle: bool,
        state_dump: Option<crate::PluginRawStateDump>,
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
        let fault_commands = crate::fault_command::FaultCommandBridge::new(
            fault_command_apis,
            fault_node_hash,
            state.setup.mapped_region_mut(),
            slot_index,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?;
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
            force_vcpu_exit,
            request_vmstop,
            preemption_injector,
            vcpu_count,
            icount_shift,
            initial_raw_icount,
            exact_deadline,
            queued_idle_advance,
            #[cfg(not(test))]
            fault_commands,
            #[cfg(test)]
            Some(fault_commands),
            header,
            mapped.node_slot,
            Arc::clone(&state.quiescence),
            state.teardown_sender.clone(),
        )?
        .attach_network(
            slot_index,
            mapped.first,
            mapped.second,
            network_rx,
            network_tx_next_seq,
        )?;
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
        let accelerator_rings = state
            .setup
            .mapped_region_mut()
            .plugin_accelerator_rings_mut(slot_index)
            .map_err(|source| LiveVcpuTimeCallbackError::MappedNodeSlot { source })?;
        // SAFETY: the pinned runtime retains this unique plugin role and its
        // owning mapping for every QEMU callback.
        let accelerator_rings = unsafe { accelerator_rings.detach_for_mapping_lifetime() };
        let callback_state = callback_state.attach_devices_with_history_limits(
            slot_index,
            block_rings,
            ninep_rings,
            storage_history_limits,
            process_generation,
            accelerator_rings,
        )?;
        let callback_state = match fingerprint {
            Some(sampling) => {
                let slot = state
                    .setup
                    .mapped_region()
                    .fingerprint_sample(slot_index)
                    .map_err(|source| LiveVcpuTimeCallbackError::MappedFingerprintSlot {
                        source,
                    })?;
                callback_state.attach_fingerprint(
                    sampling,
                    slot,
                    fingerprint_oracle,
                    Arc::clone(&state.workers),
                )?
            }
            None => callback_state,
        };
        let callback_state = match state_dump {
            Some(state_dump) => callback_state.attach_state_dump(state_dump),
            None => callback_state,
        };
        let callback_state = Box::pin(callback_state);
        let callback_pointer = std::ptr::from_ref(callback_state.as_ref().get_ref()).cast_mut();
        state.live_vcpu_time = Some(callback_state);
        Ok(callback_pointer)
    }

    fn prepare_live_whitebox_state(
        self: Pin<&mut Self>,
        apis: live_whitebox::LiveWhiteboxApis,
        args: &crate::PluginArgs,
        target_architecture: crate::abi::QemuPluginTargetArchitecture,
        vcpu_count: u32,
        request_shutdown: QemuRequestShutdownFn,
        force_vcpu_exit: crate::QemuForceVcpuExitFn,
    ) -> Result<&mut live_whitebox::LiveWhiteboxState, live_whitebox::LiveWhiteboxError> {
        // SAFETY: assigning an independently heap-owned callback runtime does
        // not move the pinned parent or its setup mapping.
        let state = unsafe { self.get_unchecked_mut() };
        let live_vcpu_time = state.live_vcpu_time.as_ref().ok_or_else(|| {
            live_whitebox::LiveWhiteboxError::RegistrationPlan {
                message: "live selectable handoff requires installed vCPU callback state"
                    .to_owned(),
            }
        })?;
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
                force_vcpu_exit,
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
        state.coverage = Some(LiveBasicBlockCoverage::register(
            plugin_id,
            callback,
            apis,
            output,
            Arc::clone(&state.quiescence),
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
    #[cfg(test)]
    _teardown_receiver: Option<mpsc::Receiver<LiveRuntimeTeardownTrigger>>,
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
            OwnedCallbackRuntimeState::pin(plugin_worker_mask(args), setup, teardown_sender),
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

    #[cfg(unix)]
    fn control_teardown_handle(
        &self,
        slot_index: u32,
    ) -> Result<LiveControlTeardownHandle, PluginRuntimeInstallError> {
        let state = self.state.as_ref().get_ref();
        let slot = state
            .setup
            .mapped_region()
            .node_slot(slot_index)
            .map_err(|source| PluginRuntimeInstallError::TeardownSlot { source })?;
        Ok(LiveControlTeardownHandle {
            quiescence: Arc::clone(&state.quiescence),
            header_address: std::ptr::from_ref(state.setup.mapped_region().header()) as usize,
            slot_address: std::ptr::from_ref(slot) as usize,
            wake_fd: state.setup.wake_fd().as_raw_fd(),
        })
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
}

#[cfg(unix)]
fn read_run_control_trigger(
    mut control: ControlLifecycleStream<UnixStream>,
) -> LiveRuntimeTeardownTrigger {
    match PluginHostQuit::read_from_run_control(&mut control) {
        Ok(host_quit) => LiveRuntimeTeardownTrigger::HostQuit(host_quit),
        Err(error) => LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: error.to_string(),
        },
    }
}

#[cfg(unix)]
fn run_control_reader(
    control: ControlLifecycleStream<UnixStream>,
    teardown_sender: mpsc::Sender<LiveRuntimeTeardownTrigger>,
    workers: Arc<LiveWorkerQuiescence>,
) -> bool {
    let idle = workers.idle(WORKER_RUN_CONTROL);
    let trigger = read_run_control_trigger(control);
    let pending = idle.received();
    let _operation = pending.enter();
    // A send failure means the sole teardown worker already selected another
    // concurrently delivered proof and returned. No second shutdown may run.
    teardown_sender.send(trigger).is_ok()
}

#[cfg(unix)]
fn run_teardown_worker(
    teardown_receiver: mpsc::Receiver<LiveRuntimeTeardownTrigger>,
    teardown_handle: LiveControlTeardownHandle,
    request_shutdown: QemuRequestShutdownFn,
    workers: Arc<LiveWorkerQuiescence>,
) {
    let idle = workers.idle(WORKER_TEARDOWN);
    let trigger = match teardown_receiver.recv() {
        Ok(trigger) => trigger,
        Err(error) => {
            emit_control_worker_diagnostic(&format!(
                "all teardown signalers disconnected before selecting a trigger: {error}"
            ));
            std::process::abort();
        }
    };
    let pending = idle.received();
    let _operation = pending.enter();
    complete_live_teardown(trigger, teardown_handle, request_shutdown);
}

#[cfg(unix)]
fn complete_live_teardown(
    trigger: LiveRuntimeTeardownTrigger,
    teardown_handle: LiveControlTeardownHandle,
    request_shutdown: QemuRequestShutdownFn,
) {
    let slot = teardown_handle.quiesce();
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
            teardown.teardown_after_host_quit(host_quit, slot, &mut shutdown)
        }
        LiveRuntimeTeardownTrigger::SharedShutdown(shutdown_requested) => {
            teardown.teardown_after_shutdown_requested(shutdown_requested, slot, &mut shutdown)
        }
        LiveRuntimeTeardownTrigger::RunControlFault { .. } => {
            teardown.teardown_after_run_control_fault(slot, &mut shutdown)
        }
    };
    if let Err(error) = result {
        emit_control_worker_diagnostic(&format!("control teardown failed: {error}"));
        std::process::abort();
    }
}

#[cfg(all(unix, test))]
fn run_control_worker(
    control: ControlLifecycleStream<UnixStream>,
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

#[cfg(all(unix, not(test)))]
fn run_runtime_thread_fail_loud<F>(role: &'static str, task: F)
where
    F: FnOnce(),
{
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)).is_err() {
        emit_control_worker_diagnostic(&format!("{role} panicked; aborting QEMU process"));
        std::process::abort();
    }
}

/// QEMU functions needed by the live registration sequence.
#[derive(Clone, Copy)]
pub(crate) struct LiveInstallCapabilities {
    pub(crate) icount_raw: crate::QemuIcountRawFn,
    pub(crate) force_vcpu_exit: crate::QemuForceVcpuExitFn,
    pub(crate) request_vmstop: crate::QemuRequestVmstopFn,
    pub(crate) inject_preemption: Option<crate::QemuInjectPreemptionFn>,
    pub(crate) request_time_control: Option<QemuRequestTimeControlFn>,
    pub(crate) clock_deadline_ns: Option<QemuClockDeadlineFn>,
    pub(crate) advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    pub(crate) register_time_advance_cb: Option<crate::QemuRegisterTimeAdvanceCbFn>,
    pub(crate) register_wake_fd: QemuRegisterWakeFdFn,
    pub(crate) register_resource_manifest: crate::QemuRegisterResourceManifestFn,
    pub(crate) register_hot_fork_barrier: crate::QemuRegisterHotForkBarrierFn,
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

const PLUGIN_RESOURCE_MANIFEST_VERSION: u32 = 2;
const PLUGIN_RESOURCE_REQUIRED: u64 = (1_u64 << 10) - 1;
const PLUGIN_RESOURCE_COVERAGE: u64 = 1_u64 << 10;
const PLUGIN_RESOURCE_WHITEBOX: u64 = 1_u64 << 11;
const PLUGIN_RESOURCE_FINGERPRINT: u64 = 1_u64 << 12;
const PLUGIN_RESOURCE_STATE_DUMP: u64 = 1_u64 << 13;
const PLUGIN_RESOURCE_APP_RANDOM: u64 = 1_u64 << 14;
const PLUGIN_CALLBACK_REQUIRED: u64 = ((1_u64 << 12) - 1) & !(1_u64 << 1);
const PLUGIN_CALLBACK_TB_TRANSLATION: u64 = 1_u64 << 12;
const PLUGIN_CALLBACK_FLUSH: u64 = 1_u64 << 13;
fn plugin_worker_mask(args: &PluginArgs) -> u64 {
    WORKER_REQUIRED | (u64::from(args.fingerprint().is_on()) * WORKER_FINGERPRINT)
}

fn plugin_resource_manifest(
    plugin_id: QemuPluginId,
    args: &PluginArgs,
    callbacks: &RequiredOwnedCallbacksRegistered,
) -> Result<crate::QemuPluginResourceManifest, PluginRuntimeInstallError> {
    let setup = callbacks.setup();
    let node_count = setup.mapped_region().header_snapshot().node_count;
    let wake_fd = setup
        .registered_wake_fd()
        .ok_or(PluginRuntimeInstallError::ResourceManifestShape)?
        .as_raw_fd();
    let struct_size = u32::try_from(std::mem::size_of::<crate::QemuPluginResourceManifest>())
        .map_err(|_error| PluginRuntimeInstallError::ResourceManifestShape)?;

    let mut resource_mask = PLUGIN_RESOURCE_REQUIRED;
    let mut callback_mask = PLUGIN_CALLBACK_REQUIRED;
    let worker_mask = callbacks.state.as_ref().get_ref().workers.worker_mask();
    if args.coverage().is_on() {
        resource_mask |= PLUGIN_RESOURCE_COVERAGE;
        callback_mask |= PLUGIN_CALLBACK_TB_TRANSLATION | PLUGIN_CALLBACK_FLUSH;
    }
    if args.whitebox().is_on() {
        resource_mask |= PLUGIN_RESOURCE_WHITEBOX;
        callback_mask |= PLUGIN_CALLBACK_TB_TRANSLATION;
    }
    if args.fingerprint().is_on() {
        resource_mask |= PLUGIN_RESOURCE_FINGERPRINT;
    }
    if args.state_dump().is_some() {
        resource_mask |= PLUGIN_RESOURCE_STATE_DUMP;
    }
    if args.app_random().is_some() {
        resource_mask |= PLUGIN_RESOURCE_APP_RANDOM;
    }

    Ok(crate::QemuPluginResourceManifest {
        schema_version: PLUGIN_RESOURCE_MANIFEST_VERSION,
        struct_size,
        process_generation: args.process_generation(),
        plugin_id,
        resource_mask,
        callback_mask,
        worker_mask,
        shmem_device: setup.shared_memory_device(),
        shmem_inode: setup.shared_memory_inode(),
        shmem_length: setup.mapped_region().region_len(),
        slot_index: args.slot(),
        node_count,
        control_fd: args.sim_fd(),
        wake_fd,
    })
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
    AdmitFaultCapabilities,
    RegisterHotForkBarrier,
    SealResourceManifest,
    SendReadyAck,
    WaitBootBarrier,
    Finalize,
}

extern "C" fn crucible_qemu_plugin_hot_fork_barrier(
    action: u32,
    status: *mut crate::QemuPluginHotForkBarrierStatus,
    userdata: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
    if status.is_null() || userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: registration passes the stable pinned runtime-owner address, and
    // production retains that allocation for the QEMU process lifetime.
    let state = unsafe { &*userdata.cast::<OwnedCallbackRuntimeState>() };
    let (snapshot, rings, workers) = match action {
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_HOLD => {
            let snapshot = state.quiescence.hold_hot_fork();
            let Ok(rings) = state.setup.mapped_region().hold_hot_fork_ring_io() else {
                return -libc::EPROTO;
            };
            let workers = state.workers.hold();
            (snapshot, rings, workers)
        }
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY => {
            let snapshot = state.quiescence.snapshot();
            let Ok(rings) = state.setup.mapped_region().hot_fork_ring_io_snapshot() else {
                return -libc::EPROTO;
            };
            let workers = state.workers.snapshot();
            (snapshot, rings, workers)
        }
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_RELEASE => {
            let Ok(rings) = state.setup.mapped_region().release_hot_fork_ring_io() else {
                return -libc::EPROTO;
            };
            let snapshot = state.quiescence.release_hot_fork();
            let workers = state.workers.release();
            (snapshot, rings, workers)
        }
        _ => return -libc::EINVAL,
    };
    if snapshot.hot_fork_held != workers.held {
        return -libc::EPROTO;
    }
    let Ok(struct_size) =
        u32::try_from(std::mem::size_of::<crate::QemuPluginHotForkBarrierStatus>())
    else {
        return -libc::EOVERFLOW;
    };
    let flags = (u32::from(snapshot.hot_fork_held) * crate::QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_HELD)
        | (u32::from(snapshot.teardown_closed) * crate::QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_TEARDOWN);
    // SAFETY: the caller supplied a non-null out pointer for this synchronous
    // callback. The fixed C/Rust ABI layouts are checked by QEMU before use.
    unsafe {
        status.write(crate::QemuPluginHotForkBarrierStatus {
            schema_version: crate::QEMU_PLUGIN_HOT_FORK_BARRIER_STATUS_VERSION,
            struct_size,
            flags,
            reserved: 0,
            in_flight: snapshot.in_flight,
            ring_count: rings.ring_count(),
            rings_held: rings.held_rings(),
            ring_producers_in_flight: rings.producers_in_flight(),
            ring_consumers_in_flight: rings.consumers_in_flight(),
            worker_mask: workers.worker_mask,
            parked_worker_mask: workers.parked_mask,
            pending_worker_mask: workers.pending_mask,
            worker_operations_in_flight: workers.operations_in_flight,
        });
    }
    0
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
                    request_vmstop: capabilities.request_vmstop,
                    inject_preemption: capabilities.inject_preemption,
                    clock_deadline_ns: capabilities.clock_deadline_ns,
                    advance_time_ns: capabilities.advance_time_ns,
                    register_vcpu_init: capabilities.register_vcpu_init,
                    register_vcpu_idle_resume: capabilities.register_vcpu_idle_resume,
                    register_control_boundary: capabilities.register_control_boundary,
                    register_sim_shmem_dispatch: capabilities.register_sim_shmem_dispatch,
                    register_time_advance_cb: capabilities.register_time_advance_cb,
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
/// Production publication deliberately forgets this owner, so its mapping and
/// callback allocations remain valid whether the lifecycle reader is blocked,
/// the teardown worker is draining callbacks, or both have returned after
/// requesting QEMU shutdown. Non-published owners interrupt and join the reader,
/// then signal and join the teardown worker in [`Drop`] before Rust may release
/// any mapped callback state.
pub struct PluginRuntimeOwner {
    plugin_id: QemuPluginId,
    args: PluginArgs,
    state: PluginStatePartition,
    control_interrupt: UnixStream,
    teardown_interrupt: mpsc::Sender<LiveRuntimeTeardownTrigger>,
    #[cfg(test)]
    _retained_control: Option<ControlLifecycleStream<UnixStream>>,
    #[cfg(test)]
    _retained_teardown_receiver: Option<mpsc::Receiver<LiveRuntimeTeardownTrigger>>,
    control_reader: Option<std::thread::JoinHandle<()>>,
    teardown_worker: Option<std::thread::JoinHandle<()>>,
    _time_control: PluginTimeControlOwnership,
    _callbacks: RequiredOwnedCallbacksRegistered,
    _boot_release: BootBarrierRelease,
    _ready: PluginRegistrationReady,
}

impl Drop for PluginRuntimeOwner {
    fn drop(&mut self) {
        let _shutdown = self.control_interrupt.shutdown(Shutdown::Both);
        if let Some(reader) = self.control_reader.take() {
            let _joined = reader.join();
        }
        let _interrupted =
            self.teardown_interrupt
                .send(LiveRuntimeTeardownTrigger::RunControlFault {
                    diagnostic: String::from(
                        "runtime owner dropped before process-lifetime shutdown",
                    ),
                });
        if let Some(worker) = self.teardown_worker.take() {
            let _joined = worker.join();
        }
    }
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

    let control_stream = crate::abi::duplicate_control_stream(args.sim_fd()).map_err(|source| {
        PluginRuntimeInstallError::DuplicateControlFd {
            fd: args.sim_fd(),
            source,
        }
    })?;
    let control_interrupt = control_stream.try_clone().map_err(|source| {
        PluginRuntimeInstallError::DuplicateControlFd {
            fd: args.sim_fd(),
            source,
        }
    })?;
    let mut control_stream = ControlLifecycleStream::connected_unix_stream(control_stream)
        .map_err(|source| PluginRuntimeInstallError::ControlLifecycle { source })?;
    reservation.mark_irreversible();
    let handshake = sequence
        .perform_control_handshake_lifecycle(&mut control_stream, &args)
        .map_err(registration_error)?;
    let time_control = sequence
        .request_time_control(capabilities.request_time_control)
        .map_err(registration_error)?;
    let setup = sequence
        .receive_setup_with_descriptors_lifecycle(&mut control_stream)
        .map_err(registration_error)?;
    let setup = {
        let mut setup_writer = PluginSetupWriter(&mut control_stream);
        sequence
            .prepare_setup_completion(&mut setup_writer, setup, handshake)
            .map_err(registration_error)?
    };

    let (teardown_sender, teardown_receiver) = mpsc::channel();
    let callback_state =
        OwnedCallbackRuntimeState::pin(plugin_worker_mask(&args), setup, teardown_sender.clone());
    let mut post_registration_stage = PostRegistrationStage::RegisterCallbacks;
    let mut acknowledgement_state = PostRegistrationAckState::Pending;
    let post_registration = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut retained = CallbackStateRetention::new(callback_state);
        maybe_inject_post_registration_panic(post_registration_stage);
        let registration_mask = match callback_registrar.register(&args, retained.registering_mut())
        {
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
                retained.registered_mut(),
                capabilities.register_wake_fd,
            )
        };
        if let Err(source) = wake_registration {
            acknowledgement_state = PostRegistrationAckState::FailureAttempted;
            return Err(registration_error(source));
        }

        post_registration_stage = PostRegistrationStage::AdmitFaultCapabilities;
        maybe_inject_post_registration_panic(post_registration_stage);
        if let Err(source) = retained.registered().admit_fault_capabilities() {
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
            retained.registered_mut().userdata(),
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

        post_registration_stage = PostRegistrationStage::SealResourceManifest;
        maybe_inject_post_registration_panic(post_registration_stage);
        let resource_manifest =
            match plugin_resource_manifest(plugin_id, &args, retained.registered()) {
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
        acknowledgement_state = PostRegistrationAckState::ReadyAttempted;
        let setup_ack = {
            let mut setup_writer = PluginSetupWriter(&mut control_stream);
            sequence
                .send_ready_setup_ack(
                    &mut setup_writer,
                    &callback_capabilities,
                    retained.registered(),
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
        Ok(Ok((callbacks_registered, boot_release, ready))) => {
            if let Err(source) = control_stream.enter_run_via_shared_memory() {
                fatal_policy.terminate(PluginRuntimeInstallError::ControlLifecycle { source });
            }
            #[cfg(not(test))]
            let (control_reader, teardown_worker) = {
                let teardown_handle =
                    match callbacks_registered.control_teardown_handle(args.slot()) {
                        Ok(handle) => handle,
                        Err(error) => fatal_policy.terminate(error),
                    };
                let request_shutdown = capabilities.request_shutdown;
                let teardown_workers = callbacks_registered.worker_quiescence();
                let teardown_worker = match std::thread::Builder::new()
                    .name(String::from("crucible-teardown"))
                    .spawn(move || {
                        run_runtime_thread_fail_loud("teardown worker", || {
                            run_teardown_worker(
                                teardown_receiver,
                                teardown_handle,
                                request_shutdown,
                                teardown_workers,
                            );
                        });
                    }) {
                    Ok(worker) => worker,
                    Err(source) => fatal_policy
                        .terminate(PluginRuntimeInstallError::TeardownWorkerSpawn { source }),
                };
                let reader_sender = teardown_sender.clone();
                let control_workers = callbacks_registered.worker_quiescence();
                let control_reader = match std::thread::Builder::new()
                    .name(String::from("crucible-run-control"))
                    .spawn(move || {
                        run_runtime_thread_fail_loud("RUN control reader", || {
                            let _delivered =
                                run_control_reader(control_stream, reader_sender, control_workers);
                        });
                    }) {
                    Ok(reader) => reader,
                    Err(source) => fatal_policy
                        .terminate(PluginRuntimeInstallError::ControlWorkerSpawn { source }),
                };
                (Some(control_reader), Some(teardown_worker))
            };
            #[cfg(test)]
            let (retained_control, control_reader, teardown_worker) =
                (Some(control_stream), None, None);
            Ok(PluginRuntimeOwner {
                plugin_id,
                args,
                state,
                control_interrupt,
                teardown_interrupt: teardown_sender,
                #[cfg(test)]
                _retained_control: retained_control,
                #[cfg(test)]
                _retained_teardown_receiver: Some(teardown_receiver),
                control_reader,
                teardown_worker,
                _time_control: time_control,
                _callbacks: callbacks_registered,
                _boot_release: boot_release,
                _ready: ready,
            })
        }
        Ok(Err(error)) => fatal_policy.terminate(error),
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
            callback_source: source,
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
    /// The lifecycle-aware control stream could not be advanced safely.
    #[error("plugin control lifecycle failed: {source}")]
    ControlLifecycle {
        /// Underlying control lifecycle or frame I/O error.
        source: crucible_protocol::ControlLifecycleIoError,
    },
    /// The teardown worker could not bind its stable mapped node slot.
    #[error("binding plugin teardown slot failed: {source}")]
    TeardownSlot {
        /// Underlying mapped-region access error.
        source: crucible_shmem::MappedSetupRegionAccessError,
    },
    /// The lifecycle control worker thread could not be started.
    #[error("spawning plugin run-control worker failed: {source}")]
    ControlWorkerSpawn {
        /// Underlying host thread-creation error.
        source: std::io::Error,
    },
    /// The sole teardown worker thread could not be started.
    #[error("spawning plugin teardown worker failed: {source}")]
    TeardownWorkerSpawn {
        /// Underlying host thread-creation error.
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
    /// Setup-time QEMU fault capability admission failed before guest start.
    #[error("live QEMU fault capability admission failed: {source}")]
    FaultCapabilityAdmission {
        /// Exact bridge or QEMU capability failure.
        source: LiveVcpuTimeCallbackError,
    },
    /// The fixed plugin resource manifest could not be represented.
    #[error("plugin resource manifest shape is not representable")]
    ResourceManifestShape,
    /// QEMU rejected the fixed plugin resource manifest.
    #[error("QEMU rejected the plugin resource manifest with status {status}")]
    ResourceManifestRejected {
        /// Negative errno-style status returned by patched QEMU.
        status: i32,
    },
    /// QEMU rejected the process-lifetime callback-barrier registration.
    #[error("QEMU rejected the hot-fork callback barrier with status {status}")]
    HotForkBarrierRejected {
        /// Negative errno-style QEMU status.
        status: i32,
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
mod tests;
