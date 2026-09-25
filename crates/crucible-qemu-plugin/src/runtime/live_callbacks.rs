//! Live vCPU-boundary and sim-loop shared-memory callback adapters.
//!
//! These adapters join the production callback families wired end to end:
//! standard vCPU initialization, the sim loop's current-icount/ceiling bridge,
//! exact-timer all-idle parking, queued time advance, normal-main-loop
//! completion, network TX/RX, block submit/poll, and 9p burst/submit/poll. The
//! optional white-box family remains disabled unless its launch switch is on.

use std::os::raw::{c_uint, c_void};
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError, mpsc};

use crucible_shmem::{
    AdvanceStopCondition, DirectedRing, FingerprintSampleSlot, FrameEntry, MappedDirectedRingMut,
    MappedSetupRegionAccessError, NodeSlot, NodeSlotError, PreemptionMailboxError,
    RegionControlAction, RegionHeader, RingHeader, SLOT_NET_ROUTER, SchedulerPreemptionKind,
};

use crate::fault_command::{FaultCommandBridge, QemuFaultCommandApis};
use crate::fingerprint_sampler::{CapturedFingerprintSample, PluginFingerprintSampling};
use crate::{
    ExactDeadlineError, ExactDeadlineReader, ExactDeadlineReport, IdleHotLoopError,
    IdleParkRequest, IdleWakeCause, InboundFrameError, InboundFrameRing, NetworkRxError,
    NetworkTxError, NetworkTxRing, PendingIdleAdvance, PluginArgs, PluginInboundFrames,
    PluginNetworkRx, PluginNetworkTx, PluginPreemptionDecision, PluginPreemptionInjector,
    PluginShmemOrdering, PluginShutdownRequested, PreemptionError, PreemptionWindow,
    QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL, QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_BLK_EVENT_CB_SYMBOL, QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_CONTROL_BOUNDARY_CB_SYMBOL, QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL, QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL, QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL,
    QemuAdvanceTimeTicksFn, QemuCanonicalNetworkRx, QemuClockDeadlineFn, QemuForceVcpuExitFn,
    QemuIcountRawFn, QemuIdleWakeWait, QemuIdleWakeWaitStatus, QemuPluginExecutionModel,
    QemuPluginId, QemuPluginNetInjectFn, QemuPluginTargetArchitecture, QemuRegisterBlkCbFn,
    QemuRegisterBlkEventCbFn, QemuRegisterBlkWaitCbFn, QemuRegisterControlBoundaryCbFn,
    QemuRegisterNetTxCbFn, QemuRegisterNinePCbFn, QemuRegisterSimShmemDispatchCbFn,
    QemuRegisterTimeAdvanceCbFn, QemuRegisterVcpuIdleResumeCbFn, QemuRegisterVcpuInitCbFn,
    QueuedIdleAdvance, QueuedIdleAdvanceError, RoundRobinError, SchedulerCeiling,
    TimeAdvanceCompletion, VcpuHaltTracker, compute_idle_wake_plan,
    handle_network_rx_idle_callback,
};

use super::{
    LiveRuntimeTeardownRouter, LiveRuntimeTeardownTrigger, OwnedCallbackRegistrar,
    OwnedCallbackRegistrationError, OwnedCallbackRegistrationMask, OwnedCallbackRuntimeState,
    callback_quiescence::{LiveCallbackInFlight, LiveCallbackQuiescence},
    live_whitebox::{
        LiveWhiteboxApis, crucible_qemu_plugin_live_whitebox_vcpu_init_cb,
        deliver_selectable_reply_on_vcpu_resume, rebind_selectable_pending_boundary,
    },
    worker_quiescence::LiveWorkerQuiescence,
};

mod devices;
mod error;
mod fingerprint_worker;
mod logical_restore;
pub use devices::LiveDeviceCallbackError;
use devices::LiveDeviceCallbackState;
pub use error::LiveVcpuTimeCallbackError;
use fingerprint_worker::LiveFingerprintDigestWorker;
use logical_restore::raw_icount_publication_is_superseded;
#[cfg(test)]
pub(crate) mod test_support;

static LIVE_VCPU_TIME_STATE: AtomicPtr<LiveVcpuTimeCallbackState> =
    AtomicPtr::new(std::ptr::null_mut());

/// QEMU capabilities for the joined production callback families.
#[derive(Clone, Copy)]
pub(crate) struct LiveVcpuTimeCallbackCapabilities {
    pub(crate) icount_raw: QemuIcountRawFn,
    pub(crate) force_vcpu_exit: QemuForceVcpuExitFn,
    pub(crate) idle_wake_wait: QemuIdleWakeWait,
    pub(crate) request_vmstop: crate::QemuRequestVmstopFn,
    pub(crate) inject_preemption: Option<crate::QemuInjectPreemptionFn>,
    pub(crate) clock_deadline_ps: Option<QemuClockDeadlineFn>,
    pub(crate) advance_time_ticks: Option<QemuAdvanceTimeTicksFn>,
    pub(crate) register_vcpu_init: Option<QemuRegisterVcpuInitCbFn>,
    pub(crate) register_vcpu_idle_resume: Option<QemuRegisterVcpuIdleResumeCbFn>,
    pub(crate) register_control_boundary: Option<QemuRegisterControlBoundaryCbFn>,
    pub(crate) register_sim_shmem_dispatch: Option<QemuRegisterSimShmemDispatchCbFn>,
    pub(crate) register_time_advance_cb: Option<QemuRegisterTimeAdvanceCbFn>,
    pub(crate) arm_virtual_timer_witness: Option<crate::QemuArmVirtualTimerWitnessFn>,
    pub(crate) query_virtual_timer_witness: Option<crate::QemuQueryVirtualTimerWitnessFn>,
    pub(crate) register_net_tx: Option<QemuRegisterNetTxCbFn>,
    pub(crate) net_inject: Option<QemuPluginNetInjectFn>,
    pub(crate) register_block: Option<QemuRegisterBlkCbFn>,
    pub(crate) register_block_event: Option<QemuRegisterBlkEventCbFn>,
    pub(crate) register_block_wait: Option<QemuRegisterBlkWaitCbFn>,
    pub(crate) register_ninep: Option<QemuRegisterNinePCbFn>,
    pub(crate) register_accelerator: Option<crate::QemuRegisterAcceleratorCbFn>,
    pub(crate) fault_commands: QemuFaultCommandApis,
    pub(crate) request_shutdown: crate::QemuRequestShutdownFn,
}

/// One exact handoff from a selectable doorbell to the sim-publication scope.
///
/// The guest doorbell runs in an instruction callback, where QEMU deliberately
/// rejects native VMStop requests. It may force the current vCPU out of its TB,
/// then this shared handoff lets the exact post-TCG callback admit the stop only
/// after the pending request and current instruction count are published.
pub(crate) struct SelectableVmstopHandoff {
    pending: AtomicU8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeferredVmstopKind {
    Selectable,
    CampaignMarker,
}

impl SelectableVmstopHandoff {
    pub(crate) fn new() -> Self {
        Self {
            pending: AtomicU8::new(0),
        }
    }

    /// Reserves the sole deferred stop and forces the current TB to finish.
    pub(crate) fn defer(
        &self,
        force_vcpu_tb_exit: super::live_whitebox::QemuForceVcpuTbExitFn,
    ) -> Result<bool, i32> {
        self.defer_kind(DeferredVmstopKind::Selectable, force_vcpu_tb_exit)
    }

    pub(crate) fn defer_campaign_marker(
        &self,
        force_vcpu_tb_exit: super::live_whitebox::QemuForceVcpuTbExitFn,
    ) -> Result<bool, i32> {
        self.defer_kind(DeferredVmstopKind::CampaignMarker, force_vcpu_tb_exit)
    }

    fn defer_kind(
        &self,
        kind: DeferredVmstopKind,
        force_vcpu_tb_exit: super::live_whitebox::QemuForceVcpuTbExitFn,
    ) -> Result<bool, i32> {
        let tag = match kind {
            DeferredVmstopKind::Selectable => 1,
            DeferredVmstopKind::CampaignMarker => 2,
        };
        if self
            .pending
            .compare_exchange(0, tag, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(false);
        }
        let status = force_vcpu_tb_exit();
        if status != 0 {
            self.pending.store(0, Ordering::Release);
            return Err(status);
        }
        Ok(true)
    }

    fn claim(&self) -> Option<DeferredVmstopKind> {
        match self.pending.swap(0, Ordering::AcqRel) {
            1 => Some(DeferredVmstopKind::Selectable),
            2 => Some(DeferredVmstopKind::CampaignMarker),
            _ => None,
        }
    }

    fn restore(&self, kind: DeferredVmstopKind) {
        let tag = match kind {
            DeferredVmstopKind::Selectable => 1,
            DeferredVmstopKind::CampaignMarker => 2,
        };
        self.pending.store(tag, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire) != 0
    }
}

/// Registrar for the joined live vCPU, time, network, block, and 9p callbacks.
pub(crate) struct LiveVcpuTimeCallbackRegistrar {
    plugin_id: QemuPluginId,
    execution_model: QemuPluginExecutionModel,
    target_architecture: QemuPluginTargetArchitecture,
    capabilities: LiveVcpuTimeCallbackCapabilities,
}

impl LiveVcpuTimeCallbackRegistrar {
    pub(crate) const fn new(
        plugin_id: QemuPluginId,
        execution_model: QemuPluginExecutionModel,
        target_architecture: QemuPluginTargetArchitecture,
        capabilities: LiveVcpuTimeCallbackCapabilities,
    ) -> Self {
        Self {
            plugin_id,
            execution_model,
            target_architecture,
            capabilities,
        }
    }

    fn required_capabilities(
        &self,
        args: &PluginArgs,
    ) -> Result<RequiredLiveVcpuTimeCapabilities, LiveVcpuTimeCallbackError> {
        let exact_deadline = ExactDeadlineReader::require(self.capabilities.clock_deadline_ps)
            .map_err(|source| LiveVcpuTimeCallbackError::ExactDeadlineCapability { source })?;
        let preemption_injector =
            PluginPreemptionInjector::require(self.capabilities.inject_preemption)
                .map_err(|source| LiveVcpuTimeCallbackError::Preemption { source })?;
        let queued_idle_advance = QueuedIdleAdvance::require(self.capabilities.advance_time_ticks)
            .map_err(|source| LiveVcpuTimeCallbackError::QueuedIdleAdvance { source })?;
        let virtual_timer_witness = crate::QemuVirtualTimerWitness::require(
            self.capabilities.arm_virtual_timer_witness,
            self.capabilities.query_virtual_timer_witness,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::VirtualTimerWitness { source })?;
        let register_vcpu_init = self.capabilities.register_vcpu_init.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL,
            },
        )?;
        let register_vcpu_idle_resume = self.capabilities.register_vcpu_idle_resume.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL,
            },
        )?;
        let register_control_boundary = self.capabilities.register_control_boundary.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_CONTROL_BOUNDARY_CB_SYMBOL,
            },
        )?;
        let register_sim_shmem_dispatch = self.capabilities.register_sim_shmem_dispatch.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL,
            },
        )?;
        let register_time_advance_cb = self.capabilities.register_time_advance_cb.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL,
            },
        )?;
        let register_net_tx = self.capabilities.register_net_tx.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL,
            },
        )?;
        let network_rx = QemuCanonicalNetworkRx::require(self.capabilities.net_inject)
            .map_err(|source| LiveVcpuTimeCallbackError::NetworkRx { source })?;
        let register_block = self.capabilities.register_block.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL,
            },
        )?;
        let register_block_event = self.capabilities.register_block_event.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_BLK_EVENT_CB_SYMBOL,
            },
        )?;
        let register_block_wait = self.capabilities.register_block_wait.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL,
            },
        )?;
        let register_ninep = self.capabilities.register_ninep.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL,
            },
        )?;
        let register_accelerator = self.capabilities.register_accelerator.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_REGISTER_ACCELERATOR_CB_SYMBOL,
            },
        )?;
        let whitebox = if args.whitebox().is_on() {
            Some(LiveWhiteboxApis::resolve().map_err(|source| {
                LiveVcpuTimeCallbackError::WhiteboxCallback {
                    message: source.to_string(),
                }
            })?)
        } else {
            None
        };
        Ok(RequiredLiveVcpuTimeCapabilities {
            icount_raw: self.capabilities.icount_raw,
            force_vcpu_exit: self.capabilities.force_vcpu_exit,
            idle_wake_wait: self.capabilities.idle_wake_wait,
            request_vmstop: self.capabilities.request_vmstop,
            preemption_injector,
            exact_deadline,
            queued_idle_advance,
            virtual_timer_witness,
            register_vcpu_init,
            register_vcpu_idle_resume,
            register_control_boundary,
            register_sim_shmem_dispatch,
            register_time_advance_cb,
            register_net_tx,
            network_rx,
            register_block,
            register_block_event,
            register_block_wait,
            register_ninep,
            register_accelerator,
            fault_commands: self.capabilities.fault_commands,
            request_shutdown: self.capabilities.request_shutdown,
            whitebox,
        })
    }
}

impl OwnedCallbackRegistrar for LiveVcpuTimeCallbackRegistrar {
    fn preflight(&self, args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
        self.required_capabilities(args)
            .map(|_capabilities| ())
            .map_err(live_callback_registration_error)
    }

    fn register(
        &self,
        args: &PluginArgs,
        mut state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
        let capabilities = self
            .required_capabilities(args)
            .map_err(live_callback_registration_error)?;
        let fingerprint = if args.fingerprint().is_on() {
            Some(PluginFingerprintSampling::resolve().ok_or_else(|| {
                live_callback_registration_error(
                    LiveVcpuTimeCallbackError::FingerprintCapabilityUnavailable,
                )
            })?)
        } else {
            None
        };
        let callback_state = state
            .as_mut()
            .prepare_live_vcpu_time_state(
                self.execution_model.smp_vcpus(),
                args.slot(),
                args.fault_node_hash(),
                capabilities.icount_raw,
                capabilities.force_vcpu_exit,
                capabilities.request_vmstop,
                capabilities.preemption_injector,
                (capabilities.icount_raw)(),
                capabilities.exact_deadline,
                capabilities.queued_idle_advance,
                capabilities.virtual_timer_witness,
                capabilities.idle_wake_wait,
                capabilities.network_rx,
                args.network_tx_next_seq(),
                args.storage_history_limits(),
                args.process_generation(),
                capabilities.fault_commands,
                fingerprint,
            )
            .map_err(live_callback_registration_error)?;
        LIVE_VCPU_TIME_STATE
            .compare_exchange(
                std::ptr::null_mut(),
                callback_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_existing| {
                live_callback_registration_error(
                    LiveVcpuTimeCallbackError::CallbackStateAlreadyPublished,
                )
            })?;

        (capabilities.register_vcpu_idle_resume)(
            Some(crucible_qemu_plugin_live_vcpu_idle_cb),
            Some(crucible_qemu_plugin_live_vcpu_resume_cb),
            callback_state.cast(),
        );
        (capabilities.register_control_boundary)(
            Some(crucible_qemu_plugin_live_control_boundary_cb),
            callback_state.cast(),
        );
        (capabilities.register_sim_shmem_dispatch)(
            Some(crucible_qemu_plugin_live_publish_icount_cb),
            Some(crucible_qemu_plugin_live_max_advance_icount_cb),
            Some(crucible_qemu_plugin_live_logical_ceiling_cb),
            callback_state.cast(),
        );
        let completion_status = (capabilities.register_time_advance_cb)(
            Some(crucible_qemu_plugin_live_time_advance_completion_cb),
            callback_state.cast(),
        );
        if completion_status != 0 {
            return Err(live_callback_registration_error(
                LiveVcpuTimeCallbackError::TimeAdvanceCompletionRegistrationRejected {
                    status: completion_status,
                },
            ));
        }
        (capabilities.register_net_tx)(
            Some(crucible_qemu_plugin_live_network_tx_cb),
            callback_state.cast(),
        );
        (capabilities.register_block)(
            Some(devices::crucible_qemu_plugin_live_block_submit_cb),
            Some(devices::crucible_qemu_plugin_live_block_poll_cb),
            callback_state.cast(),
        );
        (capabilities.register_block_event)(
            Some(devices::crucible_qemu_plugin_live_block_event_poll_cb),
            Some(devices::crucible_qemu_plugin_live_block_event_commit_cb),
            Some(devices::crucible_qemu_plugin_live_block_transport_save_cb),
            Some(devices::crucible_qemu_plugin_live_block_transport_restore_cb),
            callback_state.cast(),
        );
        (capabilities.register_block_wait)(
            Some(crucible_qemu_plugin_live_block_wait_cb),
            callback_state.cast(),
        );
        (capabilities.register_ninep)(
            Some(devices::crucible_qemu_plugin_live_ninep_burst_start_cb),
            Some(devices::crucible_qemu_plugin_live_ninep_submit_cb),
            Some(devices::crucible_qemu_plugin_live_ninep_poll_cb),
            Some(devices::crucible_qemu_plugin_live_ninep_burst_done_cb),
            callback_state.cast(),
        );
        (capabilities.register_accelerator)(
            Some(devices::crucible_qemu_plugin_live_accelerator_submit_cb),
            Some(devices::crucible_qemu_plugin_live_accelerator_poll_cb),
            Some(devices::crucible_qemu_plugin_live_accelerator_wait_cb),
            Some(devices::crucible_qemu_plugin_live_accelerator_restore_begin_cb),
            Some(devices::crucible_qemu_plugin_live_accelerator_restore_cb),
            Some(devices::crucible_qemu_plugin_live_accelerator_restore_commit_cb),
            Some(devices::crucible_qemu_plugin_live_accelerator_restore_abort_cb),
            Some(devices::crucible_qemu_plugin_live_accelerator_cancel_cb),
            callback_state.cast(),
        );
        let mut mask = OwnedCallbackRegistrationMask::base_required();
        let mut vcpu_init_callback: crate::QemuVcpuSimpleCbFn =
            crucible_qemu_plugin_live_vcpu_init_cb;
        if let Some(whitebox_apis) = capabilities.whitebox {
            let whitebox_state = state
                .as_mut()
                .prepare_live_whitebox_state(
                    whitebox_apis,
                    args,
                    self.target_architecture,
                    self.execution_model.smp_vcpus(),
                    capabilities.request_shutdown,
                )
                .map_err(|source| {
                    live_callback_registration_error(LiveVcpuTimeCallbackError::WhiteboxCallback {
                        message: source.to_string(),
                    })
                })?;
            whitebox_state
                .register(self.plugin_id, !args.coverage().is_on())
                .map_err(|source| {
                    live_callback_registration_error(LiveVcpuTimeCallbackError::WhiteboxCallback {
                        message: source.to_string(),
                    })
                })?;
            vcpu_init_callback = crucible_qemu_plugin_live_vcpu_and_whitebox_init_cb;
            mask = mask.with_whitebox();
        }
        (capabilities.register_vcpu_init)(
            self.plugin_id,
            vcpu_init_callback,
            callback_state.cast(),
        );
        Ok(mask)
    }
}

#[derive(Clone, Copy)]
struct RequiredLiveVcpuTimeCapabilities {
    icount_raw: QemuIcountRawFn,
    force_vcpu_exit: QemuForceVcpuExitFn,
    idle_wake_wait: QemuIdleWakeWait,
    request_vmstop: crate::QemuRequestVmstopFn,
    preemption_injector: PluginPreemptionInjector,
    exact_deadline: ExactDeadlineReader,
    queued_idle_advance: QueuedIdleAdvance,
    virtual_timer_witness: crate::QemuVirtualTimerWitness,
    register_vcpu_init: QemuRegisterVcpuInitCbFn,
    register_vcpu_idle_resume: QemuRegisterVcpuIdleResumeCbFn,
    register_control_boundary: QemuRegisterControlBoundaryCbFn,
    register_sim_shmem_dispatch: QemuRegisterSimShmemDispatchCbFn,
    register_time_advance_cb: QemuRegisterTimeAdvanceCbFn,
    register_net_tx: QemuRegisterNetTxCbFn,
    network_rx: QemuCanonicalNetworkRx,
    register_block: QemuRegisterBlkCbFn,
    register_block_event: QemuRegisterBlkEventCbFn,
    register_block_wait: QemuRegisterBlkWaitCbFn,
    register_ninep: QemuRegisterNinePCbFn,
    register_accelerator: crate::QemuRegisterAcceleratorCbFn,
    fault_commands: QemuFaultCommandApis,
    request_shutdown: crate::QemuRequestShutdownFn,
    whitebox: Option<LiveWhiteboxApis>,
}

/// Stable shared-memory slot address retained by the setup mapping owner.
struct StableNodeSlotHandle {
    slot: NonNull<NodeSlot>,
}

/// Stable mapped-region header retained by the setup mapping owner.
struct StableRegionHeaderHandle {
    header: NonNull<RegionHeader>,
}

impl StableRegionHeaderHandle {
    fn new(header: &RegionHeader) -> Self {
        Self {
            header: NonNull::from(header),
        }
    }

    fn get(&self) -> &RegionHeader {
        // SAFETY: the same pinned `OwnedCallbackRuntimeState` that retains the
        // node-slot handle owns the mapping containing this header. Callback
        // registration retains that owner for the process lifetime.
        unsafe { self.header.as_ref() }
    }
}

impl StableNodeSlotHandle {
    fn new(slot: &NodeSlot) -> Self {
        Self {
            slot: NonNull::from(slot),
        }
    }

    fn get(&self) -> &NodeSlot {
        // SAFETY: `OwnedCallbackRuntimeState` stores this handle only beside
        // the `PluginSetupCompletion` that owns the mapping. Callback-state
        // retention leaks both after any partial registration, and the active
        // owner retains both for process lifetime. The slot is accessed only
        // through its cross-process atomic API.
        unsafe { self.slot.as_ref() }
    }
}

/// Stable fingerprint-slot address retained by the setup mapping owner.
#[derive(Clone, Copy)]
struct StableFingerprintSlotHandle {
    slot: NonNull<FingerprintSampleSlot>,
}

// SAFETY: the handle points into the process-lifetime shared mapping retained by
// `OwnedCallbackRuntimeState`. The worker uses only `FingerprintSampleSlot`'s
// atomic publication API, whose shared reference is safe across threads.
unsafe impl Send for StableFingerprintSlotHandle {}

impl StableFingerprintSlotHandle {
    fn new(slot: &FingerprintSampleSlot) -> Self {
        Self {
            slot: NonNull::from(slot),
        }
    }

    fn get(&self) -> &FingerprintSampleSlot {
        // SAFETY: the fingerprint slot lives in the same setup-owned mapping as
        // the node slot and directed rings. `OwnedCallbackRuntimeState` retains
        // that mapping for the process lifetime after registration, and the slot
        // is published only through its interior seqlock-guarded atomics.
        unsafe { self.slot.as_ref() }
    }
}

/// Registration-fixed fingerprint sampling joined to the reached-icount publish.
///
/// Present only when the launch enabled `fingerprint=on`. It pairs the resolved
/// [`PluginFingerprintSampling`] capability with a stable handle to this VM's
/// per-node [`FingerprintSampleSlot`].
struct LiveFingerprintCallbackState {
    sampling: PluginFingerprintSampling,
    slot: StableFingerprintSlotHandle,
    worker: LiveFingerprintDigestWorker,
}

/// Stable raw view of one directed ring retained by the mapping owner.
struct StableDirectedRingHandle {
    descriptor: DirectedRing,
    header: NonNull<RingHeader>,
    entries: NonNull<FrameEntry>,
    entry_count: usize,
}

pub(super) struct LiveDirectedRingPair {
    outbound: StableDirectedRingHandle,
    inbound: StableDirectedRingHandle,
}

impl LiveDirectedRingPair {
    pub(super) fn new(
        outbound: MappedDirectedRingMut<'_>,
        inbound: MappedDirectedRingMut<'_>,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        Ok(Self {
            outbound: StableDirectedRingHandle::new(outbound)?,
            inbound: StableDirectedRingHandle::new(inbound)?,
        })
    }
}

impl StableDirectedRingHandle {
    fn new(ring: MappedDirectedRingMut<'_>) -> Result<Self, LiveVcpuTimeCallbackError> {
        let entries = NonNull::new(ring.entries.as_mut_ptr()).ok_or(
            LiveVcpuTimeCallbackError::MappedDirectedRingEmpty {
                ring_index: ring.descriptor.index,
            },
        )?;
        Ok(Self {
            descriptor: ring.descriptor,
            header: NonNull::from(ring.header),
            entries,
            entry_count: ring.entries.len(),
        })
    }

    fn inbound(&self) -> InboundFrameRing<'_> {
        // SAFETY: the setup mapping owns these validated addresses for the
        // callback state's lifetime. This handle is the only consumer for this
        // directed ring, and `dequeue` mutates only its atomic read index.
        let (header, entries) = unsafe {
            (
                self.header.as_ref(),
                core::slice::from_raw_parts(self.entries.as_ptr(), self.entry_count),
            )
        };
        InboundFrameRing::new(self.descriptor.index, header, entries)
    }

    fn outbound(&self) -> NetworkTxRing<'_> {
        // SAFETY: registration validated single-threaded round-robin callback
        // execution. `LiveVcpuTimeCallbackState` rejects callback re-entry, and
        // this handle is the sole producer for its distinct outbound ring.
        let (header, entries) = unsafe {
            (
                self.header.as_ref(),
                core::slice::from_raw_parts_mut(self.entries.as_ptr(), self.entry_count),
            )
        };
        NetworkTxRing::new(
            self.descriptor.index,
            self.descriptor.src_slot,
            self.descriptor.dst_slot,
            header,
            entries,
        )
    }
}

/// Registration-fixed live network state joined to the idle completion path.
struct LiveNetworkCallbackState {
    tx: PluginNetworkTx,
    restore_tx_sequence: u32,
    rx: PluginNetworkRx,
    rx_queue: QemuCanonicalNetworkRx,
    outbound: StableDirectedRingHandle,
    inbound: StableDirectedRingHandle,
    tx_callback_active: AtomicBool,
    rx_delivery_active: AtomicBool,
}

impl LiveNetworkCallbackState {
    fn new(
        vm_slot: u32,
        outbound: MappedDirectedRingMut<'_>,
        inbound: MappedDirectedRingMut<'_>,
        rx_queue: QemuCanonicalNetworkRx,
        next_tx_sequence: u32,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        let tx = PluginNetworkTx::from_directed_ring_with_sequence(
            vm_slot,
            outbound.descriptor,
            next_tx_sequence,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::NetworkTx { source })?;
        if inbound.descriptor.src_slot != SLOT_NET_ROUTER as u32
            || inbound.descriptor.dst_slot != vm_slot
        {
            return Err(LiveVcpuTimeCallbackError::WrongInboundNetworkRing {
                expected_src_slot: SLOT_NET_ROUTER as u32,
                expected_dst_slot: vm_slot,
                actual_src_slot: inbound.descriptor.src_slot,
                actual_dst_slot: inbound.descriptor.dst_slot,
                actual_ring_index: inbound.descriptor.index,
            });
        }
        Ok(Self {
            tx,
            restore_tx_sequence: next_tx_sequence,
            rx: PluginNetworkRx::new(),
            rx_queue,
            outbound: StableDirectedRingHandle::new(outbound)?,
            inbound: StableDirectedRingHandle::new(inbound)?,
            tx_callback_active: AtomicBool::new(false),
            rx_delivery_active: AtomicBool::new(false),
        })
    }
}

/// Heap-stable state shared by the joined production callback families.
///
/// Atomic state covers callback paths that can run without mutable access. The
/// block and 9p adapters share a separate mutex whose nonblocking acquisition
/// rejects callback re-entry before a mutable ring or freeze-state borrow forms.
pub(crate) struct LiveVcpuTimeCallbackState {
    quiescence: Arc<LiveCallbackQuiescence>,
    teardown_router: Arc<LiveRuntimeTeardownRouter>,
    shared_shutdown_signaled: AtomicBool,
    icount_raw: QemuIcountRawFn,
    sim_tick_observed: Option<crate::abi::QemuSimTickObservedFn>,
    force_vcpu_exit: QemuForceVcpuExitFn,
    idle_wake_wait: QemuIdleWakeWait,
    request_vmstop: crate::QemuRequestVmstopFn,
    selectable_vmstop: Arc<SelectableVmstopHandoff>,
    preemption_injector: PluginPreemptionInjector,
    vcpu_count: u32,
    header: StableRegionHeaderHandle,
    slot: StableNodeSlotHandle,
    exact_deadline: ExactDeadlineReader,
    queued_idle_advance: QueuedIdleAdvance,
    virtual_timer_witness: crate::QemuVirtualTimerWitness,
    initialized_vcpus: Box<[AtomicBool]>,
    halted_vcpus: Mutex<VcpuHaltTracker>,
    all_halted_idle_handled: AtomicBool,
    last_raw_icount: AtomicU64,
    logical_icount_offset: Arc<AtomicU64>,
    preemption_enqueue_active: AtomicBool,
    fault_command_pump_active: AtomicBool,
    control_boundary_dispatch_generation: AtomicU32,
    control_boundary_defer_diagnostic_generation: AtomicU64,
    idle_advance_completion_active: AtomicBool,
    last_icount: AtomicU64,
    logical_restore_continuation_generation: AtomicU32,
    // Read-only callbacks use this release-published coordinate without
    // borrowing the mutex-owned QEMU token or buffered network payloads.
    pending_idle_advance_active: AtomicBool,
    pending_idle_advance_raw_icount: AtomicU64,
    pending_idle_advance_target_icount: AtomicU64,
    idle_advance_generation: AtomicU64,
    pending_idle_advance: Mutex<Option<LivePendingIdleAdvance>>,
    network: Option<LiveNetworkCallbackState>,
    devices: Option<Mutex<LiveDeviceCallbackState>>,
    fingerprint: Option<LiveFingerprintCallbackState>,
    fault_commands: Mutex<Box<dyn LiveFaultCommandControl>>,
}

pub(super) trait LiveFaultCommandControl {
    fn initialize(&mut self) -> Result<(), crate::fault_command::FaultCommandBridgeError>;

    fn pump(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError>;

    fn pump_with_offset_reader(
        &mut self,
        raw_icount: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        self.pump(offset_reader()?, raw_icount)
    }

    fn pump_through_frontier(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
        frontier: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError>;

    fn pump_through_frontier_with_offset_reader(
        &mut self,
        raw_icount: u64,
        frontier: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        self.pump_through_frontier(offset_reader()?, raw_icount, frontier)
    }

    fn dispatch_node_boundary(
        &mut self,
        raw_icount: u64,
    ) -> Result<(), crate::fault_command::FaultCommandBridgeError>;

    fn drain_publications(
        &mut self,
        logical_icount_offset: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError>;

    fn command_frontier_is_settled(&self, frontier: u64) -> bool;
}

impl LiveFaultCommandControl for FaultCommandBridge {
    fn initialize(&mut self) -> Result<(), crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::initialize(self)
    }

    fn pump(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::pump(self, logical_icount_offset, raw_icount)
    }

    fn pump_with_offset_reader(
        &mut self,
        raw_icount: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::pump_with_offset_reader(self, raw_icount, offset_reader)
    }

    fn pump_through_frontier(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
        frontier: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::pump_through_frontier(self, logical_icount_offset, raw_icount, frontier)
    }

    fn pump_through_frontier_with_offset_reader(
        &mut self,
        raw_icount: u64,
        frontier: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::pump_through_frontier_with_offset_reader(
            self,
            raw_icount,
            frontier,
            offset_reader,
        )
    }

    fn dispatch_node_boundary(
        &mut self,
        raw_icount: u64,
    ) -> Result<(), crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::dispatch_node_boundary(self, raw_icount)
    }

    fn drain_publications(
        &mut self,
        logical_icount_offset: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        FaultCommandBridge::drain_publications(self, logical_icount_offset)
    }

    fn command_frontier_is_settled(&self, frontier: u64) -> bool {
        FaultCommandBridge::command_frontier_is_settled(self, frontier)
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct TestFaultCommandObservation {
    pumped_frontier: Option<u64>,
    boundary_dispatched: bool,
    publications_drained: bool,
}

#[cfg(test)]
pub(super) struct TestFaultCommandBridge {
    observation: Arc<Mutex<TestFaultCommandObservation>>,
    advance_tick_on_pump: Option<i64>,
}

#[cfg(test)]
impl TestFaultCommandBridge {
    fn empty() -> Self {
        Self {
            observation: Arc::new(Mutex::new(TestFaultCommandObservation::default())),
            advance_tick_on_pump: None,
        }
    }

    fn advancing_to(tick: i64) -> Self {
        Self {
            advance_tick_on_pump: Some(tick),
            ..Self::empty()
        }
    }

    fn observed() -> (Self, Arc<Mutex<TestFaultCommandObservation>>) {
        let observation = Arc::new(Mutex::new(TestFaultCommandObservation::default()));
        (
            Self {
                observation: Arc::clone(&observation),
                advance_tick_on_pump: None,
            },
            observation,
        )
    }
}

#[cfg(test)]
impl LiveFaultCommandControl for TestFaultCommandBridge {
    fn initialize(&mut self) -> Result<(), crate::fault_command::FaultCommandBridgeError> {
        Ok(())
    }

    fn pump(
        &mut self,
        _logical_icount_offset: u64,
        _raw_icount: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        Ok(true)
    }

    fn pump_with_offset_reader(
        &mut self,
        _raw_icount: u64,
        offset_reader: &dyn Fn() -> Result<u64, crate::fault_command::FaultCommandBridgeError>,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        offset_reader()?;
        if let Some(tick) = self.advance_tick_on_pump.take() {
            tests::TEST_SIM_TICK.set(tick);
        }
        offset_reader()?;
        Ok(true)
    }

    fn pump_through_frontier(
        &mut self,
        _logical_icount_offset: u64,
        _raw_icount: u64,
        frontier: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        if frontier == 0 {
            self.observation
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pumped_frontier = Some(frontier);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn dispatch_node_boundary(
        &mut self,
        _raw_icount: u64,
    ) -> Result<(), crate::fault_command::FaultCommandBridgeError> {
        let mut observation = self
            .observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        observation.boundary_dispatched = observation.pumped_frontier.is_some();
        Ok(())
    }

    fn drain_publications(
        &mut self,
        _logical_icount_offset: u64,
    ) -> Result<bool, crate::fault_command::FaultCommandBridgeError> {
        let mut observation = self
            .observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        observation.publications_drained = observation.boundary_dispatched;
        Ok(observation.publications_drained)
    }

    fn command_frontier_is_settled(&self, frontier: u64) -> bool {
        let observation = self
            .observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        observation.pumped_frontier == Some(frontier)
            && observation.boundary_dispatched
            && observation.publications_drained
    }
}

#[derive(Debug)]
struct LivePendingIdleAdvance {
    generation: u64,
    raw_icount_at_request: u64,
    target_icount: u64,
    pending: PendingIdleAdvance,
    timer_witness: Option<crate::ArmedVirtualTimerWitness>,
    buffered_tx_payloads: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdleAdvanceArmOutcome {
    Armed { generation: u64 },
    Occupied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdleSchedulerWaitDisposition {
    AdvanceTo(u64),
    ReturnToQemu,
    RescanInQemu,
}

struct PreemptionEnqueueGuard<'a>(&'a AtomicBool);

impl Drop for PreemptionEnqueueGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Releases exclusive fault-command pump ownership on every return path.
struct FaultCommandPumpGuard<'a>(&'a AtomicBool);

impl Drop for FaultCommandPumpGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Releases exclusive idle-completion ownership on every return path.
struct IdleAdvanceCompletionGuard<'a>(&'a AtomicBool);

impl Drop for IdleAdvanceCompletionGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl LiveVcpuTimeCallbackState {
    fn scheduler_advance(&self) -> Result<(u64, AdvanceStopCondition), LiveVcpuTimeCallbackError> {
        PluginShmemOrdering::load_scheduler_advance(self.slot.get()).map_err(|source| {
            LiveVcpuTimeCallbackError::IdleHotLoop {
                source: IdleHotLoopError::AdvanceStopCondition { source },
            }
        })
    }

    /// Reads the host authorization horizon in exact logical ticks.
    fn logical_ceiling(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        self.scheduler_advance()
            .map(|(ceiling, _condition)| ceiling)
    }

    fn scheduler_idle_ceiling(
        &self,
        desired_wake_icount: u64,
    ) -> Result<u64, LiveVcpuTimeCallbackError> {
        let (ceiling_icount, stop_condition) = self.scheduler_advance()?;
        if stop_condition != AdvanceStopCondition::Ceiling {
            return Err(LiveVcpuTimeCallbackError::IdleHotLoop {
                source: IdleHotLoopError::WakeNotAuthorized {
                    desired_wake_icount,
                    ceiling_icount,
                },
            });
        }
        Ok(ceiling_icount)
    }

    // crucible-lint: allow rust-allow -- construction binds the fixed QEMU clock, mapping, and slot capabilities.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor binds one fixed QEMU clock, mapping header, and node slot"
    )]
    pub(super) fn new(
        icount_raw: QemuIcountRawFn,
        force_vcpu_exit: QemuForceVcpuExitFn,
        idle_wake_wait: QemuIdleWakeWait,
        request_vmstop: crate::QemuRequestVmstopFn,
        preemption_injector: PluginPreemptionInjector,
        vcpu_count: u32,
        initial_raw_icount: u64,
        exact_deadline: ExactDeadlineReader,
        queued_idle_advance: QueuedIdleAdvance,
        virtual_timer_witness: crate::QemuVirtualTimerWitness,
        fault_commands: Box<dyn LiveFaultCommandControl>,
        header: &RegionHeader,
        slot: &NodeSlot,
        quiescence: Arc<LiveCallbackQuiescence>,
        teardown_router: Arc<LiveRuntimeTeardownRouter>,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        let snapshot = slot.snapshot();
        AdvanceStopCondition::decode(snapshot.advance_stop_condition).map_err(|source| {
            LiveVcpuTimeCallbackError::IdleHotLoop {
                source: IdleHotLoopError::AdvanceStopCondition { source },
            }
        })?;
        if snapshot.current_icount > snapshot.max_advance_icount {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount: snapshot.current_icount,
                ceiling_icount: snapshot.max_advance_icount,
            });
        }
        let logical_icount_offset = snapshot
            .current_icount
            .checked_sub(
                initial_raw_icount
                    .checked_mul(crucible_shmem::TICKS_PER_INSTRUCTION)
                    .ok_or(LiveVcpuTimeCallbackError::InitialRawIcountBeyondLogical {
                        raw_icount: initial_raw_icount,
                        logical_icount: snapshot.current_icount,
                    })?,
            )
            .ok_or(LiveVcpuTimeCallbackError::InitialRawIcountBeyondLogical {
                raw_icount: initial_raw_icount,
                logical_icount: snapshot.current_icount,
            })?;
        let initialized_vcpus = (0..vcpu_count)
            .map(|_vcpu| AtomicBool::new(false))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        #[cfg(not(test))]
        let sim_tick_observed = Some(crate::abi::resolve_qemu_sim_tick_observed_symbol().ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: crate::abi::QEMU_PLUGIN_SIM_TICK_OBSERVED_SYMBOL,
            },
        )?);
        #[cfg(test)]
        let sim_tick_observed = None;
        Ok(Self {
            quiescence,
            teardown_router,
            shared_shutdown_signaled: AtomicBool::new(false),
            icount_raw,
            sim_tick_observed,
            force_vcpu_exit,
            idle_wake_wait,
            request_vmstop,
            selectable_vmstop: Arc::new(SelectableVmstopHandoff::new()),
            preemption_injector,
            vcpu_count,
            header: StableRegionHeaderHandle::new(header),
            slot: StableNodeSlotHandle::new(slot),
            exact_deadline,
            queued_idle_advance,
            virtual_timer_witness,
            initialized_vcpus,
            halted_vcpus: Mutex::new(
                VcpuHaltTracker::new(vcpu_count)
                    .map_err(|source| LiveVcpuTimeCallbackError::VcpuHaltTracking { source })?,
            ),
            all_halted_idle_handled: AtomicBool::new(false),
            last_raw_icount: AtomicU64::new(initial_raw_icount),
            logical_icount_offset: Arc::new(AtomicU64::new(logical_icount_offset)),
            preemption_enqueue_active: AtomicBool::new(false),
            fault_command_pump_active: AtomicBool::new(false),
            control_boundary_dispatch_generation: AtomicU32::new(u32::MAX),
            control_boundary_defer_diagnostic_generation: AtomicU64::new(u64::MAX),
            idle_advance_completion_active: AtomicBool::new(false),
            last_icount: AtomicU64::new(snapshot.current_icount),
            logical_restore_continuation_generation: AtomicU32::new(0),
            pending_idle_advance_active: AtomicBool::new(false),
            pending_idle_advance_raw_icount: AtomicU64::new(0),
            pending_idle_advance_target_icount: AtomicU64::new(0),
            idle_advance_generation: AtomicU64::new(0),
            pending_idle_advance: Mutex::new(None),
            network: None,
            devices: None,
            fingerprint: None,
            fault_commands: Mutex::new(fault_commands),
        })
    }

    fn callback_guard(&self) -> Option<LiveCallbackInFlight> {
        let in_flight = self.quiescence.enter()?;
        if PluginShmemOrdering::observe_shutdown_requested(self.header.get()) {
            if let Err(error) = self.signal_shared_shutdown() {
                abort_live_callback(error);
            }
            return None;
        }
        Some(in_flight)
    }

    /// Delivers the first shared shutdown proof without waiting on capacity.
    ///
    /// The standard channel is unbounded, so `send` never waits for a receiver
    /// to drain capacity. A disconnected worker is returned as a fatal callback
    /// error rather than allowing QEMU to continue after shutdown was observed.
    fn signal_shared_shutdown(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        let proof = PluginShutdownRequested::from_region_header(self.header.get())
            .map_err(|_error| LiveVcpuTimeCallbackError::SharedShutdownProofUnavailable)?;
        if self
            .shared_shutdown_signaled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        self.teardown_router
            .send(LiveRuntimeTeardownTrigger::SharedShutdown(proof))
            .map_err(|()| LiveVcpuTimeCallbackError::TeardownWorkerUnavailable)
    }

    pub(super) fn attach_network(
        mut self,
        vm_slot: u32,
        outbound: MappedDirectedRingMut<'_>,
        inbound: MappedDirectedRingMut<'_>,
        rx_queue: QemuCanonicalNetworkRx,
        next_tx_sequence: u32,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        self.network = Some(LiveNetworkCallbackState::new(
            vm_slot,
            outbound,
            inbound,
            rx_queue,
            next_tx_sequence,
        )?);
        Ok(self)
    }

    /// Binds the resolved fingerprint sampler and this VM's shared-memory slot.
    ///
    /// Called only when the launch enabled `fingerprint=on`; afterwards an
    /// explicit, quiesced main-loop control boundary captures a black-box
    /// fingerprint sample and queues its detached preimages to a dedicated
    /// digest worker. `slot` is the per-node [`FingerprintSampleSlot`] retained by
    /// the same setup mapping owner as the node slot and directed rings.
    pub(super) fn attach_fingerprint(
        mut self,
        sampling: PluginFingerprintSampling,
        slot: &FingerprintSampleSlot,
        worker_quiescence: Arc<LiveWorkerQuiescence>,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        let slot = StableFingerprintSlotHandle::new(slot);
        let worker = LiveFingerprintDigestWorker::spawn(slot, worker_quiescence)?;
        self.fingerprint = Some(LiveFingerprintCallbackState {
            sampling,
            slot,
            worker,
        });
        Ok(self)
    }

    /// Replaces the vanished template fingerprint worker in a fork child.
    ///
    /// The caller holds callback and worker admission, and the template queue
    /// was proven empty before `fork(2)`. The inherited `JoinHandle` cannot be
    /// joined in the child, so it is deliberately abandoned after the fresh
    /// worker owns the same exact-address slot.
    pub(super) fn reinitialize_hot_fork_child_workers(
        &mut self,
        worker_quiescence: Arc<LiveWorkerQuiescence>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let Some(fingerprint) = self.fingerprint.as_mut() else {
            return Ok(());
        };
        let worker = LiveFingerprintDigestWorker::spawn(fingerprint.slot, worker_quiescence)?;
        let inherited = std::mem::replace(&mut fingerprint.worker, worker);
        std::mem::forget(inherited);
        Ok(())
    }

    /// Captures and publishes a requested fingerprint at a control boundary.
    ///
    /// A no-op unless the launch enabled `fingerprint=on`. The host first requests
    /// a capture generation, then drives the main loop to the BQL-held control
    /// boundary after device I/O quiesces. This call copies the sealed material
    /// into the bounded worker queue and returns without hashing it. The worker
    /// publishes the digest and acknowledges the capture request only after the
    /// matching sample becomes visible. The vCPU count is
    /// `self.vcpu_count` — the install-time
    /// `smp_vcpus` QEMU reported to the plugin (`execution_model.smp_vcpus()`),
    /// bound into this callback state at construction — so the sample covers
    /// every configured vCPU.
    ///
    /// # Errors
    ///
    /// Returns [`LiveVcpuTimeCallbackError::FingerprintSample`] when boundary
    /// introspection or capture fails, or a worker error when the bounded digest
    /// worker cannot accept the exact-boundary capture.
    fn publish_fingerprint_sample(
        &self,
        icount: u64,
        boundary: &'static str,
        capture_request: u32,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let Some(fingerprint) = self.fingerprint.as_ref() else {
            return Ok(());
        };
        if PluginShmemOrdering::device_io_active(self.slot.get()) {
            return Err(LiveVcpuTimeCallbackError::FingerprintSample {
                boundary,
                message: String::from("device projection requested before device I/O quiesced"),
            });
        }
        let captured = fingerprint
            .sampling
            .capture(icount, self.vcpu_count)
            .map_err(|source| LiveVcpuTimeCallbackError::FingerprintSample {
                boundary,
                message: source.to_string(),
            })?;
        fingerprint.worker.submit(captured, capture_request)
    }

    fn idle_advance_is_pending(&self) -> bool {
        self.pending_idle_advance_active.load(Ordering::Acquire)
    }

    /// Returns the raw dispatch clamp while a queued time jump is pending.
    fn pending_idle_advance_clamp(
        &self,
        raw_icount: u64,
    ) -> Result<Option<u64>, LiveVcpuTimeCallbackError> {
        if !self.idle_advance_is_pending() {
            return Ok(None);
        }
        let raw_icount_at_request = self.pending_idle_advance_raw_icount.load(Ordering::Acquire);
        if raw_icount != raw_icount_at_request {
            return Err(
                LiveVcpuTimeCallbackError::GuestProgressWhileIdleAdvancePending {
                    expected_raw_icount: raw_icount_at_request,
                    observed_raw_icount: raw_icount,
                },
            );
        }
        Ok(Some(raw_icount_at_request))
    }

    fn on_vcpu_init(&self, vcpu_index: u32) -> Result<(), LiveVcpuTimeCallbackError> {
        self.initialize_fault_commands()?;
        let initialized = self.vcpu_flag(vcpu_index)?;
        initialized.store(true, Ordering::Release);
        Ok(())
    }

    fn on_vcpu_idle(
        &self,
        vcpu_index: u32,
        raw_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.require_initialized_vcpu(vcpu_index)?;
        let all_halted = {
            let mut halted_vcpus = self.try_halted_vcpus()?;
            halted_vcpus
                .mark_halted(vcpu_index)
                .map_err(|source| LiveVcpuTimeCallbackError::VcpuHaltTracking { source })?;
            halted_vcpus.all_halted()
        };
        if !all_halted
            || self
                .all_halted_idle_handled
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Ok(());
        }
        if self.idle_advance_is_pending() {
            // The accepted advance will wake every halted vCPU after its
            // completion commits. Release this one-shot edge so that wake can
            // recompute the next target without disturbing the winner.
            self.all_halted_idle_handled.store(false, Ordering::Release);
            return Ok(());
        }
        // The all-halted callback still runs on the last vCPU thread. With no
        // serialized RR owner, cross-vCPU register capture is intentionally
        // forbidden there; the host requests a BQL-held control boundary after
        // accepting the paused quantum and samples that exact coordinate.
        self.publish_current_icount_for_boundary(raw_icount, true, "vcpu-idle")?;
        let current_icount = self.last_icount.load(Ordering::Acquire);
        let next_inbound_delivery_icount = if let Some(network) = self.network.as_ref() {
            let inbound = network.inbound.inbound();
            PluginInboundFrames::reject_already_passed_ring_heads([inbound], current_icount)
                .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?;
            PluginInboundFrames::peek_next_delivery_icount([inbound])
                .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?
        } else {
            None
        };
        let exact_deadline = self
            .exact_deadline
            .read_next_deadline()
            .map_err(|source| LiveVcpuTimeCallbackError::ExactDeadlineRead { source })?;
        let timer_deadline_ps = match exact_deadline {
            ExactDeadlineReport::Armed { deadline_ps } => Some(deadline_ps),
            ExactDeadlineReport::NoArmedTimer => None,
        };
        let (ceiling_icount, _) = self.scheduler_advance()?;
        let device_io_holding_ticks = PluginShmemOrdering::device_io_active(self.slot.get());
        let device_completion_deadline_tick = if device_io_holding_ticks {
            Some(PluginShmemOrdering::device_completion_deadline_tick(
                self.slot.get(),
            ))
        } else {
            None
        };
        let plan = compute_idle_wake_plan(
            current_icount,
            exact_deadline,
            next_inbound_delivery_icount,
            SchedulerCeiling::new(ceiling_icount),
            device_io_holding_ticks,
            device_completion_deadline_tick,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::IdleHotLoop { source })?;
        let futex_wait = PluginShmemOrdering::publish_idle_wait(
            self.slot.get(),
            current_icount,
            plan.desired_wake_icount(),
        )
        .map_err(|source| LiveVcpuTimeCallbackError::PublishIdle { source })?;
        let request = IdleParkRequest::from_published(plan, futex_wait);
        match self.wait_for_scheduler_release_or_inbound(vcpu_index, &request, raw_icount)? {
            IdleSchedulerWaitDisposition::ReturnToQemu
            | IdleSchedulerWaitDisposition::RescanInQemu => Ok(()),
            IdleSchedulerWaitDisposition::AdvanceTo(target_icount) => {
                if !self.arm_and_enqueue_idle_advance_or_defer(
                    raw_icount,
                    target_icount,
                    (plan.cause() == IdleWakeCause::TimerDeadline)
                        .then_some(timer_deadline_ps)
                        .flatten(),
                )? {
                    // QEMU still owns the preceding advance barrier. Its
                    // completion kicks every halted vCPU, so release this
                    // one-shot edge and let that later all-halted callback
                    // recompute from the then-current ceiling and inbox.
                    self.all_halted_idle_handled.store(false, Ordering::Release);
                    return Ok(());
                }
                Ok(())
            }
        }
    }

    fn wait_for_scheduler_release_or_inbound(
        &self,
        vcpu_index: u32,
        request: &IdleParkRequest,
        raw_icount: u64,
    ) -> Result<IdleSchedulerWaitDisposition, LiveVcpuTimeCallbackError> {
        loop {
            match PluginShmemOrdering::observe_control_action(self.header.get()) {
                RegionControlAction::Shutdown => {
                    self.signal_shared_shutdown()?;
                    return Ok(IdleSchedulerWaitDisposition::ReturnToQemu);
                }
                RegionControlAction::Pause => {
                    if PluginShmemOrdering::control_boundary_is_requested(self.slot.get()) {
                        // The eventfd-driven two-pass callback owns the paired
                        // pause after device waiters have run.
                        return Ok(IdleSchedulerWaitDisposition::ReturnToQemu);
                    }
                    if !PluginShmemOrdering::device_io_active(self.slot.get()) {
                        PluginShmemOrdering::publish_pause_quiesced(
                            self.slot.get(),
                            request.plan().current_icount(),
                            raw_icount,
                        )
                        .map_err(|source| LiveVcpuTimeCallbackError::PublishPause { source })?;
                        self.request_checkpoint_vmstop("vcpu-idle-wait")?;
                        // Leave the callback without authorizing an idle advance.
                        // This hands QEMU's execution path back to its main loop so
                        // it can consume the queued asynchronous stop request and
                        // remain QMP-responsive at the fenced coordinate.
                        return Ok(IdleSchedulerWaitDisposition::ReturnToQemu);
                    }
                }
                RegionControlAction::Continue => {}
            }
            if PluginShmemOrdering::control_boundary_is_requested(self.slot.get()) {
                // Return to QEMU's main loop without authorizing guest or idle
                // time. The registered eventfd callback publishes and
                // acknowledges the requested post-device boundary.
                return Ok(IdleSchedulerWaitDisposition::ReturnToQemu);
            }
            let (ceiling_icount, stop_condition) =
                PluginShmemOrdering::load_scheduler_advance(self.slot.get()).map_err(|source| {
                    LiveVcpuTimeCallbackError::IdleHotLoop {
                        source: IdleHotLoopError::AdvanceStopCondition { source },
                    }
                })?;
            if stop_condition == AdvanceStopCondition::Ceiling {
                if let Some(network) = self.network.as_ref() {
                    let inbound = network.inbound.inbound();
                    PluginInboundFrames::reject_already_passed_ring_heads(
                        [inbound],
                        request.plan().current_icount(),
                    )
                    .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?;
                    if let Some(delivery_icount) =
                        PluginInboundFrames::peek_next_delivery_icount([inbound])
                            .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?
                        && delivery_icount <= ceiling_icount
                    {
                        return Ok(IdleSchedulerWaitDisposition::AdvanceTo(
                            request.plan().desired_wake_icount().min(delivery_icount),
                        ));
                    }
                }
                if ceiling_icount >= request.plan().desired_wake_icount() {
                    return Ok(IdleSchedulerWaitDisposition::AdvanceTo(
                        request.plan().desired_wake_icount(),
                    ));
                }
            }

            let Some(status) =
                self.idle_wake_wait
                    .wait_once(vcpu_index, self.slot.get(), request.futex_wait())
            else {
                // The published wait was already runnable, so QEMU kept the BQL.
                // Rescan inside this callback without crossing the FFI boundary.
                continue;
            };

            // QEMU released and reacquired the BQL around an admitted raw wait.
            // Clear the edge before handling every status. No result may reuse
            // this callback's authorization basis or enqueue work after return.
            self.all_halted_idle_handled.store(false, Ordering::Release);
            return match status {
                QemuIdleWakeWaitStatus::Woken
                | QemuIdleWakeWaitStatus::ValueChanged
                | QemuIdleWakeWaitStatus::Interrupted
                | QemuIdleWakeWaitStatus::CpuChanged
                | QemuIdleWakeWaitStatus::QemuWorkPending => {
                    Ok(IdleSchedulerWaitDisposition::RescanInQemu)
                }
                QemuIdleWakeWaitStatus::InvalidArgument
                | QemuIdleWakeWaitStatus::InvalidContext
                | QemuIdleWakeWaitStatus::AlreadyIssued
                | QemuIdleWakeWaitStatus::Unsupported
                | QemuIdleWakeWaitStatus::SyscallError
                | QemuIdleWakeWaitStatus::Unknown(_) => {
                    Err(LiveVcpuTimeCallbackError::IdleWakeWaitRejected {
                        status: status.into_raw(),
                    })
                }
            };
        }
    }

    fn on_vcpu_resume(
        &self,
        vcpu_index: u32,
        raw_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.require_initialized_vcpu(vcpu_index)?;
        if self.publish_pause_for_boundary(raw_icount, true, false, None, "vcpu-resume")? {
            return Ok(());
        }
        let control_boundary_requested =
            PluginShmemOrdering::control_boundary_is_requested(self.slot.get());
        if self.idle_advance_is_pending() {
            if control_boundary_requested {
                return Ok(());
            }
            return Err(LiveVcpuTimeCallbackError::ResumeWhileIdleAdvancePending);
        }
        let current_icount = self.logical_icount_for_raw(raw_icount)?;
        deliver_selectable_reply_on_vcpu_resume(vcpu_index, current_icount).map_err(|source| {
            LiveVcpuTimeCallbackError::WhiteboxCallback {
                message: source.to_string(),
            }
        })?;
        if control_boundary_requested {
            // The exact resume callback remains the sole authority for a
            // host-selected guest-memory write. Settle that reply before the
            // control boundary, but retain halt tracking and the published
            // future idle deadline until the control callback acknowledges it.
            return Ok(());
        }
        let was_halted = {
            let mut halted_vcpus = self.try_halted_vcpus()?;
            let was_halted = halted_vcpus
                .is_halted(vcpu_index)
                .map_err(|source| LiveVcpuTimeCallbackError::VcpuHaltTracking { source })?;
            halted_vcpus
                .mark_running(vcpu_index)
                .map_err(|source| LiveVcpuTimeCallbackError::VcpuHaltTracking { source })?;
            was_halted
        };
        if !was_halted {
            return Ok(());
        }
        self.all_halted_idle_handled.store(false, Ordering::Release);
        // A resume from the all-halted idle path precedes RR-owner selection,
        // so cross-vCPU capture is no safer here than in the matching idle
        // callback. Publish progress now and let the host's BQL-held terminal
        // boundary own the fingerprint.
        self.publish_current_icount_for_boundary(raw_icount, true, "vcpu-resume")?;
        PluginShmemOrdering::mark_running_after_wake(self.slot.get());
        Ok(())
    }

    fn on_control_boundary(&self, raw_icount: u64) -> Result<(), LiveVcpuTimeCallbackError> {
        // A drained wake is an exact host-control opportunity, not a vCPU
        // lifecycle transition. Publish before the release acknowledgement so
        // a host acquire-load of the odd successor orders every boundary field.
        // Halt tracking and idle publication remain owned by the real
        // idle/resume callbacks.
        let control_boundary = self.slot.get().snapshot();
        if control_boundary.control_boundary_ack & 1 != 0 {
            let _fault_pump_drained = self.pump_fault_commands(raw_icount)?;
            return Ok(());
        }

        let control_request = control_boundary.control_boundary_ack;
        let fault_command_frontier = control_boundary.control_boundary_fault_command_frontier;
        let fingerprint_capture_request = match control_boundary.control_boundary_capture_request {
            0 => None,
            request => Some(request),
        };
        let observed_capture_request = self
            .fingerprint
            .as_ref()
            .and_then(|fingerprint| fingerprint.slot.get().pending_capture_request_v1());
        if observed_capture_request != fingerprint_capture_request {
            return Err(
                LiveVcpuTimeCallbackError::ControlBoundaryCaptureRequestMismatch {
                    bound: fingerprint_capture_request,
                    observed: observed_capture_request,
                },
            );
        }

        // The host binds this request to an immutable producer frontier. Submit
        // exactly those commands, commit all mutations due at this coordinate,
        // and publish every resulting record before observing machine state.
        // Any backpressure or concurrent producer advance leaves the request
        // outstanding without a capture, pause, or acknowledgement.
        if !self.settle_fault_commands_at_control_boundary(
            raw_icount,
            control_request,
            fault_command_frontier,
        )? {
            return Ok(());
        }
        let paused = self.publish_pause_for_boundary(
            raw_icount,
            true,
            true,
            fingerprint_capture_request,
            "control-boundary",
        )?;
        if !paused {
            let current_icount = self.logical_icount_for_raw(raw_icount)?;
            let (ceiling_icount, _) = self.scheduler_advance()?;
            if current_icount > ceiling_icount {
                return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                    current_icount,
                    ceiling_icount,
                });
            }
            if self.fingerprint.is_some()
                && let Some(capture_request) = fingerprint_capture_request
            {
                // The main-loop callback holds the BQL after every vCPU has
                // quiesced, making cross-vCPU register capture safe even when
                // the serialized RR owner is intentionally absent at idle.
                self.publish_fingerprint_sample(
                    current_icount,
                    "requested-control-boundary",
                    capture_request,
                )?;
            }
            PluginShmemOrdering::publish_control_boundary(
                self.slot.get(),
                current_icount,
                raw_icount,
            )
            .map_err(|source| LiveVcpuTimeCallbackError::PublishIcount { source })?;
            self.last_raw_icount.store(raw_icount, Ordering::Release);
            self.last_icount.store(current_icount, Ordering::Release);

            // Returning from the all-halted callback for an ordinary control
            // boundary ends that invocation without a real vCPU resume. Re-arm
            // the plugin-side all-halted edge so the RR loop can enter a fresh
            // idle wait and consume the next scheduler ceiling. A checkpoint
            // pause deliberately remains armed until QEMU is resumed through
            // the lifecycle control path.
            self.all_halted_idle_handled.store(false, Ordering::Release);
        }
        PluginShmemOrdering::acknowledge_control_boundary(self.slot.get());
        self.control_boundary_dispatch_generation
            .store(u32::MAX, Ordering::Release);
        Ok(())
    }

    #[cfg(test)]
    fn publish_current_icount(&self, raw_icount: u64) -> Result<(), LiveVcpuTimeCallbackError> {
        self.publish_current_icount_for_boundary(raw_icount, true, "progress-publication")
    }

    fn publish_current_icount_for_boundary(
        &self,
        raw_icount: u64,
        checkpoint_handoff: bool,
        boundary: &'static str,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.publish_pause_for_boundary(raw_icount, checkpoint_handoff, false, None, boundary)? {
            return Ok(());
        }
        let raw_icount_at_entry = self.last_raw_icount.load(Ordering::Acquire);
        let _fault_pump_drained = self.pump_fault_commands(raw_icount)?;
        let latest_raw_icount = self.last_raw_icount.load(Ordering::Acquire);
        if raw_icount_publication_is_superseded(raw_icount_at_entry, raw_icount, latest_raw_icount)?
        {
            // A QEMU mutation may synchronously re-enter the sim loop and
            // publish a newer exact boundary before the outer callback resumes.
            // The older callback has no remaining state to commit.
            return Ok(());
        }
        if self.pending_idle_advance_clamp(raw_icount)?.is_some() {
            return Ok(());
        }
        let current_icount = self.logical_icount_for_raw(raw_icount)?;
        let (ceiling_icount, _) = self.scheduler_advance()?;
        if current_icount > ceiling_icount {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount,
                ceiling_icount,
            });
        }
        let passed_delivery_floor_icount = self.last_icount.load(Ordering::Acquire);
        self.inject_due_network_inbound(current_icount, passed_delivery_floor_icount)?;
        PluginShmemOrdering::publish_reached_icount(self.slot.get(), current_icount)
            .map_err(|source| LiveVcpuTimeCallbackError::PublishIcount { source })?;
        self.last_raw_icount.store(raw_icount, Ordering::Release);
        self.last_icount.store(current_icount, Ordering::Release);
        Ok(())
    }

    fn publish_pause_for_boundary(
        &self,
        raw_icount: u64,
        checkpoint_handoff: bool,
        control_boundary_dispatch: bool,
        fingerprint_capture_request: Option<u32>,
        boundary: &'static str,
    ) -> Result<bool, LiveVcpuTimeCallbackError> {
        self.restore_logical_time_if_requested(raw_icount, true)?;
        match PluginShmemOrdering::observe_control_action(self.header.get()) {
            RegionControlAction::Shutdown => {
                self.signal_shared_shutdown()?;
                Ok(true)
            }
            RegionControlAction::Pause => {
                // A paired control request owns checkpoint ordering. Its
                // eventfd callback first resumes device waiters, then invokes
                // the two-pass control boundary after their bottom halves are
                // visible. Futex, vCPU, and device callbacks must fence guest
                // progress but defer publication and native stop to that final
                // callback; stopping here can strand a newly active coroutine.
                if PluginShmemOrdering::control_boundary_is_requested(self.slot.get())
                    && !control_boundary_dispatch
                {
                    return Ok(true);
                }
                if PluginShmemOrdering::device_io_active(self.slot.get()) {
                    return Ok(true);
                }
                let previous_raw_icount = self.last_raw_icount.load(Ordering::Acquire);
                if raw_icount < previous_raw_icount {
                    return Err(LiveVcpuTimeCallbackError::IcountRegressed {
                        previous_icount: previous_raw_icount,
                        current_icount: raw_icount,
                    });
                }
                let current_icount = self.logical_icount_for_raw(raw_icount)?;
                let (ceiling_icount, _) = self.scheduler_advance()?;
                if current_icount > ceiling_icount {
                    return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                        current_icount,
                        ceiling_icount,
                    });
                }
                if self.fingerprint.is_some()
                    && let Some(capture_request) = fingerprint_capture_request
                {
                    self.publish_fingerprint_sample(current_icount, boundary, capture_request)?;
                }
                PluginShmemOrdering::publish_pause_quiesced(
                    self.slot.get(),
                    current_icount,
                    raw_icount,
                )
                .map_err(|source| LiveVcpuTimeCallbackError::PublishPause { source })?;
                self.last_raw_icount.store(raw_icount, Ordering::Release);
                self.last_icount.store(current_icount, Ordering::Release);
                if checkpoint_handoff {
                    self.request_checkpoint_vmstop(boundary)?;
                }
                Ok(true)
            }
            RegionControlAction::Continue => Ok(false),
        }
    }

    /// Requests QEMU's native stopped runstate after publishing the boundary.
    fn request_checkpoint_vmstop(
        &self,
        boundary: &'static str,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let status = (self.request_vmstop)();
        // Multiple exact callbacks can observe the same level-triggered pause
        // before QEMU's main loop consumes the first admitted stop request.
        // QEMU reports that race as -EALREADY; the required stop is already
        // fenced and queued, so this callback has satisfied its handoff too.
        const NEGATIVE_EALREADY: i32 = -114;
        if status == 0 || status == NEGATIVE_EALREADY {
            Ok(())
        } else {
            Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected { boundary, status })
        }
    }

    /// Publishes and admits a doorbell-deferred stop from this exact callback.
    fn request_selectable_vmstop_if_pending(
        &self,
        raw_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let Some(kind) = self.selectable_vmstop.claim() else {
            return Ok(());
        };

        let result = (|| {
            let current_icount = self.logical_icount_for_raw(raw_icount)?;
            let (ceiling_icount, _) = self.scheduler_advance()?;
            if current_icount > ceiling_icount {
                return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                    current_icount,
                    ceiling_icount,
                });
            }
            if kind == DeferredVmstopKind::Selectable {
                rebind_selectable_pending_boundary(current_icount).map_err(|source| {
                    LiveVcpuTimeCallbackError::WhiteboxCallback {
                        message: source.to_string(),
                    }
                })?;
            }
            PluginShmemOrdering::publish_pause_quiesced(
                self.slot.get(),
                current_icount,
                raw_icount,
            )
            .map_err(|source| LiveVcpuTimeCallbackError::PublishPause { source })?;
            self.last_raw_icount.store(raw_icount, Ordering::Release);
            self.last_icount.store(current_icount, Ordering::Release);
            let boundary = match kind {
                DeferredVmstopKind::Selectable => "selectable-sim-publication",
                DeferredVmstopKind::CampaignMarker => "campaign-marker-sim-publication",
            };
            self.request_checkpoint_vmstop(boundary)
        })();
        if let Err(error) = result {
            self.selectable_vmstop.restore(kind);
            return Err(error);
        }
        Ok(())
    }

    /// Shares the process-local handoff with the sibling white-box callback.
    pub(crate) fn selectable_vmstop_handoff(&self) -> Arc<SelectableVmstopHandoff> {
        Arc::clone(&self.selectable_vmstop)
    }

    /// Shares the restore-adjusted raw-to-logical icount calibration.
    pub(crate) fn logical_icount_offset(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.logical_icount_offset)
    }

    fn arm_idle_advance(
        &self,
        raw_icount_at_request: u64,
        target_icount: u64,
        pending: PendingIdleAdvance,
        timer_deadline_ps: Option<u64>,
    ) -> Result<IdleAdvanceArmOutcome, LiveVcpuTimeCallbackError> {
        let mut pending_slot = match self.pending_idle_advance.try_lock() {
            Ok(pending_slot) => pending_slot,
            Err(TryLockError::WouldBlock) => return Ok(IdleAdvanceArmOutcome::Occupied),
            Err(TryLockError::Poisoned(_error)) => {
                return Err(LiveVcpuTimeCallbackError::CallbackStatePoisoned);
            }
        };
        if pending_slot.is_some() {
            return Ok(IdleAdvanceArmOutcome::Occupied);
        }
        let observed_raw_icount = self.last_raw_icount.load(Ordering::Acquire);
        if observed_raw_icount != raw_icount_at_request {
            return Err(LiveVcpuTimeCallbackError::IdleAdvanceRawIcountChanged {
                expected_raw_icount: raw_icount_at_request,
                observed_raw_icount,
            });
        }
        let current_icount = self.last_icount.load(Ordering::Acquire);
        if target_icount < current_icount {
            return Err(LiveVcpuTimeCallbackError::IdleAdvanceTargetRegressed {
                current_icount,
                target_icount,
            });
        }
        let target_tick = target_icount;
        if target_tick != pending.target_tick() {
            return Err(
                LiveVcpuTimeCallbackError::IdleAdvancePendingTargetMismatch {
                    target_icount,
                    expected_target_tick: target_tick,
                    pending_target_tick: pending.target_tick(),
                },
            );
        }
        let ceiling_icount = self.scheduler_idle_ceiling(target_icount)?;
        if target_icount > ceiling_icount {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount: target_icount,
                ceiling_icount,
            });
        }

        // Wrapping remains unique among live requests because this slot admits
        // only one generation at a time.
        let generation = self.idle_advance_generation.fetch_add(1, Ordering::Relaxed);
        let timer_witness = timer_deadline_ps
            .map(|deadline_ps| self.virtual_timer_witness.arm(deadline_ps, target_icount))
            .transpose()
            .map_err(|source| LiveVcpuTimeCallbackError::VirtualTimerWitness { source })?;
        *pending_slot = Some(LivePendingIdleAdvance {
            generation,
            raw_icount_at_request,
            target_icount,
            pending,
            timer_witness,
            buffered_tx_payloads: Vec::new(),
        });
        self.pending_idle_advance_raw_icount
            .store(raw_icount_at_request, Ordering::Relaxed);
        self.pending_idle_advance_target_icount
            .store(target_icount, Ordering::Relaxed);
        self.pending_idle_advance_active
            .store(true, Ordering::Release);
        Ok(IdleAdvanceArmOutcome::Armed { generation })
    }

    fn complete_idle_advance(
        &self,
        completion: TimeAdvanceCompletion,
    ) -> Result<u64, LiveVcpuTimeCallbackError> {
        if self
            .idle_advance_completion_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletionReentered);
        }
        let _completion_active = IdleAdvanceCompletionGuard(&self.idle_advance_completion_active);
        let (target_icount, logical_icount_offset) = {
            let pending_slot = self.try_pending_idle_advance()?;
            let pending = pending_slot
                .as_ref()
                .ok_or(LiveVcpuTimeCallbackError::IdleAdvanceCompletionWithoutPending)?;
            pending
                .pending
                .validate_completion(completion)
                .map_err(|source| LiveVcpuTimeCallbackError::IdleAdvanceCompletion { source })?;

            let observed_raw_icount = self.last_raw_icount.load(Ordering::Acquire);
            if observed_raw_icount != pending.raw_icount_at_request {
                return Err(LiveVcpuTimeCallbackError::IdleAdvanceRawIcountChanged {
                    expected_raw_icount: pending.raw_icount_at_request,
                    observed_raw_icount,
                });
            }
            if let Some(timer_witness) = pending.timer_witness {
                let evidence = self
                    .virtual_timer_witness
                    .query_completed(
                        timer_witness,
                        pending.raw_icount_at_request,
                        pending.pending.target_tick(),
                    )
                    .map_err(|source| LiveVcpuTimeCallbackError::VirtualTimerWitness { source })?;
                PluginShmemOrdering::publish_virtual_timer_witness(
                    self.slot.get(),
                    evidence.into_shared(),
                );
            }
            let logical_icount_offset = pending
                .target_icount
                .checked_sub(
                    observed_raw_icount
                        .checked_mul(crucible_shmem::TICKS_PER_INSTRUCTION)
                        .ok_or(LiveVcpuTimeCallbackError::IdleAdvanceOffsetUnderflow {
                            raw_icount: observed_raw_icount,
                            target_icount: pending.target_icount,
                        })?,
                )
                .ok_or(LiveVcpuTimeCallbackError::IdleAdvanceOffsetUnderflow {
                    raw_icount: observed_raw_icount,
                    target_icount: pending.target_icount,
                })?;
            if let Some(network) = self.network.as_ref() {
                let outbound = network.outbound.outbound();
                network
                    .tx
                    .preflight_guest_frame_batch(&outbound, pending.buffered_tx_payloads.len())
                    .map_err(|source| LiveVcpuTimeCallbackError::NetworkTx { source })?;
            }
            (pending.target_icount, logical_icount_offset)
        };
        let ceiling_icount = self.scheduler_idle_ceiling(target_icount)?;
        if target_icount > ceiling_icount {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount: target_icount,
                ceiling_icount,
            });
        }

        // QEMU RX injection may synchronously invoke another plugin callback.
        // Keep the pending token armed, but release its mutex and every mutable
        // ring view before crossing that boundary.
        let passed_delivery_floor_icount = self.last_icount.load(Ordering::Acquire);
        self.inject_due_network_inbound(target_icount, passed_delivery_floor_icount)?;

        // Time-advance completion can run without the BQL and with no serialized
        // RR owner. Even when it lands exactly on the ceiling, cross-vCPU
        // fingerprint capture is unsafe here. The host requests a BQL-held
        // control boundary after accepting the completed quantum.

        // Reacquire after callback-capable work so TX emitted by the guest while
        // RX was flushed joins the same deterministic idle-completion batch.
        let mut pending_slot = self.try_pending_idle_advance()?;
        let pending = pending_slot
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::IdleAdvanceCompletionWithoutPending)?;
        pending
            .pending
            .validate_completion(completion)
            .map_err(|source| LiveVcpuTimeCallbackError::IdleAdvanceCompletion { source })?;
        if let Some(network) = self.network.as_ref() {
            let mut outbound = network.outbound.outbound();
            network
                .tx
                .preflight_guest_frame_batch(&outbound, pending.buffered_tx_payloads.len())
                .map_err(|source| LiveVcpuTimeCallbackError::NetworkTx { source })?;
            network
                .tx
                .enqueue_guest_frame_batch(
                    &mut outbound,
                    target_icount,
                    &pending.buffered_tx_payloads,
                )
                .map_err(|source| LiveVcpuTimeCallbackError::NetworkTx { source })?;
        }

        self.logical_icount_offset
            .store(logical_icount_offset, Ordering::Release);
        if self.sim_tick_observed.is_some() {
            let observed_icount =
                self.logical_icount_for_raw(self.last_raw_icount.load(Ordering::Acquire))?;
            if observed_icount != target_icount {
                return Err(LiveVcpuTimeCallbackError::SimTickTargetMismatch {
                    target_icount,
                    observed_icount,
                });
            }
        }
        self.last_icount.store(target_icount, Ordering::Release);
        *pending_slot = None;
        self.pending_idle_advance_active
            .store(false, Ordering::Release);
        drop(pending_slot);
        self.all_halted_idle_handled.store(false, Ordering::Release);
        // Publish the reached coordinate only after clearing the pending token.
        // The host treats this release-published coordinate as permission to
        // expose a due device response and wake its coroutine. Publishing first
        // would let that wake re-enter QEMU while this callback still considered
        // the queued idle advance pending.
        PluginShmemOrdering::publish_reached_icount(self.slot.get(), target_icount)
            .map_err(|source| LiveVcpuTimeCallbackError::PublishIcount { source })?;
        Ok(target_icount)
    }

    /// Injects and commits every router frame due at this guest boundary.
    ///
    /// The plugin is the only consumer of the router-to-VM SPSC ring. The host
    /// may observe the consumer index after a release-published boundary, but it
    /// must never dequeue a payload. Previewing before the callback and
    /// comparing the committed batch afterwards keeps reentrant QEMU RX work
    /// from changing which deterministic delivery keys this boundary owns.
    fn inject_due_network_inbound(
        &self,
        current_icount: u64,
        passed_delivery_floor_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let Some(network) = self.network.as_ref() else {
            return Ok(());
        };
        if network
            .rx_delivery_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Direct QEMU RX can synchronously re-enter a progress callback.
            // The outer attempt still owns the canonical ring head, so the
            // nested callback must not deliver that same frame recursively.
            return Ok(());
        }
        let _active = NetworkRxDeliveryActiveGuard(&network.rx_delivery_active);
        let preview = {
            let inbound = network.inbound.inbound();
            PluginInboundFrames::preview_deliverable_since(
                [inbound],
                current_icount,
                passed_delivery_floor_icount,
            )
            .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?
        };
        let injection = if preview.frames().is_empty() {
            None
        } else {
            let mut rx_queue = network.rx_queue;
            Some(
                handle_network_rx_idle_callback(
                    &network.rx,
                    &mut rx_queue,
                    passed_delivery_floor_icount,
                    current_icount,
                    preview.frames(),
                )
                .map_err(|source| LiveVcpuTimeCallbackError::NetworkRx { source })?,
            )
        };
        let delivered_count = injection
            .as_ref()
            .map_or(0, |result| result.delivered_frame_keys().len());
        let delivered_frames = &preview.frames()[..delivered_count];
        if injection.as_ref().is_some_and(|result| {
            result.delivered_frame_keys()
                != delivered_frames
                    .iter()
                    .map(FrameEntry::delivery_key)
                    .collect::<Vec<_>>()
        }) {
            return Err(LiveVcpuTimeCallbackError::InboundCommitMismatch);
        }
        let inbound = network.inbound.inbound();
        let committed = PluginInboundFrames::commit_delivered_prefix(
            [inbound],
            current_icount,
            delivered_frames,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?;
        if committed.frames() != delivered_frames {
            return Err(LiveVcpuTimeCallbackError::InboundCommitMismatch);
        }
        if let Some(retained) = injection.and_then(|result| result.retained_frame_key()) {
            let inbound = network.inbound.inbound();
            PluginInboundFrames::mark_retained_head([inbound], retained, current_icount)
                .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?;
        }
        Ok(())
    }

    fn on_network_tx(
        &self,
        raw_emit_icount: u64,
        payload: &[u8],
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let network = self
            .network
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::NetworkStateUnavailable)?;
        if network
            .tx_callback_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(LiveVcpuTimeCallbackError::NetworkTxReentered);
        }
        let _active = NetworkTxActiveGuard(&network.tx_callback_active);
        let mut pending_slot = self.try_pending_idle_advance()?;
        if let Some(pending) = pending_slot.as_mut() {
            FrameEntry::new(pending.target_icount, network.tx.src_slot(), 0, payload).map_err(
                |crucible_shmem::FrameEntryError::PayloadLengthExceedsCapacity {
                     len,
                     capacity,
                 }| {
                    LiveVcpuTimeCallbackError::NetworkTx {
                        source: NetworkTxError::PayloadTooLarge { len, capacity },
                    }
                },
            )?;
            let outbound = network.outbound.outbound();
            let batch_len = pending
                .buffered_tx_payloads
                .len()
                .checked_add(1)
                .ok_or(LiveVcpuTimeCallbackError::BufferedNetworkTxCountOverflow)?;
            network
                .tx
                .preflight_guest_frame_batch(&outbound, batch_len)
                .map_err(|source| LiveVcpuTimeCallbackError::NetworkTx { source })?;
            pending.buffered_tx_payloads.push(payload.to_vec());
            return Ok(());
        }
        drop(pending_slot);

        let mut outbound = network.outbound.outbound();
        let current_icount = self.callback_supplied_raw_icount_without_pause(raw_emit_icount)?;
        network
            .tx
            .enqueue_guest_frame(&mut outbound, current_icount, payload)
            .map(|_enqueue| ())
            .map_err(|source| LiveVcpuTimeCallbackError::NetworkTx { source })
    }

    fn on_block_wait(&self, _request_id: u32) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.idle_advance_is_pending() {
            return Ok(());
        }

        let current_icount = self.callback_current_icount_without_pause()?;
        let device_deadline = PluginShmemOrdering::device_completion_deadline_tick(self.slot.get());
        if device_deadline == 0 {
            // The host publishes the deterministic deadline before signalling
            // the wake fd. QEMU re-fires this callback after that wake, so this
            // wall-time race changes only how long the coroutine stays parked.
            return Ok(());
        }
        let ceiling_icount = self.scheduler_idle_ceiling(device_deadline)?;
        let exact_deadline = self
            .exact_deadline
            .read_next_deadline()
            .map_err(|source| LiveVcpuTimeCallbackError::ExactDeadlineRead { source })?;
        let plan = compute_idle_wake_plan(
            current_icount,
            exact_deadline,
            None,
            SchedulerCeiling::new(ceiling_icount),
            true,
            Some(device_deadline),
        )
        .map_err(|source| LiveVcpuTimeCallbackError::IdleHotLoop { source })?;
        // A block coroutine can park before the vCPU gets another opportunity
        // to query `max_advance_icount`. Advance only to the currently authorized
        // scheduler boundary when the device completion lies in a later quantum;
        // the host wake after publishing that later ceiling re-fires this hook.
        let target_icount = plan.desired_wake_icount().min(ceiling_icount);
        if target_icount <= current_icount {
            // Virtual time already admits the response. If its ring write is
            // still physically pending, the next host wake retries the poll at
            // this same icount without exposing host timing to the guest.
            return Ok(());
        }
        self.arm_and_enqueue_idle_advance_or_defer(
            self.last_raw_icount.load(Ordering::Acquire),
            target_icount,
            None,
        )?;
        Ok(())
    }

    /// Publishes and enqueues an idle advance, or defers behind QEMU's barrier.
    ///
    /// QEMU notifies every idle and device waiter after releasing an accepted
    /// advance, so `-EBUSY` means this callback can park and recompute its target
    /// on that deterministic retry. Guest execution remains frozen by the
    /// outstanding barrier in the meantime.
    fn arm_and_enqueue_idle_advance_or_defer(
        &self,
        raw_icount_at_request: u64,
        target_icount: u64,
        timer_deadline_ps: Option<u64>,
    ) -> Result<bool, LiveVcpuTimeCallbackError> {
        let prepared = self
            .queued_idle_advance
            .prepare(target_icount)
            .map_err(|source| LiveVcpuTimeCallbackError::QueuedIdleAdvance { source })?;
        let pending = prepared.pending();

        // The QEMU enqueue schedules completion on the normal main loop. Make
        // its exact identity visible first because that loop can run as soon as
        // the vCPU callback releases the BQL, before the enqueue call returns.
        let generation = match self.arm_idle_advance(
            raw_icount_at_request,
            target_icount,
            pending,
            timer_deadline_ps,
        )? {
            IdleAdvanceArmOutcome::Armed { generation } => generation,
            IdleAdvanceArmOutcome::Occupied => return Ok(false),
        };
        match self.queued_idle_advance.enqueue_prepared(prepared) {
            Ok(()) => Ok(true),
            Err(QueuedIdleAdvanceError::EnqueueRejected { status, .. })
                if status == -libc::EBUSY =>
            {
                self.rollback_idle_advance(
                    generation,
                    raw_icount_at_request,
                    target_icount,
                    pending,
                )?;
                Ok(false)
            }
            Err(source) => {
                self.rollback_idle_advance(
                    generation,
                    raw_icount_at_request,
                    target_icount,
                    pending,
                )?;
                Err(LiveVcpuTimeCallbackError::QueuedIdleAdvance { source })
            }
        }
    }

    /// Removes the exact prepublished identity after QEMU rejects its enqueue.
    fn rollback_idle_advance(
        &self,
        generation: u64,
        raw_icount_at_request: u64,
        target_icount: u64,
        pending: PendingIdleAdvance,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let mut pending_slot = self.try_pending_idle_advance()?;
        let Some(armed) = pending_slot.as_ref() else {
            return Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletionWithoutPending);
        };
        if armed.generation != generation
            || armed.raw_icount_at_request != raw_icount_at_request
            || armed.target_icount != target_icount
            || armed.pending != pending
        {
            return Err(LiveVcpuTimeCallbackError::IdleAdvanceAlreadyPending);
        }

        *pending_slot = None;
        self.pending_idle_advance_active
            .store(false, Ordering::Release);
        Ok(())
    }

    fn callback_current_icount(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        self.callback_current_icount_without_pause()
    }

    /// Samples callback time without publishing a pause acknowledgement.
    ///
    /// Device callbacks can be nested inside operations that QEMU must drain
    /// before entering paused runstate. They first finish work already admitted
    /// by the scheduler; the completion callback that clears the final active
    /// marker then acknowledges and hands off a pending checkpoint pause.
    fn callback_current_icount_without_pause(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        // Capture the publication coordinate before sampling QEMU. Another
        // exact callback can finish between the raw read and our commit. In
        // that case its newer publication supersedes this callback; loading
        // the baseline after sampling would misclassify the overlap as a real
        // QEMU clock regression.
        let raw_icount_at_entry = self.last_raw_icount.load(Ordering::Acquire);
        let raw_icount = (self.icount_raw)();
        self.publish_callback_icount_without_pause(raw_icount_at_entry, raw_icount)
    }

    /// Publishes a device coordinate supplied atomically by QEMU.
    ///
    /// Network TX crosses from QEMU with the raw icount committed at the
    /// synchronous virtio device boundary. Re-sampling after entering Rust can
    /// otherwise observe a later translation-block accounting state after a
    /// cold VMState restore.
    fn callback_supplied_raw_icount_without_pause(
        &self,
        raw_icount: u64,
    ) -> Result<u64, LiveVcpuTimeCallbackError> {
        let raw_icount_at_entry = self.last_raw_icount.load(Ordering::Acquire);
        self.publish_callback_icount_without_pause(raw_icount_at_entry, raw_icount)
    }

    fn publish_callback_icount_without_pause(
        &self,
        raw_icount_at_entry: u64,
        raw_icount: u64,
    ) -> Result<u64, LiveVcpuTimeCallbackError> {
        // Device callbacks run before the two-pass control boundary. They need
        // the restored offset to interpret raw QEMU time, but acknowledging the
        // transaction here would expose an intermediate RUNNING publication to
        // the host before the exact pause callback publishes quiescence.
        self.restore_logical_time_if_requested(raw_icount, false)?;
        let latest_raw_icount = self.last_raw_icount.load(Ordering::Acquire);
        if raw_icount_publication_is_superseded(raw_icount_at_entry, raw_icount, latest_raw_icount)?
        {
            return self.logical_icount_for_raw(latest_raw_icount);
        }
        let current_icount = self.logical_icount_for_raw(raw_icount)?;
        let (ceiling_icount, _) = self.scheduler_advance()?;
        if current_icount > ceiling_icount {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount,
                ceiling_icount,
            });
        }
        PluginShmemOrdering::publish_reached_icount(self.slot.get(), current_icount)
            .map_err(|source| LiveVcpuTimeCallbackError::PublishIcount { source })?;
        self.last_raw_icount.store(raw_icount, Ordering::Release);
        self.last_icount.store(current_icount, Ordering::Release);
        Ok(current_icount)
    }

    /// Publishes a deferred checkpoint pause after device completion quiesces.
    fn publish_device_completion_pause_if_quiesced(
        &self,
        boundary: &'static str,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        if !PluginShmemOrdering::device_io_active(self.slot.get()) {
            let raw_icount = (self.icount_raw)();
            let _pause_observed =
                self.publish_pause_for_boundary(raw_icount, true, false, None, boundary)?;
        }
        Ok(())
    }

    /// Returns the logical icount for a device callback dispatched from QEMU's
    /// main-loop timer boundary.
    ///
    /// QEMU runs timer-produced bottom halves before the queued idle-advance
    /// completion callback. The authoritative QEMU tick already includes that
    /// advance even though the plugin has not committed its local offset yet.
    fn device_callback_icount(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        if self.sim_tick_observed.is_some() {
            return self.logical_icount_for_raw((self.icount_raw)());
        }
        if self.pending_idle_advance_active.load(Ordering::Acquire) {
            return Ok(self
                .pending_idle_advance_target_icount
                .load(Ordering::Acquire));
        }
        self.callback_current_icount()
    }

    fn logical_icount_for_raw(&self, raw_icount: u64) -> Result<u64, LiveVcpuTimeCallbackError> {
        if let Some(observe_tick) = self.sim_tick_observed {
            let observed_tick = observe_tick();
            let logical_icount = u64::try_from(observed_tick).map_err(|_error| {
                LiveVcpuTimeCallbackError::InvalidSimTickObservation { observed_tick }
            })?;
            let offset = raw_icount
                .checked_mul(crucible_shmem::TICKS_PER_INSTRUCTION)
                .and_then(|raw_tick| logical_icount.checked_sub(raw_tick))
                .ok_or(LiveVcpuTimeCallbackError::InitialRawIcountBeyondLogical {
                    raw_icount,
                    logical_icount,
                })?;
            self.logical_icount_offset.store(offset, Ordering::Release);
            return Ok(logical_icount);
        }
        let offset = self.logical_icount_offset.load(Ordering::Acquire);
        raw_icount
            .checked_mul(crucible_shmem::TICKS_PER_INSTRUCTION)
            .and_then(|raw_tick| raw_tick.checked_add(offset))
            .ok_or(LiveVcpuTimeCallbackError::LogicalIcountOverflow { raw_icount, offset })
    }

    fn fault_offset_for_raw(
        &self,
        raw_icount: u64,
    ) -> Result<u64, crate::fault_command::FaultCommandBridgeError> {
        let Some(observe_tick) = self.sim_tick_observed else {
            return Ok(self.logical_icount_offset.load(Ordering::Acquire));
        };
        let observed_tick = observe_tick();
        let offset = u64::try_from(observed_tick)
            .ok()
            .and_then(|tick| {
                raw_icount
                    .checked_mul(crucible_shmem::TICKS_PER_INSTRUCTION)
                    .and_then(|raw_tick| tick.checked_sub(raw_tick))
            })
            .ok_or(
                crate::fault_command::FaultCommandBridgeError::InvalidSimTickObservation {
                    observed_tick,
                    raw_icount,
                },
            )?;
        self.logical_icount_offset.store(offset, Ordering::Release);
        Ok(offset)
    }

    fn try_pending_idle_advance(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<LivePendingIdleAdvance>>, LiveVcpuTimeCallbackError>
    {
        match self.pending_idle_advance.try_lock() {
            Ok(pending) => Ok(pending),
            Err(TryLockError::WouldBlock) => {
                Err(LiveVcpuTimeCallbackError::PendingIdleAdvanceBorrowed)
            }
            Err(TryLockError::Poisoned(_error)) => {
                Err(LiveVcpuTimeCallbackError::CallbackStatePoisoned)
            }
        }
    }

    fn try_halted_vcpus(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, VcpuHaltTracker>, LiveVcpuTimeCallbackError> {
        match self.halted_vcpus.try_lock() {
            Ok(halted_vcpus) => Ok(halted_vcpus),
            Err(TryLockError::WouldBlock) => Err(LiveVcpuTimeCallbackError::HaltStateBorrowed),
            Err(TryLockError::Poisoned(_error)) => {
                Err(LiveVcpuTimeCallbackError::HaltStatePoisoned)
            }
        }
    }

    /// Returns the scheduler ceiling expressed in raw retired-instruction units.
    ///
    /// QEMU's sim-loop budget clamp compares this value against
    /// `qemu_plugin_icount_raw()` (raw retired instructions), whereas the
    /// scheduler ceiling published in shared memory is a *logical* icount that
    /// includes the accumulated idle-jump offset (`logical = raw + offset`). The
    /// clamp only stops the guest at the authorized horizon when both operands
    /// share a space, so the logical ceiling is translated back to raw by
    /// subtracting the current offset. On the busy path the offset is zero and
    /// this is the ceiling unchanged; after an idle jump advanced virtual time
    /// without retiring instructions, the offset is positive and this stops the
    /// guest from retiring instructions past its logical authorization.
    /// Returns how far QEMU's sim loop may advance the guest, in raw icount.
    ///
    /// This is the callback the live TCG sim loop actually queries to bound a
    /// running guest (registered via `register_sim_shmem_dispatch`); it is the
    /// live advance seam, not [`compute_idle_wake_plan`], which the sim loop
    /// never calls. The budget is the scheduler ceiling minus this node's
    /// logical icount offset.
    ///
    /// When a device-I/O request is in flight, the budget freezes at the current
    /// coordinate until the host publishes the deterministic completion
    /// deadline, then advances at most to that deadline. This closes the
    /// request-observation race: host wall time may delay publication, but the
    /// guest cannot retire instructions between the request callback and the
    /// publication that pins its completion. A past deadline likewise
    /// saturates the budget to zero. A queued time jump similarly freezes the
    /// budget at its raw request coordinate until completion commits the new
    /// logical offset. The distinct case of a guest *halted* on device I/O
    /// (where the sim loop stops querying this callback altogether) is closed
    /// separately by the device-wait callback of the SCHED-8 delivery patch.
    fn max_advance_icount(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        let raw_icount = (self.icount_raw)();
        if self.publish_pause_for_boundary(raw_icount, true, false, None, "max-advance")? {
            return Ok(raw_icount);
        }
        if let Some(raw_icount_at_request) = self.pending_idle_advance_clamp(raw_icount)? {
            return Ok(raw_icount_at_request);
        }
        let _fault_pump_drained = self.pump_fault_commands(raw_icount)?;
        let (ceiling, _) =
            PluginShmemOrdering::load_scheduler_advance(self.slot.get()).map_err(|source| {
                LiveVcpuTimeCallbackError::IdleHotLoop {
                    source: IdleHotLoopError::AdvanceStopCondition { source },
                }
            })?;
        let current_icount = self.logical_icount_for_raw(raw_icount)?;
        let offset = self.logical_icount_offset.load(Ordering::Acquire);
        if current_icount > ceiling {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount,
                ceiling_icount: ceiling,
            });
        }
        let effective_ceiling = if PluginShmemOrdering::device_io_active(self.slot.get()) {
            match PluginShmemOrdering::device_completion_deadline_tick(self.slot.get()) {
                0 => ceiling.min(self.last_icount.load(Ordering::Acquire)),
                deadline => ceiling.min(deadline),
            }
        } else {
            ceiling
        };
        let raw_ceiling =
            effective_ceiling.saturating_sub(offset) / crucible_shmem::TICKS_PER_INSTRUCTION;
        if self
            .preemption_enqueue_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // QEMU validates a newly enqueued command by querying this callback.
            // That nested query must observe the scheduler ceiling without
            // attempting to enqueue the same mailbox command recursively.
            return Ok(raw_ceiling);
        }
        let _guard = PreemptionEnqueueGuard(&self.preemption_enqueue_active);
        let Some(published) = self
            .slot
            .get()
            .pending_preemption_command()
            .map_err(|source| LiveVcpuTimeCallbackError::PreemptionMailbox { source })?
        else {
            return Ok(raw_ceiling);
        };
        let command = published.command;
        let raw_at = logical_preemption_icount_to_raw("at", command.at_tick, offset)?;
        let raw_deadline =
            logical_preemption_icount_to_raw("deadline", command.deadline_tick, offset)?;
        let raw_command_ceiling =
            logical_preemption_icount_to_raw("ceiling", command.ceiling_tick, offset)?;
        if raw_command_ceiling > raw_ceiling {
            // The mailbox is published before the RUN that owns it. Keep the
            // command pending until that RUN's ceiling is visible, then inject
            // it before QEMU may retire past the commanded coordinate.
            return Ok(raw_ceiling);
        }
        let window =
            PreemptionWindow::new(raw_deadline, SchedulerCeiling::new(raw_command_ceiling))
                .map_err(|source| LiveVcpuTimeCallbackError::Preemption { source })?;
        let decision = match command.kind {
            SchedulerPreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                PluginPreemptionDecision::vcpu_switch(raw_at, from_vcpu, to_vcpu)
            }
            SchedulerPreemptionKind::InterruptAt { target_vcpu, irq } => {
                PluginPreemptionDecision::interrupt_at(raw_at, target_vcpu, irq)
            }
        };
        self.preemption_injector
            .enqueue_decision(decision, window, self.vcpu_count)
            .map_err(|source| LiveVcpuTimeCallbackError::Preemption { source })?;
        self.slot
            .get()
            .acknowledge_preemption_command(published.sequence)
            .map_err(|source| LiveVcpuTimeCallbackError::PreemptionMailbox { source })?;
        Ok(raw_ceiling.min(raw_at))
    }

    fn pump_fault_commands(&self, raw_icount: u64) -> Result<bool, LiveVcpuTimeCallbackError> {
        if self
            .fault_command_pump_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Applying a QEMU mutation may synchronously make QEMU query the
            // simulator ceiling. The outer pump still owns the command and
            // result transports, so the nested query must use the already
            // published scheduling state without trying to dequeue again.
            return Ok(true);
        }
        let _pump_active = FaultCommandPumpGuard(&self.fault_command_pump_active);
        let mut bridge = match self.fault_commands.try_lock() {
            Ok(bridge) => bridge,
            Err(TryLockError::WouldBlock) => {
                return Err(LiveVcpuTimeCallbackError::FaultCommandStateBorrowed);
            }
            Err(TryLockError::Poisoned(_error)) => {
                return Err(LiveVcpuTimeCallbackError::CallbackStatePoisoned);
            }
        };
        let bridge = &mut *bridge;
        let drained = bridge
            .pump_with_offset_reader(raw_icount, &|| self.fault_offset_for_raw(raw_icount))
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?;
        self.logical_icount_for_raw(raw_icount)?;
        Ok(drained)
    }

    fn settle_fault_commands_at_control_boundary(
        &self,
        raw_icount: u64,
        control_request: u32,
        fault_command_frontier: u64,
    ) -> Result<bool, LiveVcpuTimeCallbackError> {
        if self
            .fault_command_pump_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.emit_control_boundary_defer_diagnostic(
                raw_icount,
                control_request,
                fault_command_frontier,
                "pump-active",
            );
            return Ok(false);
        }
        let _pump_active = FaultCommandPumpGuard(&self.fault_command_pump_active);
        let mut bridge = match self.fault_commands.try_lock() {
            Ok(bridge) => bridge,
            Err(TryLockError::WouldBlock) => {
                return Err(LiveVcpuTimeCallbackError::FaultCommandStateBorrowed);
            }
            Err(TryLockError::Poisoned(_error)) => {
                return Err(LiveVcpuTimeCallbackError::CallbackStatePoisoned);
            }
        };
        let bridge = &mut *bridge;

        if !bridge
            .pump_through_frontier_with_offset_reader(raw_icount, fault_command_frontier, &|| {
                self.fault_offset_for_raw(raw_icount)
            })
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?
        {
            self.emit_control_boundary_defer_diagnostic(
                raw_icount,
                control_request,
                fault_command_frontier,
                "pump-through-frontier-pending",
            );
            return Ok(false);
        }
        if self
            .control_boundary_dispatch_generation
            .load(Ordering::Acquire)
            != control_request
        {
            bridge
                .dispatch_node_boundary(raw_icount)
                .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?;
            self.control_boundary_dispatch_generation
                .store(control_request, Ordering::Release);
        }
        self.logical_icount_for_raw(raw_icount)?;
        let refreshed_offset = self.logical_icount_offset.load(Ordering::Acquire);
        if !bridge
            .drain_publications(refreshed_offset)
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?
        {
            self.emit_control_boundary_defer_diagnostic(
                raw_icount,
                control_request,
                fault_command_frontier,
                "publication-backpressure",
            );
            return Ok(false);
        }
        let settled = bridge.command_frontier_is_settled(fault_command_frontier);
        if !settled {
            self.emit_control_boundary_defer_diagnostic(
                raw_icount,
                control_request,
                fault_command_frontier,
                "command-frontier-unsettled",
            );
        }
        Ok(settled)
    }

    fn emit_control_boundary_defer_diagnostic(
        &self,
        raw_icount: u64,
        control_request: u32,
        fault_command_frontier: u64,
        reason: &'static str,
    ) {
        if self
            .control_boundary_defer_diagnostic_generation
            .swap(u64::from(control_request), Ordering::AcqRel)
            == u64::from(control_request)
        {
            return;
        }
        let token_after = self.slot.get().snapshot().control_boundary_ack;
        // crucible-lint: allow direct-diagnostic -- this bounded callback record
        // is the only channel that can identify an unacknowledged retry reason.
        let _write_result = std::io::Write::write_fmt(
            &mut std::io::stderr().lock(),
            format_args!(
                "CRUCIBLE-RR-CONTROL-DEFER-V1 reason={reason} raw_icount={raw_icount} token_before={control_request} token_after={token_after} fault_command_frontier={fault_command_frontier}\n"
            ),
        );
    }

    fn initialize_fault_commands(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        let mut bridge = match self.fault_commands.try_lock() {
            Ok(bridge) => bridge,
            Err(TryLockError::WouldBlock) => {
                return Err(LiveVcpuTimeCallbackError::FaultCommandStateBorrowed);
            }
            Err(TryLockError::Poisoned(_error)) => {
                return Err(LiveVcpuTimeCallbackError::CallbackStatePoisoned);
            }
        };
        let bridge = &mut *bridge;
        bridge
            .initialize()
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })
    }

    /// Processes setup-time capability admission before the ready ACK.
    pub(crate) fn admit_fault_capabilities(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        self.initialize_fault_commands()?;
        self.pump_fault_commands((self.icount_raw)()).map(|_| ())
    }

    fn vcpu_flag(&self, vcpu_index: u32) -> Result<&AtomicBool, LiveVcpuTimeCallbackError> {
        self.initialized_vcpus.get(vcpu_index as usize).ok_or(
            LiveVcpuTimeCallbackError::VcpuOutOfRange {
                vcpu_index,
                vcpu_count: self.vcpu_count,
            },
        )
    }

    fn require_initialized_vcpu(&self, vcpu_index: u32) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.vcpu_flag(vcpu_index)?.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(LiveVcpuTimeCallbackError::VcpuNotInitialized { vcpu_index })
        }
    }
}

struct NetworkTxActiveGuard<'a>(&'a AtomicBool);

impl Drop for NetworkTxActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct NetworkRxDeliveryActiveGuard<'a>(&'a AtomicBool);

impl Drop for NetworkRxDeliveryActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_vcpu_init_cb(
    vcpu_index: c_uint,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) = state.on_vcpu_init(vcpu_index) {
        abort_live_callback(error);
    }
}

extern "C" fn crucible_qemu_plugin_live_vcpu_and_whitebox_init_cb(
    vcpu_index: c_uint,
    userdata: *mut c_void,
) {
    crucible_qemu_plugin_live_vcpu_init_cb(vcpu_index, userdata);
    crucible_qemu_plugin_live_whitebox_vcpu_init_cb(vcpu_index, userdata);
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_vcpu_idle_cb(
    vcpu_index: c_uint,
    raw_icount: u64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) = state.on_vcpu_idle(vcpu_index, raw_icount) {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_vcpu_resume_cb(
    vcpu_index: c_uint,
    raw_icount: u64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) = state.on_vcpu_resume(vcpu_index, raw_icount) {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_publish_icount_cb(
    current_icount: u64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    let result = state
        .publish_current_icount_for_boundary(current_icount, true, "sim-publication")
        .and_then(|()| state.request_selectable_vmstop_if_pending(current_icount));
    if let Err(error) = result {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_control_boundary_cb(
    _vcpu_index: u32,
    raw_icount: u64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) = state.on_control_boundary(raw_icount) {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_max_advance_icount_cb(
    userdata: *mut c_void,
) -> u64 {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return state.last_icount.load(Ordering::SeqCst);
    };
    match state.max_advance_icount() {
        Ok(max_advance_icount) => max_advance_icount,
        Err(error) => abort_live_callback(error),
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_logical_ceiling_cb(
    userdata: *mut c_void,
) -> u64 {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return 0;
    };
    match state.logical_ceiling() {
        Ok(ceiling) => ceiling,
        Err(error) => abort_live_callback(error),
    }
}

fn logical_preemption_icount_to_raw(
    field: &'static str,
    logical_icount: u64,
    logical_icount_offset: u64,
) -> Result<u64, LiveVcpuTimeCallbackError> {
    let raw_tick = logical_icount.checked_sub(logical_icount_offset).ok_or(
        LiveVcpuTimeCallbackError::PreemptionIcountBeforeRawOrigin {
            field,
            logical_icount,
            logical_icount_offset,
        },
    )?;
    if !raw_tick.is_multiple_of(crucible_shmem::TICKS_PER_INSTRUCTION) {
        return Err(
            LiveVcpuTimeCallbackError::PreemptionIcountBetweenRetirements {
                field,
                logical_icount,
            },
        );
    }
    Ok(raw_tick / crucible_shmem::TICKS_PER_INSTRUCTION)
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_time_advance_completion_cb(
    status: std::os::raw::c_int,
    target_tick: i64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) =
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(status, target_tick))
    {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_block_wait_cb(
    request_id: u32,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) = state.on_block_wait(request_id) {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_network_tx_cb(
    payload: *const u8,
    payload_len: usize,
    raw_emit_icount: u64,
    userdata: *mut c_void,
) -> std::os::raw::c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    let payload = if payload_len == 0 {
        &[]
    } else {
        let Some(payload) = NonNull::new(payload.cast_mut()) else {
            abort_live_callback(LiveVcpuTimeCallbackError::NullNetworkTxPayload { payload_len });
        };
        // SAFETY: QEMU promises that a non-null callback payload remains
        // readable for `payload_len` bytes until this callback returns.
        unsafe { core::slice::from_raw_parts(payload.as_ptr(), payload_len) }
    };
    if let Err(error) = state.on_network_tx(raw_emit_icount, payload) {
        abort_live_callback(error);
    }
    0
}

fn callback_userdata_or_abort(userdata: *mut c_void) -> &'static LiveVcpuTimeCallbackState {
    let Some(state) = NonNull::new(userdata.cast::<LiveVcpuTimeCallbackState>()) else {
        abort_live_callback(LiveVcpuTimeCallbackError::NullCallbackUserdata);
    };
    // SAFETY: the registrar passes only the pointer to the pinned live callback
    // allocation retained by `OwnedCallbackRuntimeState` for process lifetime.
    unsafe { state.as_ref() }
}

fn abort_live_callback(error: LiveVcpuTimeCallbackError) -> ! {
    use std::io::Write as _;

    let _write_result = writeln!(
        std::io::stderr().lock(),
        "crucible-qemu-plugin: fatal live callback failure: {error}"
    );
    std::process::abort();
}

fn live_callback_registration_error(
    source: LiveVcpuTimeCallbackError,
) -> OwnedCallbackRegistrationError {
    OwnedCallbackRegistrationError::LiveVcpuTime { source }
}

/// An error in live production callback setup or dispatch.
#[cfg(test)]
pub(super) fn clear_live_vcpu_time_state_for_test() {
    LIVE_VCPU_TIME_STATE.store(std::ptr::null_mut(), Ordering::Release);
}

#[cfg(test)]
pub(crate) mod tests;
