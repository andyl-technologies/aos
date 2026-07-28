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
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError, mpsc};
use std::thread::{self, JoinHandle};

use crucible_shmem::{
    DirectedRing, FingerprintSampleSlot, FrameEntry, FutexWaitOutcome, MappedDirectedRingMut,
    MappedSetupRegionAccessError, NodeSlot, NodeSlotError, PreemptionMailboxError,
    RegionControlAction, RegionHeader, RingHeader, SLOT_NET_ROUTER, SchedulerPreemptionKind,
};
use thiserror::Error;

use crate::fingerprint_sampler::CapturedFingerprintSample;
use crate::{
    ExactDeadlineError, ExactDeadlineReader, FingerprintSamplerError, IdleHotLoopError,
    IdleParkRequest, InboundFrameError, InboundFrameRing, NetworkRxError, NetworkTxError,
    NetworkTxRing, PendingIdleAdvance, PluginArgs, PluginFingerprintSampling, PluginInboundFrames,
    PluginNetworkRx, PluginNetworkTx, PluginPreemptionDecision, PluginPreemptionInjector,
    PluginRawStateDump, PluginShmemOrdering, PluginShutdownRequested, PreemptionError,
    PreemptionWindow, QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL, QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL, QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL, QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL, QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL,
    QemuAdvanceTimeNsFn, QemuClockDeadlineFn, QemuForceVcpuExitFn, QemuIcountRawFn,
    QemuLosslessNetworkRxQueue, QemuPluginExecutionModel, QemuPluginId, QemuPluginNetFlushFn,
    QemuPluginNetSendFn, QemuPluginTargetArchitecture, QemuRegisterBlkCbFn,
    QemuRegisterBlkWaitCbFn, QemuRegisterNetTxCbFn, QemuRegisterNinePCbFn,
    QemuRegisterSimShmemDispatchCbFn, QemuRegisterTimeAdvanceCbFn, QemuRegisterVcpuIdleResumeCbFn,
    QemuRegisterVcpuInitCbFn, QueuedIdleAdvance, QueuedIdleAdvanceError, RoundRobinError,
    SchedulerCeiling, TimeAdvanceCompletion, VcpuHaltTracker, compute_idle_wake_plan,
    handle_network_rx_idle_callback,
};

use super::{
    LiveRuntimeTeardownTrigger, OwnedCallbackRegistrar, OwnedCallbackRegistrationError,
    OwnedCallbackRegistrationMask, OwnedCallbackRuntimeState,
    callback_quiescence::{LiveCallbackInFlight, LiveCallbackQuiescence},
    live_whitebox::{LiveWhiteboxApis, crucible_qemu_plugin_live_whitebox_vcpu_init_cb},
};

mod devices;
pub use devices::LiveDeviceCallbackError;
use devices::LiveDeviceCallbackState;
#[cfg(test)]
mod test_support;

static LIVE_VCPU_TIME_STATE: AtomicPtr<LiveVcpuTimeCallbackState> =
    AtomicPtr::new(std::ptr::null_mut());

/// QEMU capabilities for the joined production callback families.
#[derive(Clone, Copy)]
pub(crate) struct LiveVcpuTimeCallbackCapabilities {
    pub(crate) icount_raw: QemuIcountRawFn,
    pub(crate) force_vcpu_exit: QemuForceVcpuExitFn,
    pub(crate) inject_preemption: Option<crate::QemuInjectPreemptionFn>,
    pub(crate) clock_deadline_ns: Option<QemuClockDeadlineFn>,
    pub(crate) advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    pub(crate) register_vcpu_init: Option<QemuRegisterVcpuInitCbFn>,
    pub(crate) register_vcpu_idle_resume: Option<QemuRegisterVcpuIdleResumeCbFn>,
    pub(crate) register_sim_shmem_dispatch: Option<QemuRegisterSimShmemDispatchCbFn>,
    pub(crate) register_time_advance_cb: Option<QemuRegisterTimeAdvanceCbFn>,
    pub(crate) register_net_tx: Option<QemuRegisterNetTxCbFn>,
    pub(crate) net_send: Option<QemuPluginNetSendFn>,
    pub(crate) net_flush: Option<QemuPluginNetFlushFn>,
    pub(crate) register_block: Option<QemuRegisterBlkCbFn>,
    pub(crate) register_block_wait: Option<QemuRegisterBlkWaitCbFn>,
    pub(crate) register_ninep: Option<QemuRegisterNinePCbFn>,
    pub(crate) request_shutdown: crate::QemuRequestShutdownFn,
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
        let exact_deadline = ExactDeadlineReader::require(self.capabilities.clock_deadline_ns)
            .map_err(|source| LiveVcpuTimeCallbackError::ExactDeadlineCapability { source })?;
        let preemption_injector =
            PluginPreemptionInjector::require(self.capabilities.inject_preemption)
                .map_err(|source| LiveVcpuTimeCallbackError::Preemption { source })?;
        let queued_idle_advance = QueuedIdleAdvance::require(self.capabilities.advance_time_ns)
            .map_err(|source| LiveVcpuTimeCallbackError::QueuedIdleAdvance { source })?;
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
        let network_rx = QemuLosslessNetworkRxQueue::require(
            self.capabilities.net_send,
            self.capabilities.net_flush,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::NetworkRx { source })?;
        let register_block = self.capabilities.register_block.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL,
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
            preemption_injector,
            exact_deadline,
            queued_idle_advance,
            register_vcpu_init,
            register_vcpu_idle_resume,
            register_sim_shmem_dispatch,
            register_time_advance_cb,
            register_net_tx,
            network_rx,
            register_block,
            register_block_wait,
            register_ninep,
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
        let state_dump = args
            .state_dump()
            .map(|config| PluginRawStateDump::resolve(config, self.execution_model.smp_vcpus()))
            .transpose()
            .map_err(|source| {
                live_callback_registration_error(LiveVcpuTimeCallbackError::RawStateDump {
                    message: source.to_string(),
                })
            })?;
        let callback_state = state
            .as_mut()
            .prepare_live_vcpu_time_state(
                self.plugin_id,
                self.execution_model.smp_vcpus(),
                args.slot(),
                capabilities.icount_raw,
                capabilities.force_vcpu_exit,
                capabilities.preemption_injector,
                (capabilities.icount_raw)(),
                capabilities.exact_deadline,
                capabilities.queued_idle_advance,
                capabilities.network_rx,
                fingerprint,
                args.fingerprint_oracle().is_on(),
                state_dump,
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

        (capabilities.register_vcpu_init)(self.plugin_id, crucible_qemu_plugin_live_vcpu_init_cb);
        (capabilities.register_vcpu_idle_resume)(
            Some(crucible_qemu_plugin_live_vcpu_idle_cb),
            Some(crucible_qemu_plugin_live_vcpu_resume_cb),
            callback_state.cast(),
        );
        (capabilities.register_sim_shmem_dispatch)(
            Some(crucible_qemu_plugin_live_publish_icount_cb),
            Some(crucible_qemu_plugin_live_max_advance_icount_cb),
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
        let mut mask = OwnedCallbackRegistrationMask::base_required();
        if let Some(whitebox_apis) = capabilities.whitebox {
            let whitebox_state = state
                .as_mut()
                .prepare_live_whitebox_state(
                    whitebox_apis,
                    args,
                    self.target_architecture,
                    self.execution_model.smp_vcpus(),
                    capabilities.icount_raw,
                    capabilities.request_shutdown,
                )
                .map_err(|source| {
                    live_callback_registration_error(LiveVcpuTimeCallbackError::WhiteboxCallback {
                        message: source.to_string(),
                    })
                })?;
            whitebox_state.register(self.plugin_id).map_err(|source| {
                live_callback_registration_error(LiveVcpuTimeCallbackError::WhiteboxCallback {
                    message: source.to_string(),
                })
            })?;
            (capabilities.register_vcpu_init)(
                self.plugin_id,
                crucible_qemu_plugin_live_vcpu_and_whitebox_init_cb,
            );
            mask = mask.with_whitebox();
        }
        Ok(mask)
    }
}

#[derive(Clone, Copy)]
struct RequiredLiveVcpuTimeCapabilities {
    icount_raw: QemuIcountRawFn,
    force_vcpu_exit: QemuForceVcpuExitFn,
    preemption_injector: PluginPreemptionInjector,
    exact_deadline: ExactDeadlineReader,
    queued_idle_advance: QueuedIdleAdvance,
    register_vcpu_init: QemuRegisterVcpuInitCbFn,
    register_vcpu_idle_resume: QemuRegisterVcpuIdleResumeCbFn,
    register_sim_shmem_dispatch: QemuRegisterSimShmemDispatchCbFn,
    register_time_advance_cb: QemuRegisterTimeAdvanceCbFn,
    register_net_tx: QemuRegisterNetTxCbFn,
    network_rx: QemuLosslessNetworkRxQueue,
    register_block: QemuRegisterBlkCbFn,
    register_block_wait: QemuRegisterBlkWaitCbFn,
    register_ninep: QemuRegisterNinePCbFn,
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
    worker: LiveFingerprintDigestWorker,
    last_capture_icount: AtomicU64,
    capture_submitted: AtomicBool,
    synchronous_oracle: bool,
}

/// Bounded owner thread that digests detached captures and publishes samples.
struct LiveFingerprintDigestWorker {
    sender: Option<mpsc::SyncSender<CapturedFingerprintSample>>,
    failed: Arc<Mutex<Option<String>>>,
    join: Option<JoinHandle<()>>,
}

impl LiveFingerprintDigestWorker {
    fn spawn(slot: StableFingerprintSlotHandle) -> Result<Self, LiveVcpuTimeCallbackError> {
        let (sender, receiver) = mpsc::sync_channel::<CapturedFingerprintSample>(1);
        let failed = Arc::new(Mutex::new(None));
        let worker_failed = Arc::clone(&failed);
        let join = thread::Builder::new()
            .name("crucible-fingerprint-digest".to_owned())
            .spawn(move || {
                while let Ok(captured) = receiver.recv() {
                    let sample = captured.digest();
                    if let Err(error) = slot.get().publish(&sample) {
                        let mut failure = match worker_failed.lock() {
                            Ok(failure) => failure,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        *failure = Some(error.to_string());
                        break;
                    }
                }
            })
            .map_err(|error| LiveVcpuTimeCallbackError::FingerprintWorkerSpawn {
                message: error.to_string(),
            })?;
        Ok(Self {
            sender: Some(sender),
            failed,
            join: Some(join),
        })
    }

    fn submit(&self, captured: CapturedFingerprintSample) -> Result<(), LiveVcpuTimeCallbackError> {
        let failure = match self.failed.lock() {
            Ok(failure) => failure,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(message) = failure.as_ref() {
            return Err(LiveVcpuTimeCallbackError::FingerprintWorkerFailed {
                message: message.clone(),
            });
        }
        drop(failure);
        let sender = self
            .sender
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)?;
        sender.try_send(captured).map_err(|error| match error {
            mpsc::TrySendError::Full(_captured) => {
                LiveVcpuTimeCallbackError::FingerprintWorkerQueueFull
            }
            mpsc::TrySendError::Disconnected(_captured) => {
                LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable
            }
        })
    }
}

impl Drop for LiveFingerprintDigestWorker {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(join) = self.join.take() {
            let _worker_result = join.join();
        }
    }
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
    rx: PluginNetworkRx,
    rx_queue: QemuLosslessNetworkRxQueue,
    outbound: StableDirectedRingHandle,
    inbound: StableDirectedRingHandle,
    tx_callback_active: AtomicBool,
}

impl LiveNetworkCallbackState {
    fn new(
        vm_slot: u32,
        outbound: MappedDirectedRingMut<'_>,
        inbound: MappedDirectedRingMut<'_>,
        rx_queue: QemuLosslessNetworkRxQueue,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        let tx = PluginNetworkTx::from_directed_ring(vm_slot, outbound.descriptor)
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
            rx: PluginNetworkRx::new(),
            rx_queue,
            outbound: StableDirectedRingHandle::new(outbound)?,
            inbound: StableDirectedRingHandle::new(inbound)?,
            tx_callback_active: AtomicBool::new(false),
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
    teardown_sender: mpsc::Sender<LiveRuntimeTeardownTrigger>,
    shared_shutdown_signaled: AtomicBool,
    plugin_id: QemuPluginId,
    icount_raw: QemuIcountRawFn,
    force_vcpu_exit: QemuForceVcpuExitFn,
    preemption_injector: PluginPreemptionInjector,
    vcpu_count: u32,
    icount_shift: u8,
    header: StableRegionHeaderHandle,
    slot: StableNodeSlotHandle,
    exact_deadline: ExactDeadlineReader,
    queued_idle_advance: QueuedIdleAdvance,
    initialized_vcpus: Box<[AtomicBool]>,
    halted_vcpus: Mutex<VcpuHaltTracker>,
    all_halted_idle_handled: AtomicBool,
    last_raw_icount: AtomicU64,
    logical_icount_offset: AtomicU64,
    preemption_enqueue_active: AtomicBool,
    last_icount: AtomicU64,
    pending_idle_advance: Mutex<Option<LivePendingIdleAdvance>>,
    network: Option<LiveNetworkCallbackState>,
    devices: Option<Mutex<LiveDeviceCallbackState>>,
    fingerprint: Option<LiveFingerprintCallbackState>,
    state_dump: Option<PluginRawStateDump>,
}

#[derive(Debug)]
struct LivePendingIdleAdvance {
    raw_icount_at_request: u64,
    target_icount: u64,
    pending: PendingIdleAdvance,
    buffered_tx_payloads: Vec<Vec<u8>>,
}

struct PreemptionEnqueueGuard<'a>(&'a AtomicBool);

impl Drop for PreemptionEnqueueGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl LiveVcpuTimeCallbackState {
    // crucible-lint: allow rust-allow -- construction binds the fixed QEMU identity, clock, mapping, and slot capabilities.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor binds one fixed QEMU identity, clock, mapping header, and node slot"
    )]
    pub(super) fn new(
        plugin_id: QemuPluginId,
        icount_raw: QemuIcountRawFn,
        force_vcpu_exit: QemuForceVcpuExitFn,
        preemption_injector: PluginPreemptionInjector,
        vcpu_count: u32,
        icount_shift: u8,
        initial_raw_icount: u64,
        exact_deadline: ExactDeadlineReader,
        queued_idle_advance: QueuedIdleAdvance,
        header: &RegionHeader,
        slot: &NodeSlot,
        quiescence: Arc<LiveCallbackQuiescence>,
        teardown_sender: mpsc::Sender<LiveRuntimeTeardownTrigger>,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        if 1_u64.checked_shl(u32::from(icount_shift)).is_none() {
            return Err(LiveVcpuTimeCallbackError::IcountShiftOutOfRange {
                icount_shift: u32::from(icount_shift),
            });
        }
        let snapshot = slot.snapshot();
        if snapshot.current_icount > snapshot.max_advance_icount {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount: snapshot.current_icount,
                ceiling_icount: snapshot.max_advance_icount,
            });
        }
        let logical_icount_offset = snapshot
            .current_icount
            .checked_sub(initial_raw_icount)
            .ok_or(LiveVcpuTimeCallbackError::InitialRawIcountBeyondLogical {
                raw_icount: initial_raw_icount,
                logical_icount: snapshot.current_icount,
            })?;
        let initialized_vcpus = (0..vcpu_count)
            .map(|_vcpu| AtomicBool::new(false))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            quiescence,
            teardown_sender,
            shared_shutdown_signaled: AtomicBool::new(false),
            plugin_id,
            icount_raw,
            force_vcpu_exit,
            preemption_injector,
            vcpu_count,
            icount_shift,
            header: StableRegionHeaderHandle::new(header),
            slot: StableNodeSlotHandle::new(slot),
            exact_deadline,
            queued_idle_advance,
            initialized_vcpus,
            halted_vcpus: Mutex::new(
                VcpuHaltTracker::new(vcpu_count)
                    .map_err(|source| LiveVcpuTimeCallbackError::VcpuHaltTracking { source })?,
            ),
            all_halted_idle_handled: AtomicBool::new(false),
            last_raw_icount: AtomicU64::new(initial_raw_icount),
            logical_icount_offset: AtomicU64::new(logical_icount_offset),
            preemption_enqueue_active: AtomicBool::new(false),
            last_icount: AtomicU64::new(snapshot.current_icount),
            pending_idle_advance: Mutex::new(None),
            network: None,
            devices: None,
            fingerprint: None,
            state_dump: None,
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
        self.teardown_sender
            .send(LiveRuntimeTeardownTrigger::SharedShutdown(proof))
            .map_err(|_error| LiveVcpuTimeCallbackError::TeardownWorkerUnavailable)
    }

    pub(super) fn attach_network(
        mut self,
        vm_slot: u32,
        outbound: MappedDirectedRingMut<'_>,
        inbound: MappedDirectedRingMut<'_>,
        rx_queue: QemuLosslessNetworkRxQueue,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        self.network = Some(LiveNetworkCallbackState::new(
            vm_slot, outbound, inbound, rx_queue,
        )?);
        Ok(self)
    }

    pub(super) fn attach_devices(
        mut self,
        vm_slot: u32,
        block: LiveDirectedRingPair,
        ninep: LiveDirectedRingPair,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        self.devices = Some(Mutex::new(
            LiveDeviceCallbackState::new(vm_slot, block, ninep)
                .map_err(LiveVcpuTimeCallbackError::live_device)?,
        ));
        Ok(self)
    }

    /// Binds the resolved fingerprint sampler and this VM's shared-memory slot.
    ///
    /// Called only when the launch enabled `fingerprint=on`; afterwards each
    /// reached-icount publish captures a black-box fingerprint sample and queues
    /// its detached preimages to a dedicated digest worker. `slot` is the per-node
    /// [`FingerprintSampleSlot`] retained by the same setup mapping owner as the
    /// node slot and directed rings.
    pub(super) fn attach_fingerprint(
        mut self,
        sampling: PluginFingerprintSampling,
        slot: &FingerprintSampleSlot,
        synchronous_oracle: bool,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        let worker = LiveFingerprintDigestWorker::spawn(StableFingerprintSlotHandle::new(slot))?;
        self.fingerprint = Some(LiveFingerprintCallbackState {
            sampling,
            worker,
            last_capture_icount: AtomicU64::new(0),
            capture_submitted: AtomicBool::new(false),
            synchronous_oracle,
        });
        Ok(self)
    }

    /// Binds the optional terminal raw-state exporter to this pinned callback state.
    pub(super) fn attach_state_dump(mut self, state_dump: PluginRawStateDump) -> Self {
        self.state_dump = Some(state_dump);
        self
    }

    /// Captures and queues a black-box fingerprint sample stamped at `icount`.
    ///
    /// A no-op unless the launch enabled `fingerprint=on`. Callers invoke it only
    /// when the published icount equals the host-set scheduler ceiling — the
    /// host's ceiling is the sample request, so the dirty-tracked immutable copy
    /// runs once per host-driven quantum boundary rather than on every
    /// intermediate progress publish. SHA-256 runs on the worker after this
    /// callback returns, allowing the guest to resume; the host waits
    /// independently for the matching sample coordinate. The vCPU count is
    /// `self.vcpu_count` — the install-time
    /// `smp_vcpus` QEMU reported to the plugin (`execution_model.smp_vcpus()`),
    /// bound into this callback state at construction — so the sample covers
    /// every configured vCPU. Multi-vCPU aggregation of the sampled material is
    /// deferred to M3 (T-TIME-9); this provenance is what that slice keys on.
    ///
    /// # Errors
    ///
    /// Returns [`LiveVcpuTimeCallbackError::FingerprintSample`] when boundary
    /// introspection or capture fails, or a worker error when the bounded digest
    /// worker cannot accept the exact-boundary capture.
    fn publish_fingerprint_sample(&self, icount: u64) -> Result<(), LiveVcpuTimeCallbackError> {
        let Some(fingerprint) = self.fingerprint.as_ref() else {
            return Ok(());
        };
        if fingerprint.capture_submitted.load(Ordering::Acquire)
            && fingerprint.last_capture_icount.load(Ordering::Acquire) == icount
        {
            return Ok(());
        }
        let captured = fingerprint
            .sampling
            .capture(icount, self.vcpu_count, fingerprint.synchronous_oracle)
            .map_err(|source| LiveVcpuTimeCallbackError::FingerprintSample { source })?;
        fingerprint.worker.submit(captured)?;
        fingerprint
            .last_capture_icount
            .store(icount, Ordering::Release);
        fingerprint.capture_submitted.store(true, Ordering::Release);
        if let Some(state_dump) = self.state_dump.as_ref() {
            state_dump.request_if_target(icount).map_err(|source| {
                LiveVcpuTimeCallbackError::RawStateDump {
                    message: source.to_string(),
                }
            })?;
        }
        Ok(())
    }

    fn idle_advance_is_pending(&self) -> Result<bool, LiveVcpuTimeCallbackError> {
        self.try_pending_idle_advance()
            .map(|pending| pending.is_some())
    }

    fn on_vcpu_init(
        &self,
        plugin_id: QemuPluginId,
        vcpu_index: u32,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        if plugin_id != self.plugin_id {
            return Err(LiveVcpuTimeCallbackError::PluginIdMismatch {
                expected: self.plugin_id,
                observed: plugin_id,
            });
        }
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
        let pending_idle_advance = self.try_pending_idle_advance()?;
        if pending_idle_advance.is_some() {
            return Err(LiveVcpuTimeCallbackError::IdleAdvanceAlreadyPending);
        }
        drop(pending_idle_advance);
        self.publish_current_icount(raw_icount)?;
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
        let ceiling_icount = PluginShmemOrdering::load_scheduler_ceiling(self.slot.get());
        let device_io_holding_ticks = PluginShmemOrdering::device_io_active(self.slot.get());
        let device_completion_deadline_icount = if device_io_holding_ticks {
            Some(PluginShmemOrdering::device_completion_deadline_icount(
                self.slot.get(),
            ))
        } else {
            None
        };
        let plan = compute_idle_wake_plan(
            current_icount,
            self.icount_shift,
            exact_deadline,
            next_inbound_delivery_icount,
            SchedulerCeiling::new(ceiling_icount),
            device_io_holding_ticks,
            device_completion_deadline_icount,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::IdleHotLoop { source })?;
        let futex_wait = PluginShmemOrdering::publish_idle_wait(
            self.slot.get(),
            current_icount,
            plan.desired_wake_icount(),
            self.icount_shift,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::PublishIdle { source })?;
        let request = IdleParkRequest::from_published(plan, futex_wait);
        match self.wait_for_scheduler_release_or_inbound(&request)? {
            None => Ok(()),
            Some(target_icount) => {
                let scale = 1_u64.checked_shl(u32::from(self.icount_shift)).ok_or(
                    LiveVcpuTimeCallbackError::IdleAdvanceTargetOverflow {
                        target_icount,
                        icount_shift: self.icount_shift,
                    },
                )?;
                let target_virtual_ns = target_icount.checked_mul(scale).ok_or(
                    LiveVcpuTimeCallbackError::IdleAdvanceTargetOverflow {
                        target_icount,
                        icount_shift: self.icount_shift,
                    },
                )?;
                let Some(pending) = self.enqueue_idle_advance_or_defer(target_virtual_ns)? else {
                    return Ok(());
                };
                self.arm_idle_advance(raw_icount, target_icount, pending)
            }
        }
    }

    fn wait_for_scheduler_release_or_inbound(
        &self,
        request: &IdleParkRequest,
    ) -> Result<Option<u64>, LiveVcpuTimeCallbackError> {
        let mut wait = request.futex_wait();
        loop {
            if PluginShmemOrdering::observe_control_action(self.header.get())
                == RegionControlAction::Shutdown
            {
                self.signal_shared_shutdown()?;
                return Ok(None);
            }
            let ceiling_icount = PluginShmemOrdering::load_scheduler_ceiling(self.slot.get());
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
                    return Ok(Some(
                        request.plan().desired_wake_icount().min(delivery_icount),
                    ));
                }
            }
            if ceiling_icount >= request.plan().desired_wake_icount() {
                return Ok(Some(request.plan().desired_wake_icount()));
            }

            match PluginShmemOrdering::wait_on_wake_signal(self.slot.get(), wait).map_err(
                |source| LiveVcpuTimeCallbackError::IdleHotLoop {
                    source: IdleHotLoopError::FutexWait { source },
                },
            )? {
                FutexWaitOutcome::Noop => {
                    return Err(LiveVcpuTimeCallbackError::IdleHotLoop {
                        source: IdleHotLoopError::WakeStillBlocked {
                            desired_wake_icount: request.plan().desired_wake_icount(),
                            ceiling_icount: PluginShmemOrdering::load_scheduler_ceiling(
                                self.slot.get(),
                            ),
                        },
                    });
                }
                FutexWaitOutcome::Runnable
                | FutexWaitOutcome::ValueChanged
                | FutexWaitOutcome::Interrupted
                | FutexWaitOutcome::Woken => {
                    wait = PluginShmemOrdering::prepare_futex_wait(self.slot.get());
                }
            }
        }
    }

    fn on_vcpu_resume(
        &self,
        vcpu_index: u32,
        raw_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.require_initialized_vcpu(vcpu_index)?;
        if PluginShmemOrdering::observe_shutdown_requested(self.header.get()) {
            self.signal_shared_shutdown()?;
            return Ok(());
        }
        let pending_idle_advance = self.try_pending_idle_advance()?;
        if pending_idle_advance.is_some() {
            return Err(LiveVcpuTimeCallbackError::ResumeWhileIdleAdvancePending);
        }
        drop(pending_idle_advance);
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
        self.publish_current_icount(raw_icount)?;
        PluginShmemOrdering::mark_running_after_wake(self.slot.get());
        Ok(())
    }

    fn publish_current_icount(&self, raw_icount: u64) -> Result<(), LiveVcpuTimeCallbackError> {
        if PluginShmemOrdering::observe_shutdown_requested(self.header.get()) {
            return self.signal_shared_shutdown();
        }
        let pending_idle_advance = self.try_pending_idle_advance()?;
        if let Some(pending) = pending_idle_advance.as_ref() {
            if raw_icount == pending.raw_icount_at_request {
                return Ok(());
            }
            return Err(
                LiveVcpuTimeCallbackError::GuestProgressWhileIdleAdvancePending {
                    expected_raw_icount: pending.raw_icount_at_request,
                    observed_raw_icount: raw_icount,
                },
            );
        }
        let previous_raw_icount = self.last_raw_icount.load(Ordering::Acquire);
        if raw_icount < previous_raw_icount {
            return Err(LiveVcpuTimeCallbackError::IcountRegressed {
                previous_icount: previous_raw_icount,
                current_icount: raw_icount,
            });
        }
        let current_icount = self.logical_icount_for_raw(raw_icount)?;
        let ceiling_icount = PluginShmemOrdering::load_scheduler_ceiling(self.slot.get());
        if current_icount > ceiling_icount {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount,
                ceiling_icount,
            });
        }
        // Sample the fingerprint only at the host-driven ceiling, and gate on
        // exact equality (not `>=`): the plugin clamps advance at the max-advance
        // ceiling, so a reached publish at a host-driven boundary lands on
        // `current_icount == ceiling_icount` by construction (the same
        // exact-ceiling-stop the install/quantum gates prove). Exact equality is
        // therefore both correct and determinism-load-bearing — it makes the
        // sampled boundary a function of the host's ceiling alone, independent of
        // how many intermediate progress publishes the busy advance emitted, so
        // the guest-RAM SHA-256 runs once per host-read boundary rather than on
        // every publish.
        if current_icount == ceiling_icount {
            self.publish_fingerprint_sample(current_icount)?;
        }
        PluginShmemOrdering::publish_reached_icount(
            self.slot.get(),
            current_icount,
            self.icount_shift,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::PublishIcount { source })?;
        self.last_raw_icount.store(raw_icount, Ordering::Release);
        self.last_icount.store(current_icount, Ordering::Release);
        Ok(())
    }

    fn arm_idle_advance(
        &self,
        raw_icount_at_request: u64,
        target_icount: u64,
        pending: PendingIdleAdvance,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let mut pending_slot = self.try_pending_idle_advance()?;
        if pending_slot.is_some() {
            return Err(LiveVcpuTimeCallbackError::IdleAdvanceAlreadyPending);
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
        let scale = 1_u64.checked_shl(u32::from(self.icount_shift)).ok_or(
            LiveVcpuTimeCallbackError::IdleAdvanceTargetOverflow {
                target_icount,
                icount_shift: self.icount_shift,
            },
        )?;
        let target_virtual_ns = target_icount.checked_mul(scale).ok_or(
            LiveVcpuTimeCallbackError::IdleAdvanceTargetOverflow {
                target_icount,
                icount_shift: self.icount_shift,
            },
        )?;
        if target_virtual_ns != pending.target_virtual_ns() {
            return Err(
                LiveVcpuTimeCallbackError::IdleAdvancePendingTargetMismatch {
                    target_icount,
                    expected_target_virtual_ns: target_virtual_ns,
                    pending_target_virtual_ns: pending.target_virtual_ns(),
                },
            );
        }
        let ceiling_icount = PluginShmemOrdering::load_scheduler_ceiling(self.slot.get());
        if target_icount > ceiling_icount {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount: target_icount,
                ceiling_icount,
            });
        }

        *pending_slot = Some(LivePendingIdleAdvance {
            raw_icount_at_request,
            target_icount,
            pending,
            buffered_tx_payloads: Vec::new(),
        });
        Ok(())
    }

    fn complete_idle_advance(
        &self,
        completion: TimeAdvanceCompletion,
    ) -> Result<u64, LiveVcpuTimeCallbackError> {
        let mut pending_slot = self.try_pending_idle_advance()?;
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
        let logical_icount_offset = pending
            .target_icount
            .checked_sub(observed_raw_icount)
            .ok_or(LiveVcpuTimeCallbackError::IdleAdvanceOffsetUnderflow {
                raw_icount: observed_raw_icount,
                target_icount: pending.target_icount,
            })?;
        let ceiling_icount = PluginShmemOrdering::load_scheduler_ceiling(self.slot.get());
        if pending.target_icount > ceiling_icount {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount: pending.target_icount,
                ceiling_icount,
            });
        }

        if let Some(network) = self.network.as_ref() {
            let mut outbound = network.outbound.outbound();
            network
                .tx
                .preflight_guest_frame_batch(&outbound, pending.buffered_tx_payloads.len())
                .map_err(|source| LiveVcpuTimeCallbackError::NetworkTx { source })?;
            let inbound = network.inbound.inbound();
            PluginInboundFrames::reject_already_passed_ring_heads(
                [inbound],
                self.last_icount.load(Ordering::Acquire),
            )
            .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?;
            let preview = PluginInboundFrames::preview_deliverable_since(
                [inbound],
                pending.target_icount,
                self.last_icount.load(Ordering::Acquire),
            )
            .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?;

            if !preview.frames().is_empty() {
                let mut rx_queue = network.rx_queue;
                handle_network_rx_idle_callback(
                    &network.rx,
                    &mut rx_queue,
                    self.last_icount.load(Ordering::Acquire),
                    pending.target_icount,
                    preview.frames(),
                )
                .map_err(|source| LiveVcpuTimeCallbackError::NetworkRx { source })?;
            }
            let committed = PluginInboundFrames::drain_deliverable_since(
                [inbound],
                pending.target_icount,
                self.last_icount.load(Ordering::Acquire),
            )
            .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?;
            if committed.frames() != preview.frames() {
                return Err(LiveVcpuTimeCallbackError::InboundCommitMismatch);
            }
            network
                .tx
                .enqueue_guest_frame_batch(
                    &mut outbound,
                    pending.target_icount,
                    &pending.buffered_tx_payloads,
                )
                .map_err(|source| LiveVcpuTimeCallbackError::NetworkTx { source })?;
        }

        if pending.target_icount == ceiling_icount {
            self.publish_fingerprint_sample(pending.target_icount)?;
        }
        let completed_target_icount = pending.target_icount;
        self.logical_icount_offset
            .store(logical_icount_offset, Ordering::Release);
        self.last_icount
            .store(completed_target_icount, Ordering::Release);
        *pending_slot = None;
        drop(pending_slot);
        self.all_halted_idle_handled.store(false, Ordering::Release);
        // Publish the reached coordinate only after clearing the pending token.
        // The host treats this release-published coordinate as permission to
        // expose a due device response and wake its coroutine. Publishing first
        // would let that wake re-enter QEMU while this callback still considered
        // the queued idle advance pending.
        PluginShmemOrdering::publish_reached_icount(
            self.slot.get(),
            completed_target_icount,
            self.icount_shift,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::PublishIcount { source })?;
        Ok(completed_target_icount)
    }

    fn on_network_tx(&self, payload: &[u8]) -> Result<(), LiveVcpuTimeCallbackError> {
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
        let current_icount = self.callback_current_icount()?;
        network
            .tx
            .enqueue_guest_frame(&mut outbound, current_icount, payload)
            .map(|_enqueue| ())
            .map_err(|source| LiveVcpuTimeCallbackError::NetworkTx { source })
    }

    fn on_block_wait(&self, _request_id: u32) -> Result<(), LiveVcpuTimeCallbackError> {
        let pending = self.try_pending_idle_advance()?;
        if pending.is_some() {
            return Ok(());
        }
        drop(pending);

        let current_icount = self.callback_current_icount()?;
        let device_deadline =
            PluginShmemOrdering::device_completion_deadline_icount(self.slot.get());
        if device_deadline == 0 {
            // The host publishes the deterministic deadline before signalling
            // the wake fd. QEMU re-fires this callback after that wake, so this
            // wall-time race changes only how long the coroutine stays parked.
            return Ok(());
        }
        let ceiling_icount = PluginShmemOrdering::load_scheduler_ceiling(self.slot.get());
        let exact_deadline = self
            .exact_deadline
            .read_next_deadline()
            .map_err(|source| LiveVcpuTimeCallbackError::ExactDeadlineRead { source })?;
        let plan = compute_idle_wake_plan(
            current_icount,
            self.icount_shift,
            exact_deadline,
            None,
            SchedulerCeiling::new(ceiling_icount),
            true,
            Some(device_deadline),
        )
        .map_err(|source| LiveVcpuTimeCallbackError::IdleHotLoop { source })?;
        let target_icount = plan.desired_wake_icount();
        if target_icount <= current_icount {
            // Virtual time already admits the response. If its ring write is
            // still physically pending, the next host wake retries the poll at
            // this same icount without exposing host timing to the guest.
            return Ok(());
        }
        let scale = 1_u64.checked_shl(u32::from(self.icount_shift)).ok_or(
            LiveVcpuTimeCallbackError::IdleAdvanceTargetOverflow {
                target_icount,
                icount_shift: self.icount_shift,
            },
        )?;
        let target_virtual_ns = target_icount.checked_mul(scale).ok_or(
            LiveVcpuTimeCallbackError::IdleAdvanceTargetOverflow {
                target_icount,
                icount_shift: self.icount_shift,
            },
        )?;
        let Some(pending) = self.enqueue_idle_advance_or_defer(target_virtual_ns)? else {
            return Ok(());
        };
        self.arm_idle_advance((self.icount_raw)(), target_icount, pending)
    }

    /// Enqueues an idle advance or defers behind QEMU's outstanding barrier.
    ///
    /// QEMU notifies every idle and device waiter after releasing an accepted
    /// advance, so `-EBUSY` means this callback can park and recompute its target
    /// on that deterministic retry. Guest execution remains frozen by the
    /// outstanding barrier in the meantime.
    fn enqueue_idle_advance_or_defer(
        &self,
        target_virtual_ns: u64,
    ) -> Result<Option<PendingIdleAdvance>, LiveVcpuTimeCallbackError> {
        match self.queued_idle_advance.enqueue(target_virtual_ns) {
            Ok(pending) => Ok(Some(pending)),
            Err(QueuedIdleAdvanceError::EnqueueRejected { status, .. })
                if status == -libc::EBUSY =>
            {
                Ok(None)
            }
            Err(source) => Err(LiveVcpuTimeCallbackError::QueuedIdleAdvance { source }),
        }
    }

    fn callback_current_icount(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        self.publish_current_icount((self.icount_raw)())?;
        Ok(self.last_icount.load(Ordering::Acquire))
    }

    /// Returns the logical icount for a device callback dispatched from QEMU's
    /// main-loop timer boundary.
    ///
    /// QEMU runs timer-produced bottom halves before the queued idle-advance
    /// completion callback. A device request dispatched in that slice belongs
    /// to the already-reached advance target even though the plugin has not yet
    /// committed the corresponding logical-icount offset.
    fn device_callback_icount(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        let pending = self.try_pending_idle_advance()?;
        if let Some(pending) = pending.as_ref() {
            return Ok(pending.target_icount);
        }
        drop(pending);
        self.callback_current_icount()
    }

    fn logical_icount_for_raw(&self, raw_icount: u64) -> Result<u64, LiveVcpuTimeCallbackError> {
        let offset = self.logical_icount_offset.load(Ordering::Acquire);
        raw_icount
            .checked_add(offset)
            .ok_or(LiveVcpuTimeCallbackError::LogicalIcountOverflow { raw_icount, offset })
    }

    fn try_pending_idle_advance(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<LivePendingIdleAdvance>>, LiveVcpuTimeCallbackError>
    {
        match self.pending_idle_advance.try_lock() {
            Ok(pending) => Ok(pending),
            Err(TryLockError::WouldBlock) => Err(LiveVcpuTimeCallbackError::CallbackReentered),
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
            Err(TryLockError::WouldBlock) => Err(LiveVcpuTimeCallbackError::CallbackReentered),
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
    /// saturates the budget to zero. The distinct case of a guest *halted* on
    /// device I/O (where the sim loop stops querying this callback altogether)
    /// is closed separately by the device-wait callback of the SCHED-8 delivery
    /// patch.
    fn max_advance_icount(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        let ceiling = PluginShmemOrdering::load_scheduler_ceiling(self.slot.get());
        let offset = self.logical_icount_offset.load(Ordering::Acquire);
        let effective_ceiling = if PluginShmemOrdering::device_io_active(self.slot.get()) {
            match PluginShmemOrdering::device_completion_deadline_icount(self.slot.get()) {
                0 => ceiling.min(self.last_icount.load(Ordering::Acquire)),
                deadline => ceiling.min(deadline),
            }
        } else {
            ceiling
        };
        let raw_ceiling = effective_ceiling.saturating_sub(offset);
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
        let raw_at = logical_preemption_icount_to_raw("at", command.at_icount, offset)?;
        let raw_deadline =
            logical_preemption_icount_to_raw("deadline", command.deadline_icount, offset)?;
        let raw_command_ceiling =
            logical_preemption_icount_to_raw("ceiling", command.ceiling_icount, offset)?;
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

pub(crate) extern "C" fn crucible_qemu_plugin_live_vcpu_init_cb(
    plugin_id: QemuPluginId,
    vcpu_index: c_uint,
) {
    let state = live_vcpu_time_state_or_abort();
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) = state.on_vcpu_init(plugin_id, vcpu_index) {
        abort_live_callback(error);
    }
}

extern "C" fn crucible_qemu_plugin_live_vcpu_and_whitebox_init_cb(
    plugin_id: QemuPluginId,
    vcpu_index: c_uint,
) {
    crucible_qemu_plugin_live_vcpu_init_cb(plugin_id, vcpu_index);
    crucible_qemu_plugin_live_whitebox_vcpu_init_cb(plugin_id, vcpu_index);
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
    if let Err(error) = state.publish_current_icount(current_icount) {
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

fn logical_preemption_icount_to_raw(
    field: &'static str,
    logical_icount: u64,
    logical_icount_offset: u64,
) -> Result<u64, LiveVcpuTimeCallbackError> {
    logical_icount.checked_sub(logical_icount_offset).ok_or(
        LiveVcpuTimeCallbackError::PreemptionIcountBeforeRawOrigin {
            field,
            logical_icount,
            logical_icount_offset,
        },
    )
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_time_advance_completion_cb(
    status: std::os::raw::c_int,
    target_virtual_ns: i64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Err(error) =
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(status, target_virtual_ns))
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
    if let Err(error) = state.on_network_tx(payload) {
        abort_live_callback(error);
    }
    0
}

fn live_vcpu_time_state_or_abort() -> &'static LiveVcpuTimeCallbackState {
    let state = LIVE_VCPU_TIME_STATE.load(Ordering::Acquire);
    if state.is_null() {
        abort_live_callback(LiveVcpuTimeCallbackError::CallbackStateUnavailable);
    }
    // SAFETY: registration release-publishes a pointer into a pinned allocation
    // before QEMU can invoke the init callback. Partial registration retains the
    // allocation, and a successful runtime owns it for process lifetime.
    unsafe { &*state }
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
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LiveVcpuTimeCallbackError {
    /// A required QEMU callback registration symbol is absent.
    #[error("required live callback capability `{symbol}` is unavailable")]
    CapabilityUnavailable {
        /// Missing QEMU symbol.
        symbol: &'static str,
    },
    /// The live preemption command or QEMU injection was rejected.
    #[error("live preemption injection failed: {source}")]
    Preemption {
        /// Underlying command validation or QEMU capability error.
        source: PreemptionError,
    },
    /// The shared-memory preemption mailbox could not be consumed.
    #[error("live preemption mailbox failed: {source}")]
    PreemptionMailbox {
        /// Underlying mailbox publication or acknowledgement error.
        source: PreemptionMailboxError,
    },
    /// A logical preemption icount precedes the restored raw-icount origin.
    #[error(
        "preemption {field} icount {logical_icount} precedes logical raw origin {logical_icount_offset}"
    )]
    PreemptionIcountBeforeRawOrigin {
        /// Command field whose logical icount could not be translated.
        field: &'static str,
        /// Scheduler-authored logical icount.
        logical_icount: u64,
        /// Logical offset added to QEMU's raw retired count.
        logical_icount_offset: u64,
    },
    /// The live white-box adapter failed preflight, registration, or dispatch.
    #[error("live white-box callback failed: {message}")]
    WhiteboxCallback {
        /// Stable boundary diagnostic.
        message: String,
    },
    /// Exact virtual-deadline introspection was unavailable during preflight.
    #[error("required exact-deadline capability failed: {source}")]
    ExactDeadlineCapability {
        /// Underlying exact-deadline capability error.
        source: ExactDeadlineError,
    },
    /// Reading QEMU's exact virtual deadline failed at an idle boundary.
    #[error("reading the exact idle deadline failed: {source}")]
    ExactDeadlineRead {
        /// Underlying exact-deadline read error.
        source: ExactDeadlineError,
    },
    /// Enqueueing the scheduler-authorized QEMU idle jump failed.
    #[error("queued idle advance failed: {source}")]
    QueuedIdleAdvance {
        /// Underlying queued-advance error.
        source: QueuedIdleAdvanceError,
    },
    /// The shared idle planning or scheduler wait failed.
    #[error("live idle hot-loop failed: {source}")]
    IdleHotLoop {
        /// Underlying deterministic idle-loop error.
        source: IdleHotLoopError,
    },
    /// The mapped region could not provide the configured VM slot.
    #[error("mapped setup region cannot provide the live callback node slot")]
    MappedNodeSlot {
        /// Underlying typed mapping error.
        source: MappedSetupRegionAccessError,
    },
    /// The mapped region could not provide this VM's fingerprint sample slot.
    #[error("mapped setup region cannot provide the live callback fingerprint slot")]
    MappedFingerprintSlot {
        /// Underlying typed mapping error.
        source: MappedSetupRegionAccessError,
    },
    /// `fingerprint=on` was requested but the loaded QEMU lacks the exports.
    #[error("fingerprint sampling requested but QEMU is missing the fingerprint helper exports")]
    FingerprintCapabilityUnavailable,
    /// Capturing a boundary fingerprint sample failed.
    #[error("boundary fingerprint sampling failed: {source}")]
    FingerprintSample {
        /// Underlying plugin fingerprint sampler error.
        source: FingerprintSamplerError,
    },
    /// The dedicated fingerprint digest worker could not be created.
    #[error("fingerprint digest worker could not start: {message}")]
    FingerprintWorkerSpawn {
        /// Host thread-spawn diagnostic.
        message: String,
    },
    /// The bounded fingerprint digest queue still contains the prior boundary.
    #[error("fingerprint digest worker queue is full at a new sample boundary")]
    FingerprintWorkerQueueFull,
    /// The fingerprint digest worker is no longer accepting captures.
    #[error("fingerprint digest worker is unavailable")]
    FingerprintWorkerUnavailable,
    /// The fingerprint digest worker failed while publishing a prior sample.
    #[error("fingerprint digest worker failed: {message}")]
    FingerprintWorkerFailed {
        /// Stable publication failure diagnostic.
        message: String,
    },
    /// Terminal raw-state export setup or boundary activation failed.
    #[error("terminal raw-state dump failed: {message}")]
    RawStateDump {
        /// Stable underlying raw-state export diagnostic.
        message: String,
    },
    /// A mapped callback ring unexpectedly had no backing entries.
    #[error("mapped callback ring {ring_index} has no backing entries")]
    MappedDirectedRingEmpty {
        /// Directed ring index without storage.
        ring_index: u32,
    },
    /// The selected inbound ring was not the router-to-VM network ring.
    #[error(
        "inbound network ring mismatch: expected {expected_src_slot}->{expected_dst_slot}, got {actual_src_slot}->{actual_dst_slot} at ring {actual_ring_index}"
    )]
    WrongInboundNetworkRing {
        /// Required network-router source slot.
        expected_src_slot: u32,
        /// Required VM destination slot.
        expected_dst_slot: u32,
        /// Selected ring's source slot.
        actual_src_slot: u32,
        /// Selected ring's destination slot.
        actual_dst_slot: u32,
        /// Selected ring index.
        actual_ring_index: u32,
    },
    /// A live network TX enqueue or batch preflight failed.
    #[error("live network TX failed: {source}")]
    NetworkTx {
        /// Underlying fixed-ring TX error.
        source: NetworkTxError,
    },
    /// The inbound network ring could not be previewed or committed.
    #[error("live inbound network frame operation failed: {source}")]
    InboundFrames {
        /// Underlying inbound-ring error.
        source: InboundFrameError,
    },
    /// QEMU's lossless RX queue rejected the validated batch.
    #[error("live network RX injection failed: {source}")]
    NetworkRx {
        /// Underlying lossless RX error.
        source: NetworkRxError,
    },
    /// A live block or 9p adapter failed registration or dispatch.
    #[error("live device callback failed: {source}")]
    LiveDevice {
        /// Underlying block/9p adapter error.
        source: Box<LiveDeviceCallbackError>,
    },
    /// The consumed inbound batch changed after its pre-commit preview.
    #[error("live inbound network commit disagreed with its validated preview")]
    InboundCommitMismatch,
    /// QEMU invoked network TX without registration-fixed network state.
    #[error("live network TX callback state is unavailable")]
    NetworkStateUnavailable,
    /// QEMU re-entered the network TX callback before its prior call returned.
    #[error("live network TX callback was re-entered")]
    NetworkTxReentered,
    /// A pending timer-boundary TX batch exceeded addressable memory.
    #[error("buffered live network TX frame count overflowed")]
    BufferedNetworkTxCountOverflow,
    /// QEMU supplied a null pointer for a nonempty TX payload.
    #[error("live network TX payload is null for nonzero length {payload_len}")]
    NullNetworkTxPayload {
        /// Claimed payload length.
        payload_len: usize,
    },
    /// The mapped icount shift cannot fit the plugin clock representation.
    #[error("mapped setup icount shift {icount_shift} does not fit u8")]
    IcountShiftOutOfRange {
        /// Rejected shared-memory shift.
        icount_shift: u32,
    },
    /// QEMU's raw retired count cannot be reconciled with restored logical time.
    #[error("initial raw icount {raw_icount} exceeds restored logical icount {logical_icount}")]
    InitialRawIcountBeyondLogical {
        /// Raw retired-instruction count read from QEMU during registration.
        raw_icount: u64,
        /// Logical scheduler count restored in the shared-memory slot.
        logical_icount: u64,
    },
    /// Another live callback state pointer is already globally visible.
    #[error("live production callback state is already published")]
    CallbackStateAlreadyPublished,
    /// QEMU invoked the global vCPU-init adapter before state publication.
    #[error("live production callback state is unavailable")]
    CallbackStateUnavailable,
    /// The callback observed a shutdown action without a matching acquire proof.
    #[error("shared shutdown action could not be proven from the region header")]
    SharedShutdownProofUnavailable,
    /// The sole teardown worker disconnected after shared shutdown was observed.
    #[error("shared shutdown could not reach the production teardown worker")]
    TeardownWorkerUnavailable,
    /// QEMU rejected installation of the normal-main-loop completion callback.
    #[error("QEMU rejected time-advance completion registration with status {status}")]
    TimeAdvanceCompletionRegistrationRejected {
        /// Negative errno-style status returned by QEMU.
        status: std::os::raw::c_int,
    },
    /// The normal-main-loop completion callback ran without an outstanding request.
    #[error("time-advance completion arrived without an outstanding idle advance")]
    IdleAdvanceCompletionWithoutPending,
    /// Another idle advance was armed before the current one completed.
    #[error("an idle time advance is already pending")]
    IdleAdvanceAlreadyPending,
    /// QEMU reported an invalid per-vCPU halt or resume transition.
    #[error("live per-vCPU halt tracking failed: {source}")]
    VcpuHaltTracking {
        /// Underlying deterministic halt-tracker error.
        source: RoundRobinError,
    },
    /// QEMU reported vCPU resume before the queued idle jump completed.
    #[error("vCPU resumed while an idle time advance was still pending")]
    ResumeWhileIdleAdvancePending,
    /// The pending idle-advance slot was re-entered from another callback.
    #[error("live time callback was re-entered while pending state was borrowed")]
    CallbackReentered,
    /// A prior panic poisoned the pending idle-advance slot.
    #[error("live time callback pending state is poisoned")]
    CallbackStatePoisoned,
    /// A prior panic poisoned the per-vCPU halt tracker.
    #[error("live per-vCPU halt state is poisoned")]
    HaltStatePoisoned,
    /// Raw guest instruction progress changed while a queued idle jump was pending.
    #[error(
        "raw icount changed during idle advance: expected {expected_raw_icount}, observed {observed_raw_icount}"
    )]
    IdleAdvanceRawIcountChanged {
        /// Raw instruction count captured with the queued request.
        expected_raw_icount: u64,
        /// Raw instruction count observed at validation or completion.
        observed_raw_icount: u64,
    },
    /// Guest instructions retired while QEMU had an idle time jump outstanding.
    #[error(
        "raw icount advanced during a pending idle jump: expected {expected_raw_icount}, observed {observed_raw_icount}"
    )]
    GuestProgressWhileIdleAdvancePending {
        /// Raw count captured when the idle jump was armed.
        expected_raw_icount: u64,
        /// Unexpected later count supplied by the sim-loop callback.
        observed_raw_icount: u64,
    },
    /// The requested logical target precedes the current logical icount.
    #[error("idle advance target {target_icount} precedes current icount {current_icount}")]
    IdleAdvanceTargetRegressed {
        /// Current logical icount.
        current_icount: u64,
        /// Rejected logical target.
        target_icount: u64,
    },
    /// Projecting the logical idle target to virtual nanoseconds overflowed.
    #[error("idle advance target {target_icount} overflows at icount shift {icount_shift}")]
    IdleAdvanceTargetOverflow {
        /// Logical target being projected.
        target_icount: u64,
        /// Fixed icount shift.
        icount_shift: u8,
    },
    /// The queued QEMU target does not match the logical idle target.
    #[error(
        "idle advance target {target_icount} projects to {expected_target_virtual_ns}ns but pending request targets {pending_target_virtual_ns}ns"
    )]
    IdleAdvancePendingTargetMismatch {
        /// Logical target selected by the scheduler.
        target_icount: u64,
        /// Exact virtual target derived from the logical target.
        expected_target_virtual_ns: u64,
        /// Target retained by the queued QEMU request.
        pending_target_virtual_ns: u64,
    },
    /// QEMU rejected or mismatched the normal-main-loop completion.
    #[error("idle advance completion validation failed: {source}")]
    IdleAdvanceCompletion {
        /// Underlying queued-advance completion failure.
        source: QueuedIdleAdvanceError,
    },
    /// A logical idle target cannot be represented as a nonnegative raw offset.
    #[error("idle target {target_icount} precedes raw icount {raw_icount}")]
    IdleAdvanceOffsetUnderflow {
        /// Raw guest instruction count held across the jump.
        raw_icount: u64,
        /// Logical icount selected by the scheduler.
        target_icount: u64,
    },
    /// Adding the accumulated idle-jump offset to raw progress overflowed.
    #[error("logical icount overflows at raw icount {raw_icount} plus offset {offset}")]
    LogicalIcountOverflow {
        /// Raw retired-instruction count supplied by QEMU.
        raw_icount: u64,
        /// Accumulated logical idle-jump offset.
        offset: u64,
    },
    /// QEMU supplied null userdata to a registered live callback.
    #[error("live production callback userdata is null")]
    NullCallbackUserdata,
    /// A standard lifecycle callback named another plugin instance.
    #[error("vCPU lifecycle callback plugin id {observed} does not match {expected}")]
    PluginIdMismatch {
        /// Plugin identifier captured at registration.
        expected: QemuPluginId,
        /// Plugin identifier supplied by QEMU.
        observed: QemuPluginId,
    },
    /// QEMU named a vCPU outside the validated execution model.
    #[error("vCPU callback index {vcpu_index} is outside configured count {vcpu_count}")]
    VcpuOutOfRange {
        /// Rejected vCPU index.
        vcpu_index: u32,
        /// Validated number of vCPUs.
        vcpu_count: u32,
    },
    /// An idle/resume boundary ran before the matching vCPU initialization callback.
    #[error("vCPU callback index {vcpu_index} was not initialized")]
    VcpuNotInitialized {
        /// vCPU index that reached an out-of-order boundary.
        vcpu_index: u32,
    },
    /// A callback reported an instruction count older than its prior boundary.
    #[error("callback icount regressed from {previous_icount} to {current_icount}")]
    IcountRegressed {
        /// Most recently accepted icount.
        previous_icount: u64,
        /// Rejected older icount.
        current_icount: u64,
    },
    /// A callback reported progress beyond the scheduler's current authorization.
    #[error("callback icount {current_icount} exceeds scheduler ceiling {ceiling_icount}")]
    IcountBeyondCeiling {
        /// Rejected reached icount.
        current_icount: u64,
        /// Scheduler-published upper bound.
        ceiling_icount: u64,
    },
    /// Publishing an accepted sim-loop instruction count failed.
    #[error("publishing live callback icount failed: {source}")]
    PublishIcount {
        /// Underlying node-slot contract error.
        source: NodeSlotError,
    },
    /// Publishing the live all-idle state failed.
    #[error("publishing live callback idle state failed: {source}")]
    PublishIdle {
        /// Underlying node-slot contract error.
        source: NodeSlotError,
    },
}

impl LiveVcpuTimeCallbackError {
    fn live_device(source: LiveDeviceCallbackError) -> Self {
        Self::LiveDevice {
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
pub(super) fn clear_live_vcpu_time_state_for_test() {
    LIVE_VCPU_TIME_STATE.store(std::ptr::null_mut(), Ordering::Release);
}

#[cfg(test)]
mod tests;
