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
use std::sync::{Mutex, TryLockError};

use crucible_shmem::{
    DirectedRing, FrameEntry, FutexWaitOutcome, MappedDirectedRingMut,
    MappedSetupRegionAccessError, NodeSlot, NodeSlotError, RegionControlAction, RegionHeader,
    RingHeader, SLOT_NET_ROUTER,
};
use thiserror::Error;

use crate::{
    ExactDeadlineError, ExactDeadlineReader, IdleHotLoopError, IdleParkRequest, InboundFrameError,
    InboundFrameRing, NetworkRxError, NetworkTxError, NetworkTxRing, PendingIdleAdvance,
    PluginArgs, PluginInboundFrames, PluginNetworkRx, PluginNetworkTx, PluginShmemOrdering,
    QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL, QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL, QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL,
    QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL, QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL, QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL, QemuAdvanceTimeNsFn, QemuClockDeadlineFn,
    QemuIcountRawFn, QemuLosslessNetworkRxQueue, QemuPluginExecutionModel, QemuPluginId,
    QemuPluginNetFlushFn, QemuPluginNetSendFn, QemuRegisterBlkCbFn, QemuRegisterNetTxCbFn,
    QemuRegisterNinePCbFn, QemuRegisterSimShmemDispatchCbFn, QemuRegisterTimeAdvanceCbFn,
    QemuRegisterVcpuIdleResumeCbFn, QemuRegisterVcpuInitCbFn, QueuedIdleAdvance,
    QueuedIdleAdvanceError, SchedulerCeiling, TimeAdvanceCompletion, compute_idle_wake_plan,
    handle_network_rx_idle_callback,
};

use super::{
    OwnedCallbackRegistrar, OwnedCallbackRegistrationError, OwnedCallbackRegistrationMask,
    OwnedCallbackRuntimeState,
};

mod devices;
pub use devices::LiveDeviceCallbackError;
use devices::LiveDeviceCallbackState;

static LIVE_VCPU_TIME_STATE: AtomicPtr<LiveVcpuTimeCallbackState> =
    AtomicPtr::new(std::ptr::null_mut());

/// QEMU capabilities for the joined production callback families.
#[derive(Clone, Copy)]
pub(crate) struct LiveVcpuTimeCallbackCapabilities {
    pub(crate) icount_raw: QemuIcountRawFn,
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
    pub(crate) register_ninep: Option<QemuRegisterNinePCbFn>,
}

/// Registrar for the joined live vCPU, time, network, block, and 9p callbacks.
pub(crate) struct LiveVcpuTimeCallbackRegistrar {
    plugin_id: QemuPluginId,
    execution_model: QemuPluginExecutionModel,
    capabilities: LiveVcpuTimeCallbackCapabilities,
}

impl LiveVcpuTimeCallbackRegistrar {
    pub(crate) const fn new(
        plugin_id: QemuPluginId,
        execution_model: QemuPluginExecutionModel,
        capabilities: LiveVcpuTimeCallbackCapabilities,
    ) -> Self {
        Self {
            plugin_id,
            execution_model,
            capabilities,
        }
    }

    fn required_capabilities(
        &self,
        args: &PluginArgs,
    ) -> Result<RequiredLiveVcpuTimeCapabilities, LiveVcpuTimeCallbackError> {
        let exact_deadline = ExactDeadlineReader::require(self.capabilities.clock_deadline_ns)
            .map_err(|source| LiveVcpuTimeCallbackError::ExactDeadlineCapability { source })?;
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
        let register_ninep = self.capabilities.register_ninep.ok_or(
            LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL,
            },
        )?;
        if args.whitebox().is_on() {
            return Err(LiveVcpuTimeCallbackError::WhiteboxCallbackAbiUnavailable {
                trap_symbol: QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL,
                guest_memory_read_symbol: QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL,
            });
        }
        Ok(RequiredLiveVcpuTimeCapabilities {
            icount_raw: self.capabilities.icount_raw,
            exact_deadline,
            queued_idle_advance,
            register_vcpu_init,
            register_vcpu_idle_resume,
            register_sim_shmem_dispatch,
            register_time_advance_cb,
            register_net_tx,
            network_rx,
            register_block,
            register_ninep,
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
        let callback_state = state
            .as_mut()
            .prepare_live_vcpu_time_state(
                self.plugin_id,
                self.execution_model.smp_vcpus(),
                args.slot(),
                capabilities.icount_raw,
                (capabilities.icount_raw)(),
                capabilities.exact_deadline,
                capabilities.queued_idle_advance,
                capabilities.network_rx,
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
        (capabilities.register_ninep)(
            Some(devices::crucible_qemu_plugin_live_ninep_burst_start_cb),
            Some(devices::crucible_qemu_plugin_live_ninep_submit_cb),
            Some(devices::crucible_qemu_plugin_live_ninep_poll_cb),
            Some(devices::crucible_qemu_plugin_live_ninep_burst_done_cb),
            callback_state.cast(),
        );
        Ok(OwnedCallbackRegistrationMask::base_required())
    }
}

#[derive(Clone, Copy)]
struct RequiredLiveVcpuTimeCapabilities {
    icount_raw: QemuIcountRawFn,
    exact_deadline: ExactDeadlineReader,
    queued_idle_advance: QueuedIdleAdvance,
    register_vcpu_init: QemuRegisterVcpuInitCbFn,
    register_vcpu_idle_resume: QemuRegisterVcpuIdleResumeCbFn,
    register_sim_shmem_dispatch: QemuRegisterSimShmemDispatchCbFn,
    register_time_advance_cb: QemuRegisterTimeAdvanceCbFn,
    register_net_tx: QemuRegisterNetTxCbFn,
    network_rx: QemuLosslessNetworkRxQueue,
    register_block: QemuRegisterBlkCbFn,
    register_ninep: QemuRegisterNinePCbFn,
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
    plugin_id: QemuPluginId,
    icount_raw: QemuIcountRawFn,
    vcpu_count: u32,
    icount_shift: u8,
    header: StableRegionHeaderHandle,
    slot: StableNodeSlotHandle,
    exact_deadline: ExactDeadlineReader,
    queued_idle_advance: QueuedIdleAdvance,
    initialized_vcpus: Box<[AtomicBool]>,
    last_raw_icount: AtomicU64,
    logical_icount_offset: AtomicU64,
    last_icount: AtomicU64,
    pending_idle_advance: Mutex<Option<LivePendingIdleAdvance>>,
    network: Option<LiveNetworkCallbackState>,
    devices: Option<Mutex<LiveDeviceCallbackState>>,
}

#[derive(Debug)]
struct LivePendingIdleAdvance {
    raw_icount_at_request: u64,
    target_icount: u64,
    pending: PendingIdleAdvance,
    buffered_tx_payloads: Vec<Vec<u8>>,
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
        vcpu_count: u32,
        icount_shift: u8,
        initial_raw_icount: u64,
        exact_deadline: ExactDeadlineReader,
        queued_idle_advance: QueuedIdleAdvance,
        header: &RegionHeader,
        slot: &NodeSlot,
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
            plugin_id,
            icount_raw,
            vcpu_count,
            icount_shift,
            header: StableRegionHeaderHandle::new(header),
            slot: StableNodeSlotHandle::new(slot),
            exact_deadline,
            queued_idle_advance,
            initialized_vcpus,
            last_raw_icount: AtomicU64::new(initial_raw_icount),
            logical_icount_offset: AtomicU64::new(logical_icount_offset),
            last_icount: AtomicU64::new(snapshot.current_icount),
            pending_idle_advance: Mutex::new(None),
            network: None,
            devices: None,
        })
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
        let plan = compute_idle_wake_plan(
            current_icount,
            self.icount_shift,
            exact_deadline,
            next_inbound_delivery_icount,
            SchedulerCeiling::new(ceiling_icount),
            PluginShmemOrdering::device_io_active(self.slot.get()),
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
                let pending = self
                    .queued_idle_advance
                    .enqueue(target_virtual_ns)
                    .map_err(|source| LiveVcpuTimeCallbackError::QueuedIdleAdvance { source })?;
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
                PluginShmemOrdering::mark_done_after_shutdown(self.slot.get());
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
            PluginShmemOrdering::mark_done_after_shutdown(self.slot.get());
            return Ok(());
        }
        let pending_idle_advance = self.try_pending_idle_advance()?;
        if pending_idle_advance.is_some() {
            return Err(LiveVcpuTimeCallbackError::ResumeWhileIdleAdvancePending);
        }
        drop(pending_idle_advance);
        self.publish_current_icount(raw_icount)?;
        PluginShmemOrdering::mark_running_after_wake(self.slot.get());
        Ok(())
    }

    fn publish_current_icount(&self, raw_icount: u64) -> Result<(), LiveVcpuTimeCallbackError> {
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

        PluginShmemOrdering::publish_reached_icount(
            self.slot.get(),
            pending.target_icount,
            self.icount_shift,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::PublishIcount { source })?;
        self.logical_icount_offset
            .store(logical_icount_offset, Ordering::Release);
        self.last_icount
            .store(pending.target_icount, Ordering::Release);
        let completed_target_icount = pending.target_icount;
        *pending_slot = None;
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

    fn callback_current_icount(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        self.publish_current_icount((self.icount_raw)())?;
        Ok(self.last_icount.load(Ordering::Acquire))
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

    fn max_advance_icount(&self) -> u64 {
        PluginShmemOrdering::load_scheduler_ceiling(self.slot.get())
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
    if let Err(error) = state.on_vcpu_init(plugin_id, vcpu_index) {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_vcpu_idle_cb(
    vcpu_index: c_uint,
    raw_icount: u64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
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
    if let Err(error) = state.on_vcpu_resume(vcpu_index, raw_icount) {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_publish_icount_cb(
    current_icount: u64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    if let Err(error) = state.publish_current_icount(current_icount) {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_max_advance_icount_cb(
    userdata: *mut c_void,
) -> u64 {
    callback_userdata_or_abort(userdata).max_advance_icount()
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_time_advance_completion_cb(
    status: std::os::raw::c_int,
    target_virtual_ns: i64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    if let Err(error) =
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(status, target_virtual_ns))
    {
        abort_live_callback(error);
    }
}

pub(crate) extern "C" fn crucible_qemu_plugin_live_network_tx_cb(
    payload: *const u8,
    payload_len: usize,
    userdata: *mut c_void,
) -> std::os::raw::c_int {
    let state = callback_userdata_or_abort(userdata);
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
    /// White-box mode lacks a concrete QEMU trap/read callback ABI.
    #[error(
        "white-box mode cannot register: no live trap adapter for {trap_symbol} and no typed guest-memory reader for {guest_memory_read_symbol}"
    )]
    WhiteboxCallbackAbiUnavailable {
        /// Upstream callback surface currently modeled as the trap hook.
        trap_symbol: &'static str,
        /// Missing typed guest-memory read export.
        guest_memory_read_symbol: &'static str,
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
    /// QEMU reported vCPU resume before the queued idle jump completed.
    #[error("vCPU resumed while an idle time advance was still pending")]
    ResumeWhileIdleAdvancePending,
    /// The pending idle-advance slot was re-entered from another callback.
    #[error("live time callback was re-entered while pending state was borrowed")]
    CallbackReentered,
    /// A prior panic poisoned the pending idle-advance slot.
    #[error("live time callback pending state is poisoned")]
    CallbackStatePoisoned,
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
mod tests {
    use super::*;

    use std::cell::Cell;

    use crucible_shmem::{
        KIND_VM, RegionConfig, RegionHeader, RegionLayout, STATUS_IDLE, STATUS_RUNNING,
        authorize_advance_ceiling,
    };

    extern "C" fn test_icount_raw() -> u64 {
        0
    }

    thread_local! {
        static TEST_CLOCK_DEADLINE_NS: Cell<i64> = const { Cell::new(-1) };
        static LAST_QUEUED_ADVANCE_NS: Cell<i64> = const { Cell::new(-1) };
    }
    static TEST_RX_SEND_COUNT: AtomicU64 = AtomicU64::new(0);
    static TEST_RX_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
    static TEST_RX_LAST_LEN: AtomicU64 = AtomicU64::new(0);
    static TEST_RX_SEND_STATUS: AtomicU64 = AtomicU64::new(0);

    extern "C" fn test_clock_deadline_ns() -> i64 {
        TEST_CLOCK_DEADLINE_NS.get()
    }

    fn test_live_state(
        plugin_id: QemuPluginId,
        vcpu_count: u32,
        icount_shift: u8,
        initial_raw_icount: u64,
        slot: &NodeSlot,
    ) -> Result<LiveVcpuTimeCallbackState, LiveVcpuTimeCallbackError> {
        let layout = RegionLayout::for_config(RegionConfig::new(1, 2, u32::from(icount_shift)))
            .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
        let header = Box::leak(Box::new(RegionHeader::new(layout)));
        let exact_deadline = ExactDeadlineReader::require(Some(test_clock_deadline_ns))
            .unwrap_or_else(|error| panic!("test deadline capability should validate: {error}"));
        let queued_idle_advance = QueuedIdleAdvance::require(Some(test_queue_idle_advance))
            .unwrap_or_else(|error| panic!("test queued advance should validate: {error}"));
        LiveVcpuTimeCallbackState::new(
            plugin_id,
            test_icount_raw,
            vcpu_count,
            icount_shift,
            initial_raw_icount,
            exact_deadline,
            queued_idle_advance,
            header,
            slot,
        )
    }

    #[test]
    fn live_state_dispatches_vcpu_init_publish_and_ceiling() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 12, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let state = test_live_state(41, 2, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

        state
            .on_vcpu_init(41, 0)
            .unwrap_or_else(|error| panic!("vCPU 0 should initialize: {error}"));
        state
            .on_vcpu_init(41, 1)
            .unwrap_or_else(|error| panic!("vCPU 1 should initialize: {error}"));
        state
            .publish_current_icount(5)
            .unwrap_or_else(|error| panic!("sim icount should publish: {error}"));
        assert_eq!(state.max_advance_icount(), 12);
        assert_eq!(slot.snapshot().current_icount, 5);
        assert!(state.initialized_vcpus[0].load(Ordering::Acquire));
        assert!(state.initialized_vcpus[1].load(Ordering::Acquire));
    }

    #[test]
    fn live_time_completion_commits_logical_idle_offset_before_future_raw_progress() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 20, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let state = test_live_state(43, 1, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
        state
            .publish_current_icount(4)
            .unwrap_or_else(|error| panic!("raw progress should publish: {error}"));

        let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
            .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
        let pending = queued
            .enqueue(20)
            .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
        state
            .arm_idle_advance(4, 10, pending)
            .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
        state
            .publish_current_icount(4)
            .unwrap_or_else(|error| panic!("repeated raw boundary should be a no-op: {error}"));
        assert!(matches!(
            state.publish_current_icount(5),
            Err(
                LiveVcpuTimeCallbackError::GuestProgressWhileIdleAdvancePending {
                    expected_raw_icount: 4,
                    observed_raw_icount: 5,
                }
            )
        ));
        assert_eq!(slot.snapshot().current_icount, 4);

        let committed = state
            .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 20))
            .unwrap_or_else(|error| panic!("matching completion should commit: {error}"));
        assert_eq!(committed, 10);
        assert_eq!(slot.snapshot().current_icount, 10);

        state
            .publish_current_icount(5)
            .unwrap_or_else(|error| panic!("post-jump raw progress should publish: {error}"));
        assert_eq!(slot.snapshot().current_icount, 11);
    }

    #[test]
    fn live_idle_callback_queues_then_commits_only_from_normal_loop_completion() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 10, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let state = test_live_state(46, 1, 0, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
        state
            .on_vcpu_init(46, 0)
            .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));

        state
            .on_vcpu_idle(0, 0)
            .unwrap_or_else(|error| panic!("idle callback should queue the jump: {error}"));
        let pending_snapshot = slot.snapshot();
        assert_eq!(pending_snapshot.current_icount, 0);
        assert_eq!(pending_snapshot.status, STATUS_IDLE);

        state
            .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 10))
            .unwrap_or_else(|error| panic!("completion should commit the jump: {error}"));
        assert_eq!(slot.snapshot().current_icount, 10);
        assert_eq!(slot.snapshot().status, STATUS_RUNNING);

        state
            .on_vcpu_resume(0, 0)
            .unwrap_or_else(|error| panic!("resume should preserve logical time: {error}"));
        assert_eq!(slot.snapshot().current_icount, 10);
    }

    #[test]
    fn live_idle_callback_queues_the_exact_timer_deadline() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 20, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let state = test_live_state(47, 1, 0, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
        state
            .on_vcpu_init(47, 0)
            .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
        TEST_CLOCK_DEADLINE_NS.set(7);
        LAST_QUEUED_ADVANCE_NS.set(-1);

        state
            .on_vcpu_idle(0, 0)
            .unwrap_or_else(|error| panic!("idle callback should queue exact timer: {error}"));
        assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 7);
        assert_eq!(slot.snapshot().current_icount, 0);
        state
            .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 7))
            .unwrap_or_else(|error| panic!("exact timer completion should commit: {error}"));
        assert_eq!(slot.snapshot().current_icount, 7);
        TEST_CLOCK_DEADLINE_NS.set(-1);
    }

    #[test]
    fn live_completion_joins_buffered_tx_inbound_ring_rx_and_clock_commit() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 20, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let outbound_header = RingHeader::new();
        let inbound_header = RingHeader::new();
        let mut outbound_entries = vec![FrameEntry::default(); 4];
        let mut inbound_entries = vec![FrameEntry::default(); 4];
        let inbound_frame = FrameEntry::new(7, SLOT_NET_ROUTER as u32, 0, b"inbound")
            .unwrap_or_else(|error| panic!("test inbound frame should build: {error}"));
        inbound_header
            .enqueue(&mut inbound_entries, &inbound_frame)
            .unwrap_or_else(|error| panic!("test inbound frame should enqueue: {error}"));
        let outbound = MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: 0,
                src_slot: 0,
                dst_slot: SLOT_NET_ROUTER as u32,
            },
            header: &outbound_header,
            entries: &mut outbound_entries,
        };
        let inbound = MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: 1,
                src_slot: SLOT_NET_ROUTER as u32,
                dst_slot: 0,
            },
            header: &inbound_header,
            entries: &mut inbound_entries,
        };
        let rx_queue =
            QemuLosslessNetworkRxQueue::require(Some(test_net_send), Some(test_net_flush))
                .unwrap_or_else(|error| panic!("test RX queue should build: {error}"));
        let state = test_live_state(49, 1, 0, 0, &slot)
            .and_then(|state| state.attach_network(0, outbound, inbound, rx_queue))
            .unwrap_or_else(|error| panic!("live network callback state should build: {error}"));
        state
            .on_vcpu_init(49, 0)
            .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
        TEST_CLOCK_DEADLINE_NS.set(-1);
        LAST_QUEUED_ADVANCE_NS.set(-1);
        TEST_RX_SEND_COUNT.store(0, Ordering::SeqCst);
        TEST_RX_FLUSH_COUNT.store(0, Ordering::SeqCst);
        TEST_RX_LAST_LEN.store(0, Ordering::SeqCst);
        TEST_RX_SEND_STATUS.store(0, Ordering::SeqCst);

        state
            .on_vcpu_idle(0, 0)
            .unwrap_or_else(|error| panic!("inbound-aware idle callback should queue: {error}"));
        assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 7);
        state
            .on_network_tx(b"timer-tx")
            .unwrap_or_else(|error| panic!("pending timer TX should buffer: {error}"));
        assert_eq!(outbound_header.write_index(), 0);
        assert_eq!(inbound_header.read_index(), 0);
        assert_eq!(slot.snapshot().current_icount, 0);
        assert_eq!(TEST_RX_SEND_COUNT.load(Ordering::SeqCst), 0);

        assert!(matches!(
            state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 8)),
            Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletion { .. })
        ));
        assert_eq!(outbound_header.write_index(), 0);
        assert_eq!(inbound_header.read_index(), 0);
        assert_eq!(slot.snapshot().current_icount, 0);
        assert_eq!(TEST_RX_SEND_COUNT.load(Ordering::SeqCst), 0);

        TEST_RX_SEND_STATUS.store(5, Ordering::SeqCst);
        assert!(matches!(
            state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 7)),
            Err(LiveVcpuTimeCallbackError::NetworkRx { .. })
        ));
        assert_eq!(outbound_header.write_index(), 0);
        assert_eq!(inbound_header.read_index(), 0);
        assert_eq!(slot.snapshot().current_icount, 0);
        TEST_RX_SEND_STATUS.store(0, Ordering::SeqCst);

        state
            .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 7))
            .unwrap_or_else(|error| {
                panic!("exact completion should commit network state: {error}")
            });
        assert_eq!(slot.snapshot().current_icount, 7);
        assert_eq!(outbound_header.write_index(), 1);
        assert_eq!(outbound_entries[0].delivery_icount, 7);
        assert_eq!(outbound_entries[0].payload(), Ok(b"timer-tx".as_slice()));
        assert_eq!(inbound_header.read_index(), 1);
        assert_eq!(TEST_RX_SEND_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(TEST_RX_LAST_LEN.load(Ordering::SeqCst), 7);
        assert_eq!(TEST_RX_FLUSH_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn live_time_completion_rejects_missing_or_mismatched_pending_state() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 20, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let state = test_live_state(44, 1, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

        assert!(matches!(
            state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 20)),
            Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletionWithoutPending)
        ));
        let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
            .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
        let pending = queued
            .enqueue(20)
            .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
        assert!(matches!(
            state.arm_idle_advance(0, 9, pending),
            Err(LiveVcpuTimeCallbackError::IdleAdvancePendingTargetMismatch { .. })
        ));
        assert_eq!(slot.snapshot().current_icount, 0);

        let pending = queued
            .enqueue(16)
            .unwrap_or_else(|error| panic!("matching idle advance should queue: {error}"));
        state
            .arm_idle_advance(0, 8, pending)
            .unwrap_or_else(|error| panic!("matching idle advance should arm: {error}"));
        assert!(matches!(
            state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 14)),
            Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletion { .. })
        ));
        assert_eq!(slot.snapshot().current_icount, 0);
        state
            .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 16))
            .unwrap_or_else(|error| {
                panic!("retained pending advance should still complete: {error}")
            });
        assert_eq!(slot.snapshot().current_icount, 8);
    }

    #[test]
    fn live_pending_advance_rejects_idle_resume_and_reentrant_publication() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 20, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let state = test_live_state(48, 1, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
        state
            .on_vcpu_init(48, 0)
            .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
        let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
            .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
        let pending = queued
            .enqueue(16)
            .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
        state
            .arm_idle_advance(0, 8, pending)
            .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
        let pending_snapshot = slot.snapshot();

        assert_eq!(
            state.on_vcpu_resume(0, 0),
            Err(LiveVcpuTimeCallbackError::ResumeWhileIdleAdvancePending)
        );
        assert_eq!(
            state.on_vcpu_idle(0, 0),
            Err(LiveVcpuTimeCallbackError::IdleAdvanceAlreadyPending)
        );
        let pending_guard = match state.pending_idle_advance.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert_eq!(
            state.publish_current_icount(0),
            Err(LiveVcpuTimeCallbackError::CallbackReentered)
        );
        drop(pending_guard);
        assert_eq!(slot.snapshot(), pending_snapshot);

        state
            .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 16))
            .unwrap_or_else(|error| panic!("retained pending advance should complete: {error}"));
        assert_eq!(slot.snapshot().current_icount, 8);
    }

    #[test]
    fn live_state_calibrates_raw_progress_against_restored_logical_time() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 20, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        slot.publish_reached_icount(10, 0)
            .unwrap_or_else(|error| panic!("restored logical time should publish: {error}"));

        let state = test_live_state(45, 1, 0, 4, &slot)
            .unwrap_or_else(|error| panic!("live callback state should calibrate: {error}"));
        state
            .publish_current_icount(5)
            .unwrap_or_else(|error| panic!("raw progress should preserve idle offset: {error}"));
        assert_eq!(slot.snapshot().current_icount, 11);

        assert!(matches!(
            test_live_state(45, 1, 0, 12, &slot),
            Err(LiveVcpuTimeCallbackError::InitialRawIcountBeyondLogical {
                raw_icount: 12,
                logical_icount: 11,
            })
        ));
    }

    #[test]
    fn live_state_rejects_bad_init_and_regressing_or_excess_progress() {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 8, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let state = test_live_state(42, 2, 0, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

        assert!(matches!(
            state.on_vcpu_init(99, 0),
            Err(LiveVcpuTimeCallbackError::PluginIdMismatch { .. })
        ));
        assert!(matches!(
            state.on_vcpu_init(42, 2),
            Err(LiveVcpuTimeCallbackError::VcpuOutOfRange {
                vcpu_index: 2,
                vcpu_count: 2,
            })
        ));
        state
            .on_vcpu_init(42, 0)
            .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
        state
            .publish_current_icount(4)
            .unwrap_or_else(|error| panic!("progress should publish: {error}"));
        assert!(matches!(
            state.publish_current_icount(3),
            Err(LiveVcpuTimeCallbackError::IcountRegressed {
                previous_icount: 4,
                current_icount: 3,
            })
        ));
        assert!(matches!(
            state.publish_current_icount(9),
            Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount: 9,
                ceiling_icount: 8,
            })
        ));
    }

    #[test]
    fn live_registrar_preflight_names_each_missing_capability() {
        let execution_model = QemuPluginExecutionModel::validate(
            2,
            crate::QemuTcgThreading::SingleThreadedRoundRobin,
        )
        .unwrap_or_else(|error| panic!("test model should validate: {error}"));
        let args = PluginArgs::parse("simfd=3,slot=0")
            .unwrap_or_else(|error| panic!("test arguments should parse: {error}"));
        let missing_init = LiveVcpuTimeCallbackRegistrar::new(
            1,
            execution_model,
            LiveVcpuTimeCallbackCapabilities {
                icount_raw: test_icount_raw,
                clock_deadline_ns: Some(test_clock_deadline_ns),
                advance_time_ns: Some(test_queue_idle_advance),
                register_vcpu_init: None,
                register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
                register_sim_shmem_dispatch: Some(test_register_sim_dispatch),
                register_time_advance_cb: Some(test_register_time_advance_cb),
                register_net_tx: Some(test_register_net_tx),
                net_send: Some(test_net_send),
                net_flush: Some(test_net_flush),
                register_block: Some(test_register_block),
                register_ninep: Some(test_register_ninep),
            },
        );
        assert!(matches!(
            missing_init.preflight(&args),
            Err(OwnedCallbackRegistrationError::LiveVcpuTime {
                source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                    symbol: QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL,
                }
            })
        ));

        let missing_sim_dispatch = LiveVcpuTimeCallbackRegistrar::new(
            1,
            execution_model,
            LiveVcpuTimeCallbackCapabilities {
                icount_raw: test_icount_raw,
                clock_deadline_ns: Some(test_clock_deadline_ns),
                advance_time_ns: Some(test_queue_idle_advance),
                register_vcpu_init: Some(test_register_vcpu_init),
                register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
                register_sim_shmem_dispatch: None,
                register_time_advance_cb: Some(test_register_time_advance_cb),
                register_net_tx: Some(test_register_net_tx),
                net_send: Some(test_net_send),
                net_flush: Some(test_net_flush),
                register_block: Some(test_register_block),
                register_ninep: Some(test_register_ninep),
            },
        );
        assert!(matches!(
            missing_sim_dispatch.preflight(&args),
            Err(OwnedCallbackRegistrationError::LiveVcpuTime {
                source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                    symbol: QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL,
                },
            })
        ));

        let missing_time_advance_completion = LiveVcpuTimeCallbackRegistrar::new(
            1,
            execution_model,
            LiveVcpuTimeCallbackCapabilities {
                icount_raw: test_icount_raw,
                clock_deadline_ns: Some(test_clock_deadline_ns),
                advance_time_ns: Some(test_queue_idle_advance),
                register_vcpu_init: Some(test_register_vcpu_init),
                register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
                register_sim_shmem_dispatch: Some(test_register_sim_dispatch),
                register_time_advance_cb: None,
                register_net_tx: Some(test_register_net_tx),
                net_send: Some(test_net_send),
                net_flush: Some(test_net_flush),
                register_block: Some(test_register_block),
                register_ninep: Some(test_register_ninep),
            },
        );
        assert!(matches!(
            missing_time_advance_completion.preflight(&args),
            Err(OwnedCallbackRegistrationError::LiveVcpuTime {
                source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                    symbol: QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL,
                },
            })
        ));
    }

    extern "C" fn test_register_vcpu_init(
        _plugin_id: QemuPluginId,
        _callback: crate::QemuVcpuSimpleCbFn,
    ) {
    }

    extern "C" fn test_register_vcpu_idle_resume(
        _idle_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
        _resume_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
        _userdata: *mut c_void,
    ) {
    }

    extern "C" fn test_register_sim_dispatch(
        _publish: Option<crate::QemuSimShmemPublishIcountCbFn>,
        _ceiling: Option<crate::QemuSimShmemMaxAdvanceIcountCbFn>,
        _userdata: *mut c_void,
    ) {
    }

    extern "C" fn test_register_time_advance_cb(
        _callback: Option<crate::QemuTimeAdvanceCompletionCbFn>,
        _userdata: *mut c_void,
    ) -> std::os::raw::c_int {
        0
    }

    extern "C" fn test_register_net_tx(
        _callback: Option<crate::QemuNetTxCbFn>,
        _userdata: *mut c_void,
    ) {
    }

    extern "C" fn test_register_block(
        _submit: Option<crate::QemuBlkSubmitCbFn>,
        _poll: Option<crate::QemuBlkPollCbFn>,
        _userdata: *mut c_void,
    ) {
    }

    extern "C" fn test_register_ninep(
        _burst_start: Option<crate::QemuNinePBurstCbFn>,
        _submit: Option<crate::QemuNinePSubmitCbFn>,
        _poll: Option<crate::QemuNinePPollCbFn>,
        _burst_done: Option<crate::QemuNinePBurstCbFn>,
        _userdata: *mut c_void,
    ) {
    }

    extern "C" fn test_net_send(payload: *const u8, payload_len: usize) -> std::os::raw::c_int {
        if payload.is_null() && payload_len != 0 {
            return 1;
        }
        TEST_RX_SEND_COUNT.fetch_add(1, Ordering::SeqCst);
        TEST_RX_LAST_LEN.store(payload_len as u64, Ordering::SeqCst);
        TEST_RX_SEND_STATUS.load(Ordering::SeqCst) as std::os::raw::c_int
    }

    extern "C" fn test_net_flush() -> std::os::raw::c_int {
        TEST_RX_FLUSH_COUNT.fetch_add(1, Ordering::SeqCst);
        0
    }

    extern "C" fn test_queue_idle_advance(target_virtual_ns: i64) -> std::os::raw::c_int {
        LAST_QUEUED_ADVANCE_NS.set(target_virtual_ns);
        0
    }
}
