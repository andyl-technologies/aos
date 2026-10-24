//! Ordered callback-child construction independently of raw allocator ownership.
//!
//! The private guard retains an initialized prefix until every field is valid.
//! It never exposes a partial state or assumes the layout of Mutex or Option.
//! Owned Box construction and externally retained uninitialized spans use the
//! same actual initializer. Source birth/claim/registration APIs remain separate;
//! this module cannot authenticate arbitrary supplied memory as Native custody.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::mem::{ManuallyDrop, MaybeUninit};

/// Keeps allocator ownership distinct from initialization of a supplied span.
/// Native constructor entry supplies a genuine unique span; this trait grants
/// no Source ownership, capacity, callback membership or allocation credit.
///
/// # Safety
/// The pointer denotes one unique, aligned, live uninitialized child span. Its
/// owner remains valid through conversion or prefix rollback, and conversion
/// preserves its original allocator and backing lifetime.
pub(in crate::runtime) unsafe trait CallbackAllocation {
    /// Preserves the original owned or lifetime-bound complete representation.
    type Initialized;

    /// Borrows the unique valid span for ordered field writes.
    fn pointer(&mut self) -> *mut LiveVcpuTimeCallbackState;

    /// Converts this exact storage only after all fields have been initialized.
    ///
    /// # Safety
    /// All fields contain valid unique values and no unfinished prefix guard or
    /// other owner may destroy them. The underlying allocation owner remains live.
    unsafe fn initialized(self) -> Self::Initialized;

    /// Records actual completed prefix cleanup without freeing external backing.
    fn prefix_rollback_completed(&mut self) {}
}

#[cfg(test)]
// SAFETY: this sole Box owns a stable exact uninitialized child allocation;
// conversion and unfinished cleanup retain the same allocator ownership.
unsafe impl CallbackAllocation for Box<MaybeUninit<LiveVcpuTimeCallbackState>> {
    type Initialized = Box<LiveVcpuTimeCallbackState>;

    fn pointer(&mut self) -> *mut LiveVcpuTimeCallbackState {
        self.as_mut_ptr()
    }

    /// Converts the complete unique storage using its existing allocation owner.
    ///
    /// # Safety
    /// Every child field is initialized and no unfinished prefix guard or other
    /// owner may destroy it. The original backing remains live after conversion.
    unsafe fn initialized(self) -> Self::Initialized {
        // SAFETY: caller proves the complete initialized body in this sole Box.
        unsafe { self.assume_init() }
    }
}

// SAFETY: this unique reference lends an exact live child span. Conversion
// keeps its backing lifetime; dropping the reference never frees that backing.
unsafe impl<'a> CallbackAllocation for &'a mut MaybeUninit<LiveVcpuTimeCallbackState> {
    type Initialized = &'a mut LiveVcpuTimeCallbackState;

    fn pointer(&mut self) -> *mut LiveVcpuTimeCallbackState {
        self.as_mut_ptr()
    }

    /// Converts the complete unique storage using its existing allocation owner.
    ///
    /// # Safety
    /// Every child field is initialized and no unfinished prefix guard or other
    /// owner may destroy it. The original backing remains live after conversion.
    unsafe fn initialized(self) -> Self::Initialized {
        // SAFETY: caller proves all fields initialized in the unique live span.
        // The lifetime remains tied to its real backing owner, not a new Box.
        unsafe { self.assume_init_mut() }
    }
}

struct LiveVcpuTimeInitialization<S: CallbackAllocation> {
    allocation: S,
    initialized: usize,
}

impl<S: CallbackAllocation> LiveVcpuTimeInitialization<S> {
    fn new(allocation: S) -> Self {
        Self {
            allocation,
            initialized: 0,
        }
    }

    fn finish(self) -> S::Initialized {
        // Missing-field controls refuse here before any typed state can form.
        assert_eq!(self.initialized, 40, "incomplete live vCPU initialization");
        let guard = ManuallyDrop::new(self);
        // SAFETY: all 40 fields were written and recorded. Move only the original
        // storage representation; it converts within its own allocator/lifetime.
        // ManuallyDrop prevents prefix cleanup after complete conversion.
        unsafe { std::ptr::read(&guard.allocation).initialized() }
    }
}

impl<S: CallbackAllocation> Drop for LiveVcpuTimeInitialization<S> {
    fn drop(&mut self) {
        let state = self.allocation.pointer();
        // SAFETY: initialized denotes the exact contiguous prefix written by
        // initialize_with_allocation. No hook runs between a field write and its marker update.
        // Only that prefix is dropped, in reverse unfinished-expression order;
        // Storage Drop follows its original owner: a Box frees only its own
        // raw backing; a borrowed span does not free its external allocation.
        unsafe {
            if self.initialized > 39 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).fault_commands));
            }
            if self.initialized > 38 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).fingerprint));
            }
            if self.initialized > 37 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).devices));
            }
            if self.initialized > 36 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).network));
            }
            if self.initialized > 35 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).pending_idle_advance));
            }
            if self.initialized > 34 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).idle_advance_generation));
            }
            if self.initialized > 33 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!(
                    (*state).pending_idle_advance_target_icount
                ));
            }
            if self.initialized > 32 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!(
                    (*state).pending_idle_advance_raw_icount
                ));
            }
            if self.initialized > 31 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!(
                    (*state).pending_idle_advance_active
                ));
            }
            if self.initialized > 30 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!(
                    (*state).logical_restore_continuation_generation
                ));
            }
            if self.initialized > 29 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).last_icount));
            }
            if self.initialized > 28 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!(
                    (*state).idle_advance_completion_active
                ));
            }
            if self.initialized > 27 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).control_stage_identity));
            }
            if self.initialized > 26 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).stop_caller_witness));
            }
            if self.initialized > 25 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).control_callback_witness));
            }
            if self.initialized > 24 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!(
                    (*state).control_boundary_defer_diagnostic_generation
                ));
            }
            if self.initialized > 23 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!(
                    (*state).control_boundary_dispatch_generation
                ));
            }
            if self.initialized > 22 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).fault_command_pump_active));
            }
            if self.initialized > 21 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).preemption_enqueue_active));
            }
            if self.initialized > 20 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).logical_icount_offset));
            }
            if self.initialized > 19 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).last_raw_icount));
            }
            if self.initialized > 18 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).all_halted_idle_handled));
            }
            if self.initialized > 17 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).halted_vcpus));
            }
            if self.initialized > 16 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).initialized_vcpus));
            }
            if self.initialized > 15 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).virtual_timer_witness));
            }
            if self.initialized > 14 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).queued_idle_advance));
            }
            if self.initialized > 13 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).exact_deadline));
            }
            if self.initialized > 12 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).slot));
            }
            if self.initialized > 11 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).header));
            }
            if self.initialized > 10 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).vcpu_count));
            }
            if self.initialized > 9 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).preemption_injector));
            }
            if self.initialized > 8 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).selectable_vmstop));
            }
            if self.initialized > 7 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).request_vmstop));
            }
            if self.initialized > 6 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).idle_wake_wait));
            }
            if self.initialized > 5 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).force_vcpu_exit));
            }
            if self.initialized > 4 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).sim_tick_observed));
            }
            if self.initialized > 3 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).icount_raw));
            }
            if self.initialized > 2 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).shared_shutdown_signaled));
            }
            if self.initialized > 1 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).teardown_router));
            }
            if self.initialized > 0 {
                std::ptr::drop_in_place(std::ptr::addr_of_mut!((*state).quiescence));
            }
        }
        self.allocation.prefix_rollback_completed();
    }
}

const _: fn(&LiveVcpuTimeCallbackState) = |state| {
    let LiveVcpuTimeCallbackState {
        quiescence: _,
        teardown_router: _,
        shared_shutdown_signaled: _,
        icount_raw: _,
        sim_tick_observed: _,
        force_vcpu_exit: _,
        idle_wake_wait: _,
        request_vmstop: _,
        selectable_vmstop: _,
        preemption_injector: _,
        vcpu_count: _,
        header: _,
        slot: _,
        exact_deadline: _,
        queued_idle_advance: _,
        virtual_timer_witness: _,
        initialized_vcpus: _,
        halted_vcpus: _,
        all_halted_idle_handled: _,
        last_raw_icount: _,
        logical_icount_offset: _,
        preemption_enqueue_active: _,
        fault_command_pump_active: _,
        control_boundary_dispatch_generation: _,
        control_boundary_defer_diagnostic_generation: _,
        control_callback_witness: _,
        stop_caller_witness: _,
        control_stage_identity: _,
        idle_advance_completion_active: _,
        last_icount: _,
        logical_restore_continuation_generation: _,
        pending_idle_advance_active: _,
        pending_idle_advance_raw_icount: _,
        pending_idle_advance_target_icount: _,
        idle_advance_generation: _,
        pending_idle_advance: _,
        network: _,
        devices: _,
        fingerprint: _,
        fault_commands: _,
    } = state;
};

impl LiveVcpuTimeCallbackState {
    // crucible-lint: allow rust-allow -- construction binds the fixed QEMU clock, mapping, and slot capabilities.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor binds one fixed QEMU clock, mapping header, and node slot"
    )]
    /// Initializes one final allocation before any callback can observe it.
    ///
    /// # Errors
    ///
    /// Returns the original clock, capability, or halt-tracker validation error.
    #[cfg(test)]
    pub(in crate::runtime) fn new_boxed(
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
        fault_commands: impl Into<FaultCommandControl>,
        header: &RegionHeader,
        slot: &NodeSlot,
        quiescence: Arc<LiveCallbackQuiescence>,
        teardown_router: Arc<LiveRuntimeTeardownRouter>,
    ) -> Result<Box<Self>, LiveVcpuTimeCallbackError> {
        Self::new_boxed_with_hook(
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
            slot,
            quiescence,
            teardown_router,
            #[cfg(test)]
            &mut |_| {},
        )
    }

    // crucible-lint: allow rust-allow -- construction binds the fixed QEMU clock, mapping, and slot capabilities.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor binds one fixed QEMU clock, mapping header, and node slot"
    )]
    #[cfg(test)]
    pub(in crate::runtime) fn new_boxed_with_hook(
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
        fault_commands: impl Into<FaultCommandControl>,
        header: &RegionHeader,
        slot: &NodeSlot,
        quiescence: Arc<LiveCallbackQuiescence>,
        teardown_router: Arc<LiveRuntimeTeardownRouter>,
        #[cfg(test)] initialization_hook: &mut dyn FnMut(usize),
    ) -> Result<Box<Self>, LiveVcpuTimeCallbackError> {
        Self::initialize_with_allocation(
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
            slot,
            quiescence,
            teardown_router,
            || Ok(Box::<Self>::new_uninit()),
            #[cfg(test)]
            initialization_hook,
        )
    }

    /// Initializes the actual callback child in exactly one supplied allocation.
    ///
    /// The provider runs at the original allocation cut after scalar validation
    /// and existing auxiliary preparation, immediately before the first field
    /// write. A future Source creator must supply authentic paid storage and its
    /// placement journal there; arbitrary supplied memory is no ownership grant.
    /// Borrowed storage returns only a lifetime-bound complete child, never a Box.
    ///
    /// # Errors
    /// Preserves original validation or provider refusal and rolls back only the
    /// real initialized prefix. A partial child is never returned as a complete T.
    // crucible-lint: allow rust-allow -- one constructor preserves exact common callback-field initialization for owned and externally retained storage.
    #[allow(
        clippy::too_many_arguments,
        reason = "one ordered constructor binds the existing callback, mapping and storage inputs"
    )]
    pub(in crate::runtime) fn initialize_with_allocation<S: CallbackAllocation>(
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
        fault_commands: impl Into<FaultCommandControl>,
        header: &RegionHeader,
        slot: &NodeSlot,
        quiescence: Arc<LiveCallbackQuiescence>,
        teardown_router: Arc<LiveRuntimeTeardownRouter>,
        allocation: impl FnOnce() -> Result<S, LiveVcpuTimeCallbackError>,
        #[cfg(test)] initialization_hook: &mut dyn FnMut(usize),
    ) -> Result<S::Initialized, LiveVcpuTimeCallbackError> {
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
                    .checked_mul(crucible_qemu_shmem::TICKS_PER_INSTRUCTION)
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
        let control_callback_witness = Arc::new(ControlCallbackWitness::from_env());
        let stop_caller_witness =
            checkpoint_stop_witness::StopCallerWitness::new(control_callback_witness.is_enabled());

        let mut initialization = LiveVcpuTimeInitialization::new(allocation()?);
        let state = initialization.allocation.pointer();
        macro_rules! initialize {
            ($field:ident, $value:expr) => {{
                // SAFETY: state addresses the uniquely owned correctly aligned
                // allocation. This field has not yet been written; addr_of_mut
                // creates no reference to the incomplete state. The value is
                // evaluated before writing; its error leaves the prior prefix.
                unsafe { std::ptr::addr_of_mut!((*state).$field).write($value) };
                initialization.initialized += 1;
                #[cfg(test)]
                initialization_hook(initialization.initialized);
            }};
        }
        initialize!(quiescence, quiescence);
        initialize!(teardown_router, teardown_router);
        initialize!(shared_shutdown_signaled, AtomicBool::new(false));
        initialize!(icount_raw, icount_raw);
        initialize!(sim_tick_observed, sim_tick_observed);
        initialize!(force_vcpu_exit, force_vcpu_exit);
        initialize!(idle_wake_wait, idle_wake_wait);
        initialize!(request_vmstop, request_vmstop);
        initialize!(selectable_vmstop, Arc::new(SelectableVmstopHandoff::new()));
        initialize!(preemption_injector, preemption_injector);
        initialize!(vcpu_count, vcpu_count);
        initialize!(header, StableRegionHeaderHandle::new(header));
        initialize!(slot, StableNodeSlotHandle::new(slot));
        initialize!(exact_deadline, exact_deadline);
        initialize!(queued_idle_advance, queued_idle_advance);
        initialize!(virtual_timer_witness, virtual_timer_witness);
        initialize!(initialized_vcpus, initialized_vcpus);
        initialize!(
            halted_vcpus,
            Mutex::new(
                VcpuHaltTracker::new(vcpu_count)
                    .map_err(|source| LiveVcpuTimeCallbackError::VcpuHaltTracking { source })?,
            )
        );
        initialize!(all_halted_idle_handled, AtomicBool::new(false));
        initialize!(last_raw_icount, AtomicU64::new(initial_raw_icount));
        initialize!(
            logical_icount_offset,
            Arc::new(AtomicU64::new(logical_icount_offset))
        );
        initialize!(preemption_enqueue_active, AtomicBool::new(false));
        initialize!(fault_command_pump_active, AtomicBool::new(false));
        initialize!(
            control_boundary_dispatch_generation,
            AtomicU32::new(u32::MAX)
        );
        initialize!(
            control_boundary_defer_diagnostic_generation,
            AtomicU64::new(u64::MAX)
        );
        initialize!(control_callback_witness, control_callback_witness);
        initialize!(stop_caller_witness, stop_caller_witness);
        initialize!(control_stage_identity, None);
        initialize!(idle_advance_completion_active, AtomicBool::new(false));
        initialize!(last_icount, AtomicU64::new(snapshot.current_icount));
        initialize!(logical_restore_continuation_generation, AtomicU32::new(0));
        initialize!(pending_idle_advance_active, AtomicBool::new(false));
        initialize!(pending_idle_advance_raw_icount, AtomicU64::new(0));
        initialize!(pending_idle_advance_target_icount, AtomicU64::new(0));
        initialize!(idle_advance_generation, AtomicU64::new(0));
        initialize!(pending_idle_advance, Mutex::new(None));
        initialize!(network, None);
        initialize!(devices, None);
        initialize!(fingerprint, None);
        initialize!(fault_commands, Mutex::new(fault_commands.into()));
        Ok(initialization.finish())
    }
}
