//! Halted-vCPU transitions and deterministic idle-time advancement.

use super::*;

impl LiveVcpuTimeCallbackState {
    pub(super) fn on_vcpu_idle(
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
        if self.preserve_network_output_stop(raw_icount, "vcpu-idle")? {
            return Ok(());
        }
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

    pub(super) fn wait_for_scheduler_release_or_inbound(
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

    pub(super) fn on_vcpu_resume(
        &self,
        vcpu_index: u32,
        raw_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.require_initialized_vcpu(vcpu_index)?;
        if self.publish_pause_for_boundary(raw_icount, true, false, None, "vcpu-resume")? {
            return Ok(());
        }
        if self.preserve_network_output_stop(raw_icount, "vcpu-resume")? {
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
        deliver_selectable_reply_on_vcpu_resume(vcpu_index, current_icount)
            .map_err(|source| LiveVcpuTimeCallbackError::WhiteboxCallback { source })?;
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

    pub(super) fn arm_idle_advance(
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

    pub(super) fn complete_idle_advance(
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
                        .checked_mul(crucible_qemu_shmem::TICKS_PER_INSTRUCTION)
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
        let emitted_network_output = !pending.buffered_tx_payloads.is_empty();
        let mut output_stop = if emitted_network_output {
            Some(self.begin_network_output_stop(
                target_icount,
                self.last_raw_icount.load(Ordering::Acquire),
                "idle-advance-completion",
            )?)
        } else {
            None
        };
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
        if let Some(mut output_stop) = output_stop.take() {
            let original = self.finish_network_output_stop(
                &mut output_stop,
                target_icount,
                self.last_raw_icount.load(Ordering::Acquire),
                network_output_stop::ArmOrigin::IdleAdvanceCompletion,
            )?;
            drop(output_stop);
            self.request_network_output_stop(original)?;
        } else {
            PluginShmemOrdering::publish_reached_icount(self.slot.get(), target_icount)
                .map_err(|source| LiveVcpuTimeCallbackError::PublishIcount { source })?;
        }
        Ok(target_icount)
    }
}
