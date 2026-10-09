//! Per-node shared-memory publication and control operations.

use super::control_effect::BoundaryWriter;
use super::*;

impl NodeSlot {
    /// Builds a zeroed node slot with `max_advance_icount` held at the boot barrier.
    #[must_use]
    pub const fn new(kind: u8) -> Self {
        Self::new_with_status(kind, STATUS_IDLE)
    }

    pub(crate) const fn new_with_status(kind: u8, status: u8) -> Self {
        Self {
            current_icount: AtomicU64::new(0),
            current_ns: AtomicU64::new(0),
            max_advance_icount: AtomicU64::new(0),
            idle_wake_icount: AtomicU64::new(0),
            wake_signal: AtomicU32::new(0),
            status: AtomicU8::new(status),
            kind: AtomicU8::new(kind),
            device_io_active: AtomicU8::new(0),
            advance_stop_condition: AtomicU8::new(ADVANCE_STOP_CONDITION_CEILING),
            publish_gen: AtomicU32::new(0),
            // Odd values are acknowledged; the host publishes the even
            // successor while one main-loop control boundary is requested.
            control_boundary_ack: AtomicU32::new(1),
            device_completion_deadline_tick: AtomicU64::new(0),
            preemption_at_tick: AtomicU64::new(0),
            preemption_deadline_tick: AtomicU64::new(0),
            preemption_ceiling_tick: AtomicU64::new(0),
            preemption_published_sequence: AtomicU32::new(0),
            preemption_consumed_sequence: AtomicU32::new(0),
            preemption_arg0: AtomicU32::new(0),
            preemption_arg1: AtomicU32::new(0),
            preemption_kind: AtomicU8::new(PREEMPTION_KIND_NONE),
            _pad2: [0; 7],
            logical_time_raw_icount: AtomicU64::new(0),
            logical_time_restore_target: AtomicU64::new(0),
            logical_time_restore_request: AtomicU32::new(0),
            logical_time_restore_ack: AtomicU32::new(0),
            control_boundary_fault_command_frontier: AtomicU64::new(0),
            control_boundary_capture_request: AtomicU32::new(0),
            control_boundary_publication_claim: AtomicU32::new(0),
            timer_witness_generation: AtomicU64::new(0),
            timer_witness_deadline_ps: AtomicU64::new(0),
            timer_witness_deadline_tick: AtomicU64::new(0),
            timer_witness_armed_raw_icount: AtomicU64::new(0),
            timer_witness_fired_expire_ps: AtomicU64::new(0),
            timer_witness_fired_virtual_ps: AtomicU64::new(0),
            timer_witness_fired_raw_icount: AtomicU64::new(0),
            timer_witness_completed: AtomicU32::new(0),
            timer_witness_reserved: AtomicU32::new(0),
            advance_publication_sequence: AtomicU64::new(0),
            _pad4: [0; 40],
        }
    }

    /// Publishes one plugin-validated actual virtual-timer callback witness.
    pub fn publish_virtual_timer_witness(&self, witness: VirtualTimerFireWitness) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.timer_witness_deadline_ps
            .store(witness.deadline_ps, Ordering::Release);
        self.timer_witness_deadline_tick
            .store(witness.deadline_tick, Ordering::Release);
        self.timer_witness_armed_raw_icount
            .store(witness.armed_raw_icount, Ordering::Release);
        self.timer_witness_fired_expire_ps
            .store(witness.fired_expire_ps, Ordering::Release);
        self.timer_witness_fired_virtual_ps
            .store(witness.fired_virtual_ps, Ordering::Release);
        self.timer_witness_fired_raw_icount
            .store(witness.fired_raw_icount, Ordering::Release);
        self.timer_witness_completed
            .store(witness.completed, Ordering::Release);
        self.timer_witness_reserved
            .store(witness.reserved, Ordering::Release);
        self.timer_witness_generation
            .store(witness.generation, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Publishes one scheduler advance with explicit completion semantics.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::CeilingBeforePublishedCurrent`] when the ceiling
    /// is behind the slot's published current icount, or
    /// [`NodeSlotError::FutexWake`] when the non-private futex wake fails.
    pub fn publish_scheduler_advance(
        &self,
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
    ) -> Result<WakeAction, NodeSlotError> {
        self.publish_scheduler_advance_with_effect(ceiling, stop_condition, |_| {})
    }

    /// Publishes a scheduler ceiling with an already-prepared local effect.
    ///
    /// The original writer supplies its exact next even sequence after storing
    /// the ceiling and before its release publication or wake. The effect must
    /// not allocate, wait, or perform fallible work. Its caller must prepare all
    /// storage and authenticate any additional owner before entering this method.
    /// No phase or native execution authority is conferred by the sequence.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] for an invalid ceiling or a failed futex wake.
    /// A wake failure leaves the preceding publication and effect committed.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `effect`. The ceiling writer closes coherently
    /// during unwind, but its wake and caller-specific effects are incomplete.
    pub fn publish_scheduler_advance_with_effect(
        &self,
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
        effect: impl FnOnce(SchedulerAdvanceSequence),
    ) -> Result<WakeAction, NodeSlotError> {
        self.validate_scheduler_ceiling(ceiling)?;
        self.publish_prevalidated_scheduler_ceiling_with_effect(ceiling, stop_condition, effect)
    }

    /// Arms a ceiling for an externally restored execution state without waking it.
    ///
    /// A process supervisor uses this only while the external executor is
    /// quiesced immediately before restoring state whose first published
    /// instruction counter may be ahead of this slot's current value. Unlike a
    /// normal scheduler handoff, this operation deliberately does not increment
    /// the futex word: the restore command, not a scheduler quantum, owns the
    /// executor transition. The restored executor must publish its exact current
    /// state before normal scheduling resumes.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::CeilingBeforePublishedCurrent`] when
    /// `restored_icount` is behind the slot's currently published counter.
    pub fn arm_external_state_restore_ceiling(
        &self,
        restored_icount: u64,
    ) -> Result<(), NodeSlotError> {
        let ceiling = AdvanceCeiling {
            current_icount: self.current_icount.load(Ordering::Acquire),
            max_advance_icount: restored_icount,
        };
        self.validate_scheduler_ceiling(ceiling)?;
        self.publish_scheduler_advance_fields(restored_icount, AdvanceStopCondition::Ceiling);
        Ok(())
    }

    /// Publishes pending inbox frames, then the scheduler ceiling, then the wake.
    ///
    /// This borrowed-ring variant is for runtime adapters that hold one node
    /// slot and one inbound SPSC ring rather than a typed [`RegionAllocation`].
    /// It validates the ceiling and ring capacity before publishing any frame,
    /// release-publishes every frame to the inbox, release-publishes the
    /// ceiling, and only then increments the non-private futex wake word.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerWakePublicationError`] when the node slot rejects the
    /// ceiling, an input frame is stamped with a different source than
    /// `src_slot`, the inbox rejects the batch, or the futex wake fails.
    // crucible-lint: allow rust-allow -- the borrowed adapter binds every independent ring and scheduler-advance input explicitly.
    #[allow(
        clippy::too_many_arguments,
        reason = "the borrowed adapter binds one directed ring and one typed scheduler advance"
    )]
    pub fn publish_scheduler_inbox_and_advance(
        &self,
        dst_slot: u32,
        src_slot: u32,
        inbox: &RingHeader,
        inbox_entries: &mut [FrameEntry],
        pending_inputs: &[FrameEntry],
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
    ) -> Result<SchedulerWakePublication, SchedulerWakePublicationError> {
        self.publish_scheduler_inbox_and_advance_with_effect(
            dst_slot,
            src_slot,
            inbox,
            inbox_entries,
            pending_inputs,
            ceiling,
            stop_condition,
            |_| {},
        )
    }

    /// Publishes an inbox batch and an already-prepared advance effect in order.
    ///
    /// The caller must reserve effect storage before calling this method. Source,
    /// ceiling and ring preflight precede inbox changes. The local effect runs
    /// inside the original scheduler writer before its even release and wake.
    /// It must not allocate, wait, or fail; it supplies no execution authority.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerWakePublicationError`] under the same conditions as
    /// [`Self::publish_scheduler_inbox_and_advance`]. A failure after publication
    /// does not undo the already-published input or effect.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `effect`. Published inputs remain published and
    /// the ceiling writer closes, but the original wake has not completed.
    // crucible-lint: allow rust-allow -- the borrowed adapter retains explicit ring, advance and prepared local effect inputs.
    #[allow(
        clippy::too_many_arguments,
        reason = "the borrowed adapter binds one directed ring and one typed scheduler advance"
    )]
    pub fn publish_scheduler_inbox_and_advance_with_effect(
        &self,
        dst_slot: u32,
        src_slot: u32,
        inbox: &RingHeader,
        inbox_entries: &mut [FrameEntry],
        pending_inputs: &[FrameEntry],
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
        effect: impl FnOnce(SchedulerAdvanceSequence),
    ) -> Result<SchedulerWakePublication, SchedulerWakePublicationError> {
        self.validate_scheduler_ceiling(ceiling)?;
        for (input_index, frame) in pending_inputs.iter().enumerate() {
            crate::region::helpers::validate_pending_input_source(input_index, src_slot, frame)?;
        }
        crate::region::helpers::preflight_ring_enqueue_capacity(
            inbox,
            inbox_entries,
            pending_inputs.len(),
        )
        .map_err(RegionAllocationAccessError::from)?;

        for frame in pending_inputs {
            inbox
                .enqueue(inbox_entries, frame)
                .map_err(RegionAllocationAccessError::from)?;
        }

        let wake = self.publish_prevalidated_scheduler_ceiling_with_effect(
            ceiling,
            stop_condition,
            effect,
        )?;
        Ok(SchedulerWakePublication {
            dst_slot,
            pending_input_count: pending_inputs.len(),
            max_advance_icount: ceiling.max_advance_icount,
            wake,
        })
    }

    /// Loads a scheduler ceiling paired with a stable advance-stop condition.
    ///
    /// The publication sequence excludes both partial transitions and a full
    /// ceiling-to-next-idle-to-ceiling ABA while the tuple is being read.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::InvalidAdvanceStopCondition`] when the stable
    /// tuple contains an unknown current-ABI encoding.
    pub fn load_scheduler_advance(&self) -> Result<(u64, AdvanceStopCondition), NodeSlotError> {
        let publication = self.load_scheduler_advance_publication()?;
        Ok((publication.ceiling(), publication.stop()))
    }

    /// Retains the exact original coherent scheduler-advance observation.
    ///
    /// This publication receipt confers no execution or phase authority.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] for an unknown completion-condition encoding.
    pub fn load_scheduler_advance_publication(
        &self,
    ) -> Result<SchedulerAdvancePublication, NodeSlotError> {
        let (ceiling, encoded, sequence) = self.load_scheduler_advance_raw();
        Ok(SchedulerAdvancePublication {
            ceiling,
            stop: AdvanceStopCondition::decode(encoded)?,
            sequence,
        })
    }

    /// Publishes that this node has plugin-submitted device I/O in flight.
    pub fn mark_device_io_active(&self) {
        self.publish_device_io_active(true);
    }

    /// Publishes that this node no longer has plugin-submitted device I/O in flight.
    pub fn clear_device_io_active(&self) {
        self.publish_device_io_active(false);
    }

    /// Returns whether plugin-submitted device I/O is currently active.
    #[must_use]
    pub fn load_device_io_active(&self) -> bool {
        self.device_io_active.load(Ordering::Acquire) != 0
    }

    /// Checks whether a node may advance to `next_icount` under the current ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::NodeAdvancePastCeiling`] when `next_icount`
    /// exceeds the acquire-loaded scheduler ceiling.
    pub fn check_node_may_advance_to(&self, next_icount: u64) -> Result<(), NodeSlotError> {
        let (max_advance_icount, _) = self.load_scheduler_advance()?;
        if next_icount > max_advance_icount {
            Err(NodeSlotError::NodeAdvancePastCeiling {
                next_icount,
                max_advance_icount,
            })
        } else {
            Ok(())
        }
    }

    /// Publishes the reached icount and derived virtual time while the node runs.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when the reached icount exceeds the published
    /// ceiling.
    pub fn publish_reached_icount(&self, reached_icount: u64) -> Result<(), NodeSlotError> {
        self.check_node_may_advance_to(reached_icount)?;
        let current_ns = icount_to_virtual_ns(reached_icount);
        self.publish_state(reached_icount, current_ns, None, STATUS_RUNNING);
        Ok(())
    }

    /// Publishes that the node is idle and prepares the futex wait precondition.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when `reached_icount` exceeds the published
    /// ceiling, `idle_wake_icount` is behind `reached_icount`.
    pub fn publish_idle(
        &self,
        reached_icount: u64,
        idle_wake_icount: u64,
    ) -> Result<FutexWait, NodeSlotError> {
        self.check_node_may_advance_to(reached_icount)?;
        if idle_wake_icount < reached_icount {
            return Err(NodeSlotError::IdleWakeBeforeCurrent {
                current_icount: reached_icount,
                idle_wake_icount,
            });
        }

        let current_ns = icount_to_virtual_ns(reached_icount);
        self.publish_state(
            reached_icount,
            current_ns,
            Some(idle_wake_icount),
            STATUS_IDLE,
        );
        Ok(self.prepare_futex_wait())
    }

    /// Publishes that a node quiesced at a pause boundary.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] if the publication violates node state.
    pub fn publish_pause_quiesced(
        &self,
        reached_icount: u64,
        raw_icount: u64,
    ) -> Result<(), NodeSlotError> {
        self.publish_pause_quiesced_with_effect(reached_icount, raw_icount, |_| {
            Ok::<_, std::convert::Infallible>(())
        })
        .map_err(NodeBoundaryPublicationError::into_slot)
    }

    /// Publishes the original pause fields before one prepared local effect.
    ///
    /// No scheduler-advance read or ceiling check is added to this pause writer.
    /// The effect must refuse before mutating its accepted state, then commit
    /// infallibly. It must not block, allocate, perform IO or change authority.
    /// This method publishes no control acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns original slot validation errors or the effect's original refusal.
    /// Refusal closes the node publication coherently but does not roll back the
    /// original boundary stores or a caller's incorrectly partial effect.
    ///
    /// # Panics
    ///
    /// Propagates an effect panic after closing the original node publication.
    pub fn publish_pause_quiesced_with_effect<E>(
        &self,
        reached_icount: u64,
        raw_icount: u64,
        effect: impl FnOnce(NodeBoundaryPublication) -> Result<(), E>,
    ) -> Result<(), NodeBoundaryPublicationError<E>> {
        validate_raw_retirement_at_tick(raw_icount, reached_icount)
            .map_err(NodeBoundaryPublicationError::Slot)?;
        let current_ns = icount_to_virtual_ns(reached_icount);
        let writer = BoundaryWriter::enter(&self.publish_gen);
        self.current_icount.store(reached_icount, Ordering::Release);
        self.current_ns.store(current_ns, Ordering::Release);
        self.idle_wake_icount
            .store(reached_icount, Ordering::Release);
        self.logical_time_raw_icount
            .store(raw_icount, Ordering::Release);
        self.status.store(STATUS_IDLE, Ordering::Release);
        effect(NodeBoundaryPublication {
            logical: reached_icount,
            raw: raw_icount,
            advance: None,
            closed_generation: writer.closed_generation(),
        })
        .map_err(NodeBoundaryPublicationError::Effect)
    }

    /// Republishes the exact coordinate observed by a QEMU control callback.
    ///
    /// At the scheduler ceiling, the callback publishes an exact idle boundary:
    /// the vCPU has yielded, the ceiling prevents another dispatch, and QEMU has
    /// already run the preceding device bottom halves. An existing idle
    /// publication retains its future wake deadline so the scheduler can still
    /// classify an early pause against the original quantum horizon. A
    /// previously running node instead receives the exact ceiling as its idle
    /// coordinate. Below the ceiling, the publication preserves the preceding
    /// classification because an arbitrary main-loop yield is not proof of
    /// scheduler idleness. Device work is represented independently by
    /// `device_io_active`.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when `reached_icount` exceeds the scheduler
    /// ceiling.
    pub fn publish_control_boundary(
        &self,
        reached_icount: u64,
        raw_icount: u64,
    ) -> Result<(), NodeSlotError> {
        self.publish_control_boundary_with_effect(reached_icount, raw_icount, |_| {
            Ok::<_, std::convert::Infallible>(())
        })
        .map_err(NodeBoundaryPublicationError::into_slot)
    }

    /// Publishes original control fields and their same-read advance receipt.
    ///
    /// The effect has the same refusal/commit contract as
    /// [`Self::publish_pause_quiesced_with_effect`]. The original odd control
    /// ACK remains the caller's separate final operation.
    ///
    /// # Errors
    ///
    /// Returns original validation errors or a refusal before accepted effects.
    ///
    /// # Panics
    ///
    /// Propagates an effect panic after closing the original publication.
    pub fn publish_control_boundary_with_effect<E>(
        &self,
        reached_icount: u64,
        raw_icount: u64,
        effect: impl FnOnce(NodeBoundaryPublication) -> Result<(), E>,
    ) -> Result<(), NodeBoundaryPublicationError<E>> {
        let advance = self
            .load_scheduler_advance_publication()
            .map_err(NodeBoundaryPublicationError::Slot)?;
        let max_advance_icount = advance.ceiling();
        let stop_condition = advance.stop();
        if reached_icount > max_advance_icount {
            return Err(NodeBoundaryPublicationError::Slot(
                NodeSlotError::NodeAdvancePastCeiling {
                    next_icount: reached_icount,
                    max_advance_icount,
                },
            ));
        }
        validate_raw_retirement_at_tick(raw_icount, reached_icount)
            .map_err(NodeBoundaryPublicationError::Slot)?;
        let current_ns = icount_to_virtual_ns(reached_icount);
        let was_idle = self.status.load(Ordering::Acquire) == STATUS_IDLE;
        let writer = BoundaryWriter::enter(&self.publish_gen);
        self.current_icount.store(reached_icount, Ordering::Release);
        self.current_ns.store(current_ns, Ordering::Release);
        self.logical_time_raw_icount
            .store(raw_icount, Ordering::Release);
        if reached_icount == max_advance_icount && stop_condition == AdvanceStopCondition::Ceiling {
            if !was_idle {
                self.idle_wake_icount
                    .store(reached_icount, Ordering::Release);
            }
            self.status.store(STATUS_IDLE, Ordering::Release);
        }
        effect(NodeBoundaryPublication {
            logical: reached_icount,
            raw: raw_icount,
            advance: Some(advance),
            closed_generation: writer.closed_generation(),
        })
        .map_err(NodeBoundaryPublicationError::Effect)
    }

    /// Arms one host-to-plugin logical-time restore transaction.
    ///
    /// The caller must hold the external executor stopped. The returned
    /// generation identifies the request that the plugin must acknowledge
    /// after VMState has restored QEMU's raw icount.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::LogicalTimeRestoreAlreadyPending`] when a prior
    /// request has not been acknowledged.
    pub fn arm_logical_time_restore(&self, target_icount: u64) -> Result<u32, NodeSlotError> {
        let request = self.logical_time_restore_request.load(Ordering::Acquire);
        let ack = self.logical_time_restore_ack.load(Ordering::Acquire);
        if request != ack {
            return Err(NodeSlotError::LogicalTimeRestoreAlreadyPending { request, ack });
        }
        let mut next = request.wrapping_add(1);
        if next == 0 {
            next = 1;
        }
        self.logical_time_restore_target
            .store(target_icount, Ordering::Release);
        self.logical_time_restore_request
            .store(next, Ordering::Release);
        Ok(next)
    }

    /// Returns the pending logical-time restore request, if any.
    #[must_use]
    pub fn pending_logical_time_restore(&self) -> Option<LogicalTimeRestoreRequest> {
        let request = self.logical_time_restore_request.load(Ordering::Acquire);
        let ack = self.logical_time_restore_ack.load(Ordering::Acquire);
        (request != ack).then(|| LogicalTimeRestoreRequest {
            generation: request,
            target_icount: self.logical_time_restore_target.load(Ordering::Acquire),
        })
    }

    /// Acknowledges a logical-time restore and publishes its exact boundary.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when the request is stale or its logical target
    /// differs from `reached_icount`.
    pub fn acknowledge_logical_time_restore(
        &self,
        request: LogicalTimeRestoreRequest,
        reached_icount: u64,
        raw_icount: u64,
    ) -> Result<(), NodeSlotError> {
        let published_request = self.logical_time_restore_request.load(Ordering::Acquire);
        if published_request != request.generation {
            return Err(NodeSlotError::LogicalTimeRestoreRequestChanged {
                expected: request.generation,
                observed: published_request,
            });
        }
        if request.target_icount != reached_icount {
            return Err(NodeSlotError::LogicalTimeRestoreTargetMismatch {
                requested: request.target_icount,
                reached: reached_icount,
            });
        }
        validate_raw_retirement_at_tick(raw_icount, reached_icount)?;
        let current_ns = icount_to_virtual_ns(reached_icount);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.current_icount.store(reached_icount, Ordering::Release);
        self.current_ns.store(current_ns, Ordering::Release);
        self.idle_wake_icount
            .store(reached_icount, Ordering::Release);
        self.logical_time_raw_icount
            .store(raw_icount, Ordering::Release);
        self.status.store(STATUS_IDLE, Ordering::Release);
        self.logical_time_restore_ack
            .store(request.generation, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Marks a woken node as running.
    pub fn mark_running(&self) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.status.store(STATUS_RUNNING, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Marks a node as done after it observes shutdown.
    pub fn mark_done(&self) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.status.store(STATUS_DONE, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Returns a stable snapshot of the slot's published fields.
    ///
    /// This producer-side convenience waits for both publications. Host
    /// supervision uses [`Self::try_snapshot`] so an interrupted writer cannot
    /// prevent its independent deadline or child-exit check from running.
    #[must_use]
    pub fn snapshot(&self) -> NodeSlotSnapshot {
        loop {
            if let Some(snapshot) = self.try_snapshot() {
                return snapshot;
            }
        }
    }

    /// Attempts one coherent read without waiting for either publication.
    ///
    /// Returns `None` when the node or scheduler publication is in progress or
    /// changes during the read. No partially published fields are returned.
    /// The caller owns any retry and its original liveness deadline.
    #[must_use]
    pub fn try_snapshot(&self) -> Option<NodeSlotSnapshot> {
        self.try_snapshot_with_control_claim(0)
    }

    pub(super) fn try_snapshot_with_control_claim(
        &self,
        expected_claim: u32,
    ) -> Option<NodeSlotSnapshot> {
        let control_claim = self
            .control_boundary_publication_claim
            .load(Ordering::Acquire);
        let before = self.publish_gen.load(Ordering::Acquire);
        if control_claim != expected_claim || !before.is_multiple_of(2) {
            return None;
        }
        // Read the independently published control acknowledgement before
        // the fields it orders. Its acquire pairs with the plugin's release
        // only for operations that follow this load; reading it later could
        // return a new acknowledgement beside slot fields fetched before
        // the corresponding control callback published them.
        let control_boundary_ack = self.control_boundary_ack.load(Ordering::Acquire);
        let (max_advance_icount, advance_stop_condition, advance_publication_sequence) =
            self.try_load_scheduler_advance_raw()?;
        let snapshot = NodeSlotSnapshot {
            current_icount: self.current_icount.load(Ordering::Acquire),
            current_ns: self.current_ns.load(Ordering::Acquire),
            max_advance_icount,
            idle_wake_icount: self.idle_wake_icount.load(Ordering::Acquire),
            wake_signal: self.wake_signal.load(Ordering::Acquire),
            status: self.status.load(Ordering::Acquire),
            kind: self.kind.load(Ordering::Acquire),
            device_io_active: self.device_io_active.load(Ordering::Acquire),
            advance_stop_condition,
            advance_publication_sequence,
            publish_gen: before,
            control_boundary_ack,
            control_boundary_fault_command_frontier: self
                .control_boundary_fault_command_frontier
                .load(Ordering::Acquire),
            control_boundary_capture_request: self
                .control_boundary_capture_request
                .load(Ordering::Acquire),
            logical_time_raw_icount: self.logical_time_raw_icount.load(Ordering::Acquire),
            logical_time_restore_target: self.logical_time_restore_target.load(Ordering::Acquire),
            logical_time_restore_request: self.logical_time_restore_request.load(Ordering::Acquire),
            logical_time_restore_ack: self.logical_time_restore_ack.load(Ordering::Acquire),
            virtual_timer_witness: match self.timer_witness_generation.load(Ordering::Acquire) {
                0 => None,
                generation => Some(VirtualTimerFireWitness {
                    generation,
                    deadline_ps: self.timer_witness_deadline_ps.load(Ordering::Acquire),
                    deadline_tick: self.timer_witness_deadline_tick.load(Ordering::Acquire),
                    armed_raw_icount: self.timer_witness_armed_raw_icount.load(Ordering::Acquire),
                    fired_expire_ps: self.timer_witness_fired_expire_ps.load(Ordering::Acquire),
                    fired_virtual_ps: self.timer_witness_fired_virtual_ps.load(Ordering::Acquire),
                    fired_raw_icount: self.timer_witness_fired_raw_icount.load(Ordering::Acquire),
                    completed: self.timer_witness_completed.load(Ordering::Acquire),
                    reserved: self.timer_witness_reserved.load(Ordering::Acquire),
                }),
            },
        };
        if expected_claim == 0 {
            self.finish_snapshot_read(snapshot)
        } else {
            self.finish_snapshot_read_with_control_claim(snapshot, expected_claim)
        }
    }

    // The final ACK check excludes a whole host request interval between the
    // two claim reads. A released claim alone cannot identify that interval.
    pub(super) fn finish_snapshot_read(
        &self,
        snapshot: NodeSlotSnapshot,
    ) -> Option<NodeSlotSnapshot> {
        self.finish_snapshot_read_with_control_claim(snapshot, 0)
    }

    fn finish_snapshot_read_with_control_claim(
        &self,
        snapshot: NodeSlotSnapshot,
        expected_claim: u32,
    ) -> Option<NodeSlotSnapshot> {
        let after = self.publish_gen.load(Ordering::Acquire);
        let scheduler_after = self.advance_publication_sequence.load(Ordering::Acquire);
        if snapshot.publish_gen == after
            && self
                .control_boundary_publication_claim
                .load(Ordering::Acquire)
                == expected_claim
            && after.is_multiple_of(2)
            && scheduler_after == snapshot.advance_publication_sequence
            && scheduler_after.is_multiple_of(2)
            && self.control_boundary_ack.load(Ordering::Acquire) == snapshot.control_boundary_ack
        {
            return Some(snapshot);
        }
        None
    }

    /// Returns `true` when all forward-compatible reserved slot bytes are zero.
    #[must_use]
    pub fn reserved_bytes_are_zero(&self) -> bool {
        self._pad2.iter().all(|byte| *byte == 0) && self._pad4.iter().all(|byte| *byte == 0)
    }

    /// Requests one QEMU main-loop control boundary and wakes an idle plugin.
    ///
    /// Odd values are acknowledged tokens. The host publishes their even
    /// successor as the request and leaves an already-outstanding even request
    /// unchanged. The plugin must publish the boundary state before storing the
    /// odd successor as its release acknowledgement.
    ///
    /// The plugin's vCPU-resume callback recognizes the outstanding even token
    /// and preserves its halt/idle classification while returning control to
    /// QEMU's main loop. The caller also rings QEMU's eventfd after publication.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::FutexWake`] when the non-private futex wake
    /// syscall fails.
    pub fn request_control_boundary(
        &self,
        fault_command_frontier: u64,
        capture_request: Option<u32>,
    ) -> Result<u32, NodeSlotError> {
        self.request_control_boundary_with_effect(fault_command_frontier, capture_request, |_| {})
    }

    /// Retains the original request pairing before either wake can fail.
    ///
    /// The prepared effect runs once after the original successful publication
    /// or exact idempotent pending request, before the futex wake. It must not
    /// allocate, block or fail, and reobservation must not duplicate custody.
    ///
    /// # Errors
    ///
    /// Returns original capture/frontier validation or futex-wake errors. A
    /// wake failure preserves the published request and its retained pairing.
    ///
    /// # Panics
    ///
    /// Propagates an effect panic; the already-published request remains pending.
    pub fn request_control_boundary_with_effect(
        &self,
        fault_command_frontier: u64,
        capture_request: Option<u32>,
        effect: impl FnOnce(u32),
    ) -> Result<u32, NodeSlotError> {
        self.request_control_boundary_with_effect_and_wake(
            fault_command_frontier,
            capture_request,
            effect,
            || self.wake_after_signal_increment(),
        )
    }

    pub(super) fn request_control_boundary_with_effect_and_wake(
        &self,
        fault_command_frontier: u64,
        capture_request: Option<u32>,
        effect: impl FnOnce(u32),
        wake: impl FnOnce() -> Result<WakeAction, FutexError>,
    ) -> Result<u32, NodeSlotError> {
        self.request_control_boundary_with_fields_and_wake(
            fault_command_frontier,
            capture_request,
            None::<fn(PreparedControlBoundaryRequest)>,
            effect,
            wake,
        )
    }

    /// Publishes prepared native-readable fields before the request Release.
    ///
    /// The fields effect runs only for a new request, before it is observable
    /// through the original CAS. All fallible storage and owner checks must
    /// already be complete. The retained effect runs after successful request
    /// publication and before wake, preserving local custody on wake failure.
    /// An already-pending exact request retains its existing fields.
    ///
    /// A shared nonblocking host claim excludes all other request publishers
    /// before any metadata or paired fields change. Matching codec fields alone
    /// never prove phase authority.
    ///
    /// # Errors
    ///
    /// Returns original frontier/capture/wake failures or a competing request
    /// publication. A busy contender changes neither the request nor its fields.
    ///
    /// # Panics
    ///
    /// Propagates an effect panic. A fields panic precedes request publication;
    /// a retained-effect panic leaves its already-published request pending.
    pub fn request_control_boundary_with_prepared_fields(
        &self,
        fault_command_frontier: u64,
        capture_request: Option<u32>,
        fields: impl FnOnce(PreparedControlBoundaryRequest),
        retained: impl FnOnce(u32),
    ) -> Result<u32, NodeSlotError> {
        self.request_control_boundary_with_fields_and_wake(
            fault_command_frontier,
            capture_request,
            Some(fields),
            retained,
            || self.wake_after_signal_increment(),
        )
    }

    pub(super) fn request_control_boundary_with_fields_and_wake(
        &self,
        fault_command_frontier: u64,
        capture_request: Option<u32>,
        fields: Option<impl FnOnce(PreparedControlBoundaryRequest)>,
        effect: impl FnOnce(u32),
        wake: impl FnOnce() -> Result<WakeAction, FutexError>,
    ) -> Result<u32, NodeSlotError> {
        // Every host request publisher shares this claim, including ordinary
        // requests. A contender cannot overwrite metadata or paired fields
        // belonging to the same proposed even successor.
        self.control_boundary_publication_claim
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| NodeSlotError::ControlBoundaryPublicationBusy)?;
        self.request_control_boundary_claimed_with_fields_and_wake(
            ControlBoundaryPublicationClaim(&self.control_boundary_publication_claim),
            fault_command_frontier,
            capture_request,
            fields,
            effect,
            wake,
        )
    }

    pub(super) fn request_control_boundary_claimed_with_fields_and_wake(
        &self,
        publication: ControlBoundaryPublicationClaim<'_>,
        fault_command_frontier: u64,
        capture_request: Option<u32>,
        mut fields: Option<impl FnOnce(PreparedControlBoundaryRequest)>,
        effect: impl FnOnce(u32),
        wake: impl FnOnce() -> Result<WakeAction, FutexError>,
    ) -> Result<u32, NodeSlotError> {
        if !core::ptr::eq(publication.0, &self.control_boundary_publication_claim)
            || publication.0.load(Ordering::Acquire) != 1
        {
            return Err(NodeSlotError::ControlBoundaryPublicationBusy);
        }
        let capture_request = capture_request.unwrap_or(0);
        if capture_request != 0 && capture_request & 1 == 0 {
            return Err(NodeSlotError::InvalidControlBoundaryCaptureRequest {
                request: capture_request,
            });
        }
        let request = loop {
            let observed = self.control_boundary_ack.load(Ordering::Acquire);
            if observed & 1 == 0 {
                let observed_frontier = self
                    .control_boundary_fault_command_frontier
                    .load(Ordering::Acquire);
                let observed_capture = self
                    .control_boundary_capture_request
                    .load(Ordering::Acquire);
                if observed_frontier != fault_command_frontier
                    || observed_capture != capture_request
                {
                    return Err(NodeSlotError::ControlBoundaryRequestChanged {
                        expected_frontier: observed_frontier,
                        observed_frontier: fault_command_frontier,
                        expected_capture_request: observed_capture,
                        observed_capture_request: capture_request,
                    });
                }
                break observed;
            }
            let request = observed.wrapping_add(1);
            self.control_boundary_fault_command_frontier
                .store(fault_command_frontier, Ordering::Relaxed);
            self.control_boundary_capture_request
                .store(capture_request, Ordering::Relaxed);
            let fields_prepared = fields.is_some();
            if let Some(fields) = fields.take() {
                fields(PreparedControlBoundaryRequest(request));
            }
            match self.control_boundary_ack.compare_exchange(
                observed,
                request,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break request,
                Err(observed) if fields_prepared => {
                    return Err(NodeSlotError::ControlBoundaryPublicationRaced {
                        expected: request,
                        observed,
                    });
                }
                Err(_) => continue,
            }
        };
        effect(request);
        // A woken consumer must see completed slot/pair fields immediately.
        // Releasing after wake could let it park on the held claim forever.
        drop(publication);
        wake().map_err(|source| NodeSlotError::FutexWake { source })?;
        Ok(request)
    }

    /// Returns the fault-command frontier bound to the pending control request.
    #[must_use]
    pub fn control_boundary_fault_command_frontier(&self) -> u64 {
        self.control_boundary_fault_command_frontier
            .load(Ordering::Acquire)
    }

    /// Returns the fingerprint request generation bound to the control request.
    #[must_use]
    pub fn control_boundary_capture_request(&self) -> Option<u32> {
        let request = self
            .control_boundary_capture_request
            .load(Ordering::Acquire);
        (request != 0).then_some(request)
    }

    /// Returns whether the host has published an unacknowledged even request.
    #[must_use]
    pub fn control_boundary_is_requested(&self) -> bool {
        self.control_boundary_ack.load(Ordering::Acquire) & 1 == 0
    }

    /// Returns the control request or acknowledgement from one acquire load.
    ///
    /// Even values identify pending requests; their odd successors acknowledge
    /// completion. This observational read does not snapshot other slot fields.
    #[must_use]
    pub fn control_boundary_token(&self) -> u32 {
        self.control_boundary_ack.load(Ordering::Acquire)
    }

    /// Release-acknowledges the currently requested QEMU main-loop boundary.
    ///
    /// The caller must publish the exact boundary state first. If no request is
    /// pending, this method is an idempotent no-op and returns the current odd
    /// acknowledgement.
    pub fn acknowledge_control_boundary(&self) -> u32 {
        let request = self.control_boundary_ack.load(Ordering::Acquire);
        if request & 1 != 0 {
            return request;
        }
        let acknowledgement = request.wrapping_add(1);
        self.control_boundary_ack
            .store(acknowledgement, Ordering::Release);
        acknowledgement
    }

    /// Publishes the host-computed device-completion deadline icount for this slot.
    ///
    /// This field is host-owned in the host-to-plugin direction: the host writes
    /// the exact icount at which a pending device completion for this VM will be
    /// delivered, and a time-owning plugin whose guest is blocked on device I/O
    /// idle-jumps virtual time to it. A value of zero means no device completion
    /// is pending. It is deliberately distinct from `idle_wake_icount` (which is
    /// plugin-published in the other direction) so the two directions never share
    /// one field.
    pub fn store_device_completion_deadline_tick(&self, icount: u64) {
        self.device_completion_deadline_tick
            .store(icount, Ordering::Release);
    }

    /// Returns the host-published device-completion deadline icount, or zero when
    /// no device completion is pending for this slot.
    #[must_use]
    pub fn device_completion_deadline_tick(&self) -> u64 {
        self.device_completion_deadline_tick.load(Ordering::Acquire)
    }

    fn publish_state(
        &self,
        current_icount: u64,
        current_ns: u64,
        idle_wake_icount: Option<u64>,
        status: u8,
    ) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.current_icount.store(current_icount, Ordering::Release);
        self.current_ns.store(current_ns, Ordering::Release);
        if let Some(idle_wake_icount) = idle_wake_icount {
            self.idle_wake_icount
                .store(idle_wake_icount, Ordering::Release);
        }
        self.status.store(status, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    fn publish_device_io_active(&self, active: bool) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.device_io_active
            .store(u8::from(active), Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn validate_scheduler_ceiling(
        &self,
        ceiling: AdvanceCeiling,
    ) -> Result<(), NodeSlotError> {
        let current_icount = self.current_icount.load(Ordering::Acquire);
        if ceiling.max_advance_icount < current_icount {
            Err(NodeSlotError::CeilingBeforePublishedCurrent {
                current_icount,
                max_advance_icount: ceiling.max_advance_icount,
            })
        } else {
            Ok(())
        }
    }

    pub(crate) fn publish_prevalidated_scheduler_ceiling(
        &self,
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
    ) -> Result<WakeAction, NodeSlotError> {
        self.publish_prevalidated_scheduler_ceiling_with_effect(ceiling, stop_condition, |_| {})
    }

    fn publish_prevalidated_scheduler_ceiling_with_effect(
        &self,
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
        effect: impl FnOnce(SchedulerAdvanceSequence),
    ) -> Result<WakeAction, NodeSlotError> {
        self.publish_prevalidated_scheduler_ceiling_with_wake(
            ceiling,
            stop_condition,
            effect,
            || self.wake_after_signal_increment(),
        )
    }

    /// Keeps the original publication body shared with the focused wake-error control.
    fn publish_prevalidated_scheduler_ceiling_with_wake(
        &self,
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
        effect: impl FnOnce(SchedulerAdvanceSequence),
        wake: impl FnOnce() -> Result<WakeAction, FutexError>,
    ) -> Result<WakeAction, NodeSlotError> {
        self.publish_scheduler_advance_fields_with_effect(
            ceiling.max_advance_icount,
            stop_condition,
            effect,
        );
        wake().map_err(|source| NodeSlotError::FutexWake { source })
    }

    #[cfg(test)]
    pub(super) fn publish_scheduler_advance_with_test_wake(
        &self,
        ceiling: AdvanceCeiling,
        effect: impl FnOnce(SchedulerAdvanceSequence),
        wake: impl FnOnce() -> Result<WakeAction, FutexError>,
    ) -> Result<WakeAction, NodeSlotError> {
        self.validate_scheduler_ceiling(ceiling)?;
        self.publish_prevalidated_scheduler_ceiling_with_wake(
            ceiling,
            AdvanceStopCondition::Ceiling,
            effect,
            wake,
        )
    }

    fn publish_scheduler_advance_fields(
        &self,
        max_advance_icount: u64,
        stop_condition: AdvanceStopCondition,
    ) {
        self.publish_scheduler_advance_fields_with_effect(
            max_advance_icount,
            stop_condition,
            |_| {},
        );
    }

    pub(super) fn publish_scheduler_advance_fields_with_effect(
        &self,
        max_advance_icount: u64,
        stop_condition: AdvanceStopCondition,
        effect: impl FnOnce(SchedulerAdvanceSequence),
    ) {
        let published_sequence = loop {
            let observed = self.advance_publication_sequence.load(Ordering::Acquire);
            if !observed.is_multiple_of(2) {
                core::hint::spin_loop();
                continue;
            }
            match self.advance_publication_sequence.compare_exchange(
                observed,
                observed.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break observed.wrapping_add(2),
                Err(_) => core::hint::spin_loop(),
            }
        };

        let publication = SchedulerAdvanceWriter {
            sequence: &self.advance_publication_sequence,
            published: published_sequence,
        };

        match stop_condition {
            AdvanceStopCondition::NextAuthenticatedIdle => {
                // A peer that observes the raised ceiling must also observe the
                // stop mode that prevents that ceiling from authorizing an idle
                // deadline.
                self.advance_stop_condition
                    .store(stop_condition.encode(), Ordering::Release);
                self.max_advance_icount
                    .store(max_advance_icount, Ordering::Release);
            }
            AdvanceStopCondition::Ceiling => {
                // A peer that observes the cleared mode must first observe the
                // clamp or replacement ceiling that bounds renewed execution.
                self.max_advance_icount
                    .store(max_advance_icount, Ordering::Release);
                self.advance_stop_condition
                    .store(stop_condition.encode(), Ordering::Release);
            }
        }

        effect(SchedulerAdvanceSequence(published_sequence));
        drop(publication);
    }

    pub(crate) fn load_scheduler_advance_raw(&self) -> (u64, u8, u64) {
        loop {
            if let Some(publication) = self.try_load_scheduler_advance_raw() {
                return publication;
            }
            core::hint::spin_loop();
        }
    }

    pub(super) fn try_load_scheduler_advance_raw(&self) -> Option<(u64, u8, u64)> {
        let before = self.advance_publication_sequence.load(Ordering::Acquire);
        if !before.is_multiple_of(2) {
            return None;
        }
        let stop_condition = self.advance_stop_condition.load(Ordering::Acquire);
        let max_advance_icount = self.max_advance_icount.load(Ordering::Acquire);
        let after = self.advance_publication_sequence.load(Ordering::Acquire);
        (before == after && after.is_multiple_of(2)).then_some((
            max_advance_icount,
            stop_condition,
            after,
        ))
    }

    pub(super) fn is_runnable_after_idle_publish(&self) -> bool {
        let Ok((max_advance_icount, AdvanceStopCondition::Ceiling)) = self.load_scheduler_advance()
        else {
            return false;
        };
        let status = self.status.load(Ordering::Acquire);
        let idle_wake_icount = self.idle_wake_icount.load(Ordering::Acquire);
        status != STATUS_IDLE || max_advance_icount >= idle_wake_icount
    }

    pub(crate) fn wake_after_signal_increment(&self) -> Result<WakeAction, FutexError> {
        let previous = self.wake_signal.fetch_add(1, Ordering::Release);
        let futex = self.futex_wake_nonprivate(1)?;
        Ok(WakeAction::Wake {
            previous,
            new: previous.wrapping_add(1),
            futex,
        })
    }
}

impl Default for NodeSlot {
    fn default() -> Self {
        Self::new(KIND_VM)
    }
}

fn validate_raw_retirement_at_tick(
    raw_icount: u64,
    logical_tick: u64,
) -> Result<(), NodeSlotError> {
    let retired_ticks = raw_icount.checked_mul(crate::TICKS_PER_INSTRUCTION);
    if retired_ticks.is_none_or(|ticks| ticks > logical_tick) {
        return Err(NodeSlotError::RawRetirementAhead {
            logical_icount: logical_tick,
            raw_icount,
        });
    }
    Ok(())
}

/// Completes a coherent ceiling even if an invalid local effect unwinds.
struct SchedulerAdvanceWriter<'a> {
    sequence: &'a AtomicU64,
    published: u64,
}

impl Drop for SchedulerAdvanceWriter<'_> {
    fn drop(&mut self) {
        self.sequence.store(self.published, Ordering::Release);
    }
}

// This host-only claim is not a native completion or phase receipt. Unwind
// clears it before another original request publisher may touch paired fields.
pub(super) struct ControlBoundaryPublicationClaim<'a>(pub(super) &'a AtomicU32);

impl Drop for ControlBoundaryPublicationClaim<'_> {
    fn drop(&mut self) {
        // An externally changed word is never ours to release.
        let _ = self
            .0
            .compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed);
    }
}
