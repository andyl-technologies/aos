//! Idle callback hot-loop state machine.
//!
//! QEMU enters this path when the guest node is idle. The module keeps the
//! deterministic core in safe Rust: publish the current clock, compute the next
//! idle wake from exact virtual deadlines and inbound delivery, prepare the
//! cross-process futex wait, consume a scheduler-authorized idle jump, expose due
//! frames in deterministic injection order, and republish the node as running.

use thiserror::Error;

use crucible_shmem::{
    FrameDeliveryKey, FrameEntry, FutexError, FutexWait, FutexWaitOutcome, NodeSlot, NodeSlotError,
    RegionControlAction, RegionHeader,
};

use crate::{
    ExactDeadlineError, ExactDeadlineReader, ExactDeadlineReport, InboundFrameError,
    InboundFrameRing, LosslessNetworkRxQueue, NetworkRxError, NetworkRxInjection,
    PendingIdleAdvance, PluginClockAdvance, PluginClockError, PluginDeviceIoFreeze,
    PluginInboundFrames, PluginNetworkRx, PluginVirtualClock, QueuedIdleAdvance,
    QueuedIdleAdvanceError, SchedulerCeiling, TimeAdvanceCompletion,
    handle_network_rx_idle_callback, shmem_ordering::PluginShmemOrdering,
};

/// The source that determined the node's next idle wake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleWakeCause {
    /// The earliest exact guest virtual-timer deadline woke the node.
    TimerDeadline,
    /// The head inbound frame delivery icount woke the node.
    InboundFrame,
    /// Device I/O is in flight, so guest timer deadlines are held.
    DeviceIoFreeze,
    /// No local timer or inbound input was pending, so the scheduler ceiling was the bound.
    SchedulerCeiling,
}

/// The computed idle wake before the plugin parks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleWakePlan {
    current_icount: u64,
    desired_wake_icount: u64,
    ceiling_icount: u64,
    timer_deadline_icount: Option<u64>,
    inbound_delivery_icount: Option<u64>,
    device_io_holding_ticks: bool,
    cause: IdleWakeCause,
}

impl IdleWakePlan {
    /// Returns the node icount observed at the idle transition.
    #[must_use]
    pub const fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns the local wake target published in `idle_wake_icount`.
    #[must_use]
    pub const fn desired_wake_icount(&self) -> u64 {
        self.desired_wake_icount
    }

    /// Returns the scheduler ceiling observed while publishing idle.
    #[must_use]
    pub const fn ceiling_icount(&self) -> u64 {
        self.ceiling_icount
    }

    /// Returns the exact timer deadline converted to icount, if one exists.
    #[must_use]
    pub const fn timer_deadline_icount(&self) -> Option<u64> {
        self.timer_deadline_icount
    }

    /// Returns the next inbound delivery icount, if one was peeked.
    #[must_use]
    pub const fn inbound_delivery_icount(&self) -> Option<u64> {
        self.inbound_delivery_icount
    }

    /// Returns whether device I/O suppressed guest timer deadlines.
    #[must_use]
    pub const fn device_io_holding_ticks(&self) -> bool {
        self.device_io_holding_ticks
    }

    /// Returns the source that selected [`Self::desired_wake_icount`].
    #[must_use]
    pub const fn cause(&self) -> IdleWakeCause {
        self.cause
    }

    /// Returns whether the current ceiling is still below the desired wake.
    #[must_use]
    pub const fn requires_scheduler_wait(&self) -> bool {
        self.ceiling_icount < self.desired_wake_icount
    }
}

/// A prepared idle park operation after publishing the node slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleParkRequest {
    plan: IdleWakePlan,
    futex_wait: FutexWait,
}

impl IdleParkRequest {
    /// Retains an already-published idle plan and its race-free futex precondition.
    pub(crate) const fn from_published(plan: IdleWakePlan, futex_wait: FutexWait) -> Self {
        Self { plan, futex_wait }
    }

    /// Returns the wake plan associated with this park request.
    #[must_use]
    pub const fn plan(&self) -> IdleWakePlan {
        self.plan
    }

    /// Returns the race-free futex wait decision from the shared-memory slot.
    #[must_use]
    pub const fn futex_wait(&self) -> FutexWait {
        self.futex_wait
    }
}

/// The reason an idle wait stopped blocking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleWaitOutcome {
    /// The scheduler raised the node ceiling to the desired wake icount.
    SchedulerReleased,
    /// The global control plane requested shutdown and the node marked itself done.
    ShutdownRequested,
}

/// The result of one completed idle hot-loop turn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdleHotLoopResult {
    wake_plan: IdleWakePlan,
    advance: PluginClockAdvance,
    pending_advance: PendingIdleAdvance,
    injected_frames: Vec<FrameEntry>,
    network_rx_injection: Option<NetworkRxInjection>,
}

impl IdleHotLoopResult {
    /// Returns the wake plan that drove the completed loop.
    #[must_use]
    pub const fn wake_plan(&self) -> IdleWakePlan {
        self.wake_plan
    }

    /// Returns the virtual-clock advance performed after scheduler release.
    #[must_use]
    pub const fn advance(&self) -> PluginClockAdvance {
        self.advance
    }

    /// Returns the QEMU advance token after normal-main-loop completion.
    #[must_use]
    pub const fn pending_advance(&self) -> PendingIdleAdvance {
        self.pending_advance
    }

    /// Returns due inbound frames in deterministic injection order.
    #[must_use]
    pub fn injected_frames(&self) -> &[FrameEntry] {
        &self.injected_frames
    }

    /// Returns the lossless network RX injection metadata, if this turn injected frames.
    #[must_use]
    pub fn network_rx_injection(&self) -> Option<&NetworkRxInjection> {
        self.network_rx_injection.as_ref()
    }
}

/// Deterministic idle hot-loop operations.
#[derive(Debug)]
pub struct PluginIdleHotLoop;

impl PluginIdleHotLoop {
    /// Reads QEMU's exact virtual deadline, publishes idle state, and prepares the futex wait.
    ///
    /// The caller supplies the already-peeked head inbound delivery icount. This
    /// keeps ring ownership outside the hot-loop core while preserving the
    /// non-consuming `peek_delivery_icount` contract.
    ///
    /// When a device callback owns a [`PluginDeviceIoFreeze`], it must pass that
    /// state so the local pending counter can suppress timer deadlines even if
    /// the shared-memory flag has not yet been observed.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when timer conversion, slot publication, or
    /// ceiling validation fails, or when the required exact-deadline read fails.
    pub fn begin_idle(
        slot: &NodeSlot,
        clock: &PluginVirtualClock,
        exact_deadline_reader: &ExactDeadlineReader,
        next_inbound_delivery_icount: Option<u64>,
        device_io_freeze: Option<&PluginDeviceIoFreeze>,
    ) -> Result<IdleParkRequest, IdleHotLoopError> {
        let exact_deadline = exact_deadline_reader
            .read_next_deadline()
            .map_err(|source| IdleHotLoopError::ReadExactDeadline { source })?;
        Self::begin_idle_from_report(
            slot,
            clock,
            exact_deadline,
            next_inbound_delivery_icount,
            device_io_freeze,
        )
    }

    /// Peeks inbound rings, reads QEMU's exact deadline, and prepares the idle wait.
    ///
    /// The optional device-I/O freeze state has the same pending-counter
    /// semantics as [`Self::begin_idle`].
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when inbound ring peeking fails, exact-deadline
    /// introspection fails, or idle publication fails.
    pub fn begin_idle_with_inbound_rings<'a>(
        slot: &NodeSlot,
        clock: &PluginVirtualClock,
        exact_deadline_reader: &ExactDeadlineReader,
        inbound_rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
        device_io_freeze: Option<&PluginDeviceIoFreeze>,
    ) -> Result<IdleParkRequest, IdleHotLoopError> {
        let inbound_rings = inbound_rings.into_iter().collect::<Vec<_>>();
        PluginInboundFrames::reject_already_passed_ring_heads(
            inbound_rings.iter().copied(),
            clock.current_icount(),
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        let next_inbound_delivery_icount =
            PluginInboundFrames::peek_next_delivery_icount(inbound_rings.iter().copied())
                .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        Self::begin_idle(
            slot,
            clock,
            exact_deadline_reader,
            next_inbound_delivery_icount,
            device_io_freeze,
        )
    }

    fn begin_idle_from_report(
        slot: &NodeSlot,
        clock: &PluginVirtualClock,
        exact_deadline: ExactDeadlineReport,
        next_inbound_delivery_icount: Option<u64>,
        device_io_freeze: Option<&PluginDeviceIoFreeze>,
    ) -> Result<IdleParkRequest, IdleHotLoopError> {
        let current_icount = clock.current_icount();
        let ceiling_icount = PluginShmemOrdering::load_scheduler_ceiling(slot);
        if ceiling_icount < current_icount {
            return Err(IdleHotLoopError::CeilingBehindCurrent {
                current_icount,
                ceiling_icount,
            });
        }
        reject_passed_inbound_delivery(current_icount, next_inbound_delivery_icount)?;
        let device_io_holding_ticks = device_io_freeze.map_or_else(
            || PluginShmemOrdering::device_io_active(slot),
            |freeze| freeze.is_tick_hold_active(slot),
        );

        PluginShmemOrdering::publish_reached_icount(slot, current_icount, clock.icount_shift())
            .map_err(|source| IdleHotLoopError::PublishReached { source })?;

        let plan = compute_idle_wake_plan(
            current_icount,
            clock.icount_shift(),
            exact_deadline,
            next_inbound_delivery_icount,
            SchedulerCeiling::new(ceiling_icount),
            device_io_holding_ticks,
        )?;
        let futex_wait = PluginShmemOrdering::publish_idle_wait(
            slot,
            current_icount,
            plan.desired_wake_icount,
            clock.icount_shift(),
        )
        .map_err(|source| IdleHotLoopError::PublishIdle { source })?;

        Ok(IdleParkRequest { plan, futex_wait })
    }

    /// Parks on the non-private futex until the scheduler authorizes the wake.
    ///
    /// This loop has no wall-clock timeout and does not sleep for a duration. It
    /// rechecks the acquire-loaded control action and ceiling after each futex
    /// return so shutdown and scheduler release wakes are both observed without a
    /// lost-wake window.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when the futex syscall fails, or when the
    /// non-Linux no-op futex shim cannot prove a scheduler release or shutdown.
    pub fn wait_for_scheduler_release(
        header: &RegionHeader,
        slot: &NodeSlot,
        request: &IdleParkRequest,
    ) -> Result<IdleWaitOutcome, IdleHotLoopError> {
        let mut wait = request.futex_wait;
        loop {
            if PluginShmemOrdering::observe_control_action(header) == RegionControlAction::Shutdown
            {
                PluginShmemOrdering::mark_done_after_shutdown(slot);
                return Ok(IdleWaitOutcome::ShutdownRequested);
            }
            if PluginShmemOrdering::load_scheduler_ceiling(slot) >= request.plan.desired_wake_icount
            {
                if PluginShmemOrdering::observe_control_action(header)
                    == RegionControlAction::Shutdown
                {
                    PluginShmemOrdering::mark_done_after_shutdown(slot);
                    return Ok(IdleWaitOutcome::ShutdownRequested);
                }
                return Ok(IdleWaitOutcome::SchedulerReleased);
            }

            match PluginShmemOrdering::wait_on_wake_signal(slot, wait)
                .map_err(|source| IdleHotLoopError::FutexWait { source })?
            {
                FutexWaitOutcome::Noop => {
                    if PluginShmemOrdering::observe_control_action(header)
                        == RegionControlAction::Shutdown
                    {
                        PluginShmemOrdering::mark_done_after_shutdown(slot);
                        return Ok(IdleWaitOutcome::ShutdownRequested);
                    }
                    return Err(IdleHotLoopError::WakeStillBlocked {
                        desired_wake_icount: request.plan.desired_wake_icount,
                        ceiling_icount: PluginShmemOrdering::load_scheduler_ceiling(slot),
                    });
                }
                FutexWaitOutcome::Runnable
                | FutexWaitOutcome::ValueChanged
                | FutexWaitOutcome::Interrupted
                | FutexWaitOutcome::Woken => {
                    wait = PluginShmemOrdering::prepare_futex_wait(slot);
                }
            }
        }
    }

    /// Completes the idle jump after the scheduler authorizes the wake.
    ///
    /// `candidate_frames` are frames visible to this node after the wake. The
    /// function returns only those due at the new current icount, sorted by
    /// `(delivery_icount, src_node, seq)`, which is the order the QEMU callback
    /// must inject.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when the scheduler has not authorized the
    /// desired wake, the virtual-clock jump fails, or running-state publication
    /// fails.
    pub fn complete_after_scheduler_wake(
        slot: &NodeSlot,
        clock: &mut PluginVirtualClock,
        queued_idle_advance: &QueuedIdleAdvance,
        request: IdleParkRequest,
        candidate_frames: impl IntoIterator<Item = FrameEntry>,
    ) -> Result<IdleHotLoopResult, IdleHotLoopError> {
        let candidate_frames = candidate_frames.into_iter().collect::<Vec<_>>();
        reject_passed_materialized_frames(&candidate_frames, request.plan.current_icount)?;
        let (advance, pending_advance) =
            Self::advance_after_scheduler_wake(slot, clock, queued_idle_advance, &request)?;
        let injected_frames = PluginInboundFrames::select_deliverable_frames_since(
            candidate_frames,
            clock.current_icount(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        Self::publish_completed_idle(
            slot,
            clock,
            request,
            advance,
            pending_advance,
            injected_frames,
            None,
        )
    }

    /// Finishes a materialized-frame idle turn after QEMU reports time completion.
    ///
    /// The initial [`Self::complete_after_scheduler_wake`] call must have
    /// returned [`IdleHotLoopError::TimeAdvanceCompletionPending`]. This method
    /// validates that exact pending token and completion before advancing the
    /// plugin clock, selecting frames, or republishing the node as running.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when completion failed or names another
    /// target, authorization changed, frame validation fails, or running-state
    /// publication fails.
    pub fn complete_after_time_advance(
        slot: &NodeSlot,
        clock: &mut PluginVirtualClock,
        request: IdleParkRequest,
        pending_advance: PendingIdleAdvance,
        completion: TimeAdvanceCompletion,
        candidate_frames: impl IntoIterator<Item = FrameEntry>,
    ) -> Result<IdleHotLoopResult, IdleHotLoopError> {
        let candidate_frames = candidate_frames.into_iter().collect::<Vec<_>>();
        reject_passed_materialized_frames(&candidate_frames, request.plan.current_icount)?;
        let (advance, completed_advance) = Self::finish_advance_after_completion(
            slot,
            clock,
            &request,
            pending_advance,
            completion,
        )?;
        let injected_frames = PluginInboundFrames::select_deliverable_frames_since(
            candidate_frames,
            clock.current_icount(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        Self::publish_completed_idle(
            slot,
            clock,
            request,
            advance,
            completed_advance,
            injected_frames,
            None,
        )
    }

    /// Completes the idle jump and drains due frames from inbound shared-memory rings.
    ///
    /// Ring heads behind the authorized wake are rejected before QEMU virtual time
    /// is advanced. Due heads at the reached icount are consumed and returned in
    /// deterministic injection order.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when the scheduler has not authorized the
    /// desired wake, the virtual-clock jump fails, inbound frame polling fails, or
    /// running-state publication fails.
    pub fn complete_after_scheduler_wake_from_inbound_rings<'a>(
        slot: &NodeSlot,
        clock: &mut PluginVirtualClock,
        queued_idle_advance: &QueuedIdleAdvance,
        request: IdleParkRequest,
        inbound_rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
    ) -> Result<IdleHotLoopResult, IdleHotLoopError> {
        let inbound_rings = inbound_rings.into_iter().collect::<Vec<_>>();
        PluginInboundFrames::reject_already_passed_ring_heads(
            inbound_rings.iter().copied(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        let (advance, pending_advance) =
            Self::advance_after_scheduler_wake(slot, clock, queued_idle_advance, &request)?;
        let inbound_batch = PluginInboundFrames::drain_deliverable_since(
            inbound_rings,
            clock.current_icount(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        Self::publish_completed_idle(
            slot,
            clock,
            request,
            advance,
            pending_advance,
            inbound_batch.into_frames(),
            None,
        )
    }

    /// Finishes an inbound-ring idle turn after QEMU reports time completion.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when completion validation, scheduler
    /// authorization, inbound-ring draining, or running-state publication fails.
    pub fn complete_after_time_advance_from_inbound_rings<'a>(
        slot: &NodeSlot,
        clock: &mut PluginVirtualClock,
        request: IdleParkRequest,
        pending_advance: PendingIdleAdvance,
        completion: TimeAdvanceCompletion,
        inbound_rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
    ) -> Result<IdleHotLoopResult, IdleHotLoopError> {
        let inbound_rings = inbound_rings.into_iter().collect::<Vec<_>>();
        PluginInboundFrames::reject_already_passed_ring_heads(
            inbound_rings.iter().copied(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        let (advance, completed_advance) = Self::finish_advance_after_completion(
            slot,
            clock,
            &request,
            pending_advance,
            completion,
        )?;
        let inbound_batch = PluginInboundFrames::drain_deliverable_since(
            inbound_rings,
            clock.current_icount(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        Self::publish_completed_idle(
            slot,
            clock,
            request,
            advance,
            completed_advance,
            inbound_batch.into_frames(),
            None,
        )
    }

    /// Completes the idle jump, drains due inbound frames, and injects them via RX.
    ///
    /// Ring heads behind the authorized wake are rejected before QEMU virtual time
    /// is advanced. After queued idle-jump completion, due heads at the reached
    /// icount are consumed, queued through the lossless network RX backend,
    /// flushed, and then the node is republished as running.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when the scheduler has not authorized the
    /// desired wake, the virtual-clock jump fails, inbound frame polling fails,
    /// network RX injection fails, or running-state publication fails.
    pub fn complete_after_scheduler_wake_from_inbound_rings_with_rx_injection<'a, Q>(
        slot: &NodeSlot,
        clock: &mut PluginVirtualClock,
        queued_idle_advance: &QueuedIdleAdvance,
        request: IdleParkRequest,
        inbound_rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
        network_rx: &PluginNetworkRx,
        rx_queue: &mut Q,
    ) -> Result<IdleHotLoopResult, IdleHotLoopError>
    where
        Q: LosslessNetworkRxQueue + ?Sized,
    {
        let inbound_rings = inbound_rings.into_iter().collect::<Vec<_>>();
        PluginInboundFrames::reject_already_passed_ring_heads(
            inbound_rings.iter().copied(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        let (advance, pending_advance) =
            Self::advance_after_scheduler_wake(slot, clock, queued_idle_advance, &request)?;
        let inbound_batch = PluginInboundFrames::preview_deliverable_since(
            inbound_rings.iter().copied(),
            clock.current_icount(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        let injected_frames = inbound_batch.into_frames();
        let network_rx_injection = handle_network_rx_idle_callback(
            network_rx,
            rx_queue,
            request.plan.current_icount,
            clock.current_icount(),
            &injected_frames,
        )
        .map_err(|source| IdleHotLoopError::NetworkRxInjection { source })?;
        let committed_batch = PluginInboundFrames::drain_deliverable_since(
            inbound_rings,
            clock.current_icount(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        if committed_batch.frames() != injected_frames.as_slice() {
            return Err(IdleHotLoopError::InboundFrames {
                source: InboundFrameError::CommittedBatchMismatch {
                    expected: injected_frames
                        .iter()
                        .map(FrameEntry::delivery_key)
                        .collect(),
                    actual: committed_batch
                        .frames()
                        .iter()
                        .map(FrameEntry::delivery_key)
                        .collect(),
                },
            });
        }
        Self::publish_completed_idle(
            slot,
            clock,
            request,
            advance,
            pending_advance,
            injected_frames,
            Some(network_rx_injection),
        )
    }

    /// Finishes an RX-injecting idle turn after QEMU reports time completion.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when completion validation, scheduler
    /// authorization, inbound preview/drain, RX injection, or running-state
    /// publication fails.
    // crucible-lint: allow rust-allow -- this boundary carries the exact request, completion, ring, and RX owners.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_after_time_advance_from_inbound_rings_with_rx_injection<'a, Q>(
        slot: &NodeSlot,
        clock: &mut PluginVirtualClock,
        request: IdleParkRequest,
        pending_advance: PendingIdleAdvance,
        completion: TimeAdvanceCompletion,
        inbound_rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
        network_rx: &PluginNetworkRx,
        rx_queue: &mut Q,
    ) -> Result<IdleHotLoopResult, IdleHotLoopError>
    where
        Q: LosslessNetworkRxQueue + ?Sized,
    {
        let inbound_rings = inbound_rings.into_iter().collect::<Vec<_>>();
        PluginInboundFrames::reject_already_passed_ring_heads(
            inbound_rings.iter().copied(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        let (advance, completed_advance) = Self::finish_advance_after_completion(
            slot,
            clock,
            &request,
            pending_advance,
            completion,
        )?;
        let inbound_batch = PluginInboundFrames::preview_deliverable_since(
            inbound_rings.iter().copied(),
            clock.current_icount(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        let injected_frames = inbound_batch.into_frames();
        let network_rx_injection = handle_network_rx_idle_callback(
            network_rx,
            rx_queue,
            request.plan.current_icount,
            clock.current_icount(),
            &injected_frames,
        )
        .map_err(|source| IdleHotLoopError::NetworkRxInjection { source })?;
        let committed_batch = PluginInboundFrames::drain_deliverable_since(
            inbound_rings,
            clock.current_icount(),
            request.plan.current_icount,
        )
        .map_err(|source| IdleHotLoopError::InboundFrames { source })?;
        if committed_batch.frames() != injected_frames.as_slice() {
            return Err(IdleHotLoopError::InboundFrames {
                source: InboundFrameError::CommittedBatchMismatch {
                    expected: injected_frames
                        .iter()
                        .map(FrameEntry::delivery_key)
                        .collect(),
                    actual: committed_batch
                        .frames()
                        .iter()
                        .map(FrameEntry::delivery_key)
                        .collect(),
                },
            });
        }
        Self::publish_completed_idle(
            slot,
            clock,
            request,
            advance,
            completed_advance,
            injected_frames,
            Some(network_rx_injection),
        )
    }

    fn advance_after_scheduler_wake(
        slot: &NodeSlot,
        clock: &mut PluginVirtualClock,
        queued_idle_advance: &QueuedIdleAdvance,
        request: &IdleParkRequest,
    ) -> Result<(PluginClockAdvance, PendingIdleAdvance), IdleHotLoopError> {
        let ceiling_icount = PluginShmemOrdering::load_scheduler_ceiling(slot);
        if ceiling_icount < request.plan.desired_wake_icount {
            return Err(IdleHotLoopError::WakeNotAuthorized {
                desired_wake_icount: request.plan.desired_wake_icount,
                ceiling_icount,
            });
        }

        let authorization = clock
            .authorize_idle_jump(
                request.plan.desired_wake_icount,
                SchedulerCeiling::new(ceiling_icount),
            )
            .map_err(|source| IdleHotLoopError::AdvanceClock { source })?;
        let target_virtual_ns = authorization
            .target_virtual_ns(clock.icount_shift())
            .map_err(|source| IdleHotLoopError::AdvanceClock { source })?;
        let pending_advance = queued_idle_advance
            .enqueue(target_virtual_ns)
            .map_err(|source| IdleHotLoopError::QueuedIdleAdvance { source })?;
        Err(IdleHotLoopError::TimeAdvanceCompletionPending {
            target_virtual_ns,
            pending_advance,
        })
    }

    /// Validates a QEMU completion and publishes the resulting clock advance.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when QEMU's completion does not match the
    /// pending request, the scheduler ceiling no longer authorizes the wake, or
    /// clock and shared-memory publication fails.
    fn finish_advance_after_completion(
        slot: &NodeSlot,
        clock: &mut PluginVirtualClock,
        request: &IdleParkRequest,
        pending_advance: PendingIdleAdvance,
        completion: TimeAdvanceCompletion,
    ) -> Result<(PluginClockAdvance, PendingIdleAdvance), IdleHotLoopError> {
        let completed_advance = pending_advance
            .validate_completion(completion)
            .map_err(|source| IdleHotLoopError::QueuedIdleAdvance { source })?;
        let ceiling_icount = PluginShmemOrdering::load_scheduler_ceiling(slot);
        if ceiling_icount < request.plan.desired_wake_icount {
            return Err(IdleHotLoopError::WakeNotAuthorized {
                desired_wake_icount: request.plan.desired_wake_icount,
                ceiling_icount,
            });
        }
        let authorization = clock
            .authorize_idle_jump(
                request.plan.desired_wake_icount,
                SchedulerCeiling::new(ceiling_icount),
            )
            .map_err(|source| IdleHotLoopError::AdvanceClock { source })?;
        let target_virtual_ns = authorization
            .target_virtual_ns(clock.icount_shift())
            .map_err(|source| IdleHotLoopError::AdvanceClock { source })?;
        if target_virtual_ns != completed_advance.target_virtual_ns() {
            return Err(IdleHotLoopError::TimeAdvanceTargetDrift {
                authorized_target_virtual_ns: target_virtual_ns,
                completed_target_virtual_ns: completed_advance.target_virtual_ns(),
            });
        }
        let advance = clock
            .advance_authorized_idle_jump(authorization)
            .map_err(|source| IdleHotLoopError::AdvanceClock { source })?;
        Ok((advance, completed_advance))
    }

    fn publish_completed_idle(
        slot: &NodeSlot,
        clock: &PluginVirtualClock,
        request: IdleParkRequest,
        advance: PluginClockAdvance,
        pending_advance: PendingIdleAdvance,
        injected_frames: Vec<FrameEntry>,
        network_rx_injection: Option<NetworkRxInjection>,
    ) -> Result<IdleHotLoopResult, IdleHotLoopError> {
        PluginShmemOrdering::publish_reached_icount(
            slot,
            clock.current_icount(),
            clock.icount_shift(),
        )
        .map_err(|source| IdleHotLoopError::PublishReached { source })?;

        Ok(IdleHotLoopResult {
            wake_plan: request.plan,
            advance,
            pending_advance,
            injected_frames,
            network_rx_injection,
        })
    }

    /// Republishes running state when QEMU reports that a vCPU resumed.
    ///
    /// Resume is a boundary marker only: it does not block and does not advance
    /// virtual time.
    ///
    /// # Errors
    ///
    /// Returns [`IdleHotLoopError`] when publishing the current clock to the node
    /// slot fails.
    pub fn publish_resume_boundary(
        slot: &NodeSlot,
        clock: &PluginVirtualClock,
    ) -> Result<(), IdleHotLoopError> {
        PluginShmemOrdering::publish_reached_icount(
            slot,
            clock.current_icount(),
            clock.icount_shift(),
        )
        .map_err(|source| IdleHotLoopError::PublishReached { source })
    }
}

/// Computes the idle wake target from virtual timers, inbound delivery, and ceiling.
///
/// When `device_io_holding_ticks` is true, the exact timer deadline is still
/// recorded in the returned plan, but it cannot select the wake target.
///
/// # Errors
///
/// Returns [`IdleHotLoopError`] when the timer deadline cannot be converted to
/// an aggregate icount or the observed ceiling is behind the current icount.
pub fn compute_idle_wake_plan(
    current_icount: u64,
    icount_shift: u8,
    exact_deadline: ExactDeadlineReport,
    next_inbound_delivery_icount: Option<u64>,
    ceiling: SchedulerCeiling,
    device_io_holding_ticks: bool,
) -> Result<IdleWakePlan, IdleHotLoopError> {
    if ceiling.icount() < current_icount {
        return Err(IdleHotLoopError::CeilingBehindCurrent {
            current_icount,
            ceiling_icount: ceiling.icount(),
        });
    }

    let timer_deadline_icount = timer_deadline_icount(exact_deadline, icount_shift)?
        .map(|deadline| deadline.max(current_icount));
    let effective_timer_deadline_icount = if device_io_holding_ticks {
        None
    } else {
        timer_deadline_icount
    };
    let inbound_delivery_icount = next_inbound_delivery_icount;

    let (desired_wake_icount, cause) =
        match (effective_timer_deadline_icount, inbound_delivery_icount) {
            (Some(timer), Some(inbound)) if inbound < timer => {
                (inbound, IdleWakeCause::InboundFrame)
            }
            (Some(timer), Some(_inbound)) => (timer, IdleWakeCause::TimerDeadline),
            (Some(timer), None) => (timer, IdleWakeCause::TimerDeadline),
            (None, Some(inbound)) => (inbound, IdleWakeCause::InboundFrame),
            (None, None) if device_io_holding_ticks => {
                (ceiling.icount(), IdleWakeCause::DeviceIoFreeze)
            }
            (None, None) => (ceiling.icount(), IdleWakeCause::SchedulerCeiling),
        };

    Ok(IdleWakePlan {
        current_icount,
        desired_wake_icount,
        ceiling_icount: ceiling.icount(),
        timer_deadline_icount,
        inbound_delivery_icount,
        device_io_holding_ticks,
        cause,
    })
}

fn reject_passed_materialized_frames(
    frames: &[FrameEntry],
    consumer_current_icount: u64,
) -> Result<(), IdleHotLoopError> {
    for frame in frames {
        if frame.delivery_icount < consumer_current_icount {
            return Err(IdleHotLoopError::InboundFrames {
                source: InboundFrameError::DeliveryAlreadyPassed {
                    ring_index: None,
                    consumer_current_icount,
                    frame: frame.delivery_key(),
                },
            });
        }
    }
    Ok(())
}

fn reject_passed_inbound_delivery(
    consumer_current_icount: u64,
    next_inbound_delivery_icount: Option<u64>,
) -> Result<(), IdleHotLoopError> {
    let Some(delivery_icount) = next_inbound_delivery_icount else {
        return Ok(());
    };
    if delivery_icount < consumer_current_icount {
        return Err(IdleHotLoopError::InboundFrames {
            source: InboundFrameError::DeliveryAlreadyPassed {
                ring_index: None,
                consumer_current_icount,
                frame: FrameDeliveryKey {
                    delivery_icount,
                    src_node: 0,
                    seq: 0,
                },
            },
        });
    }
    Ok(())
}

/// Converts an exact virtual-clock timer report into aggregate icount units.
///
/// # Errors
///
/// Returns [`IdleHotLoopError::InvalidIcountShift`] if `icount_shift >= 64`, or
/// [`IdleHotLoopError::TimerDeadlineOverflow`] when the ceiling conversion would
/// overflow.
pub fn timer_deadline_icount(
    report: ExactDeadlineReport,
    icount_shift: u8,
) -> Result<Option<u64>, IdleHotLoopError> {
    let ExactDeadlineReport::Armed { deadline_ns } = report else {
        return Ok(None);
    };
    if icount_shift >= 64 {
        return Err(IdleHotLoopError::InvalidIcountShift { icount_shift });
    }

    let base = deadline_ns >> icount_shift;
    let remainder_mask = if icount_shift == 0 {
        0
    } else {
        (1_u64 << icount_shift) - 1
    };
    if deadline_ns & remainder_mask == 0 {
        Ok(Some(base))
    } else {
        base.checked_add(1)
            .map(Some)
            .ok_or(IdleHotLoopError::TimerDeadlineOverflow {
                deadline_ns,
                icount_shift,
            })
    }
}

/// An error produced while executing the idle hot-loop state machine.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum IdleHotLoopError {
    /// The scheduler ceiling was behind the node's current icount.
    #[error("scheduler ceiling {ceiling_icount} is behind current icount {current_icount}")]
    CeilingBehindCurrent {
        /// The node's current icount.
        current_icount: u64,
        /// The stale scheduler ceiling.
        ceiling_icount: u64,
    },
    /// The timer deadline conversion used an unrepresentable fixed icount shift.
    #[error("idle deadline conversion cannot represent icount shift {icount_shift}")]
    InvalidIcountShift {
        /// The rejected fixed icount shift.
        icount_shift: u8,
    },
    /// The timer deadline conversion overflowed aggregate icount units.
    #[error("timer deadline {deadline_ns}ns overflows icount conversion at shift {icount_shift}")]
    TimerDeadlineOverflow {
        /// The exact virtual nanosecond deadline.
        deadline_ns: u64,
        /// The fixed icount shift.
        icount_shift: u8,
    },
    /// Publishing the running/reached clock failed.
    #[error("publishing reached icount failed: {source}")]
    PublishReached {
        /// The shared-memory slot publication error.
        source: NodeSlotError,
    },
    /// Publishing idle state failed.
    #[error("publishing idle state failed: {source}")]
    PublishIdle {
        /// The shared-memory slot publication error.
        source: NodeSlotError,
    },
    /// The futex wait operation failed.
    #[error("idle futex wait failed: {source}")]
    FutexWait {
        /// The futex syscall error.
        source: FutexError,
    },
    /// Reading QEMU's exact virtual-clock deadline failed.
    #[error("reading exact idle deadline failed: {source}")]
    ReadExactDeadline {
        /// The exact deadline introspection error.
        source: ExactDeadlineError,
    },
    /// The no-op futex shim could not prove a scheduler release.
    #[error("idle wake {desired_wake_icount} is still blocked by ceiling {ceiling_icount}")]
    WakeStillBlocked {
        /// The desired wake icount.
        desired_wake_icount: u64,
        /// The currently observed scheduler ceiling.
        ceiling_icount: u64,
    },
    /// The scheduler has not raised the ceiling to the desired wake.
    #[error("idle wake {desired_wake_icount} was not authorized by ceiling {ceiling_icount}")]
    WakeNotAuthorized {
        /// The desired wake icount.
        desired_wake_icount: u64,
        /// The currently observed scheduler ceiling.
        ceiling_icount: u64,
    },
    /// Advancing the plugin virtual clock failed.
    #[error("idle virtual-clock advance failed: {source}")]
    AdvanceClock {
        /// The plugin clock error.
        source: PluginClockError,
    },
    /// Enqueueing QEMU virtual time failed before ownership transferred.
    #[error("queued idle advance failed: {source}")]
    QueuedIdleAdvance {
        /// The queued-advance error.
        source: QueuedIdleAdvanceError,
    },
    /// QEMU accepted the advance, so this callback must return until completion.
    #[error("queued idle advance to {target_virtual_ns}ns awaits normal-main-loop completion")]
    TimeAdvanceCompletionPending {
        /// Absolute target accepted by QEMU.
        target_virtual_ns: u64,
        /// Token that must be matched by the later completion callback.
        pending_advance: PendingIdleAdvance,
    },
    /// The retained idle request no longer derives the target QEMU completed.
    #[error(
        "authorized idle target {authorized_target_virtual_ns}ns differs from completed target {completed_target_virtual_ns}ns"
    )]
    TimeAdvanceTargetDrift {
        /// Virtual time derived again from the retained scheduler request.
        authorized_target_virtual_ns: u64,
        /// Virtual time named by the validated completed request.
        completed_target_virtual_ns: u64,
    },
    /// Inbound frame polling or deterministic injection failed.
    #[error("inbound frame handling failed: {source}")]
    InboundFrames {
        /// The inbound frame error.
        source: InboundFrameError,
    },
    /// Lossless network RX injection failed.
    #[error("network RX injection failed: {source}")]
    NetworkRxInjection {
        /// The network RX injection error.
        source: NetworkRxError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    use crucible_shmem::{
        AdvanceCeiling, KIND_VM, RegionConfig, RegionHeader, RegionLayout, RingHeader, STATUS_DONE,
        STATUS_IDLE, STATUS_RUNNING, authorize_advance_ceiling,
    };

    use crate::{
        CANONICAL_TIME_CONTROL_REGISTRATION_ORDER, CoverageCapabilities, NetworkRxQueueError,
        PluginArgs, PluginDeviceIoFreeze, PluginRegistrationSequence, PluginTimeControlOwnership,
    };

    thread_local! {
        static LAST_DIRECT_ADVANCE_NS: Cell<i64> = const { Cell::new(-1) };
        static BLOCKED_DIRECT_ADVANCE_NS: Cell<i64> = const { Cell::new(-1) };
    }

    #[test]
    fn idle_loop_computes_wake_from_timer_inbound_and_ceiling() {
        let timer_wins = match compute_idle_wake_plan(
            10,
            1,
            ExactDeadlineReport::Armed { deadline_ns: 40 },
            Some(30),
            SchedulerCeiling::new(50),
            false,
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("timer wake plan should compute: {error}"),
        };
        assert_eq!(timer_wins.timer_deadline_icount(), Some(20));
        assert_eq!(timer_wins.inbound_delivery_icount(), Some(30));
        assert_eq!(timer_wins.desired_wake_icount(), 20);
        assert_eq!(timer_wins.cause(), IdleWakeCause::TimerDeadline);
        assert!(!timer_wins.requires_scheduler_wait());

        let inbound_wins = match compute_idle_wake_plan(
            10,
            1,
            ExactDeadlineReport::Armed { deadline_ns: 80 },
            Some(30),
            SchedulerCeiling::new(20),
            false,
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("inbound wake plan should compute: {error}"),
        };
        assert_eq!(inbound_wins.desired_wake_icount(), 30);
        assert_eq!(inbound_wins.cause(), IdleWakeCause::InboundFrame);
        assert!(inbound_wins.requires_scheduler_wait());

        let ceiling_wins = match compute_idle_wake_plan(
            10,
            1,
            ExactDeadlineReport::NoArmedTimer,
            None,
            SchedulerCeiling::new(64),
            false,
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("ceiling wake plan should compute: {error}"),
        };
        assert_eq!(ceiling_wins.desired_wake_icount(), 64);
        assert_eq!(ceiling_wins.cause(), IdleWakeCause::SchedulerCeiling);
    }

    #[test]
    fn idle_loop_device_io_freeze_suppresses_timer_deadline_until_scheduler_wake() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 0);
        publish_ceiling(&slot, ceiling(0, 50));
        let mut freeze = PluginDeviceIoFreeze::new();
        let _token = match freeze.begin_submit(&slot, clock.current_icount()) {
            Ok(token) => token,
            Err(error) => panic!("device I/O submit should activate freeze: {error}"),
        };

        let request = match PluginIdleHotLoop::begin_idle(
            &slot,
            &clock,
            &deadline_reader(deadline_20),
            None,
            Some(&freeze),
        ) {
            Ok(request) => request,
            Err(error) => panic!("device-I/O idle publish should succeed: {error}"),
        };

        assert_eq!(request.plan().timer_deadline_icount(), Some(20));
        assert!(request.plan().device_io_holding_ticks());
        assert_eq!(request.plan().desired_wake_icount(), 50);
        assert_eq!(request.plan().cause(), IdleWakeCause::DeviceIoFreeze);
        assert_eq!(slot.snapshot().idle_wake_icount, 50);
    }

    #[test]
    fn idle_loop_device_io_freeze_uses_pending_counter_when_flag_is_stale() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 0);
        publish_ceiling(&slot, ceiling(0, 50));
        let mut freeze = PluginDeviceIoFreeze::new();
        let _token = match freeze.begin_submit(&slot, clock.current_icount()) {
            Ok(token) => token,
            Err(error) => panic!("device I/O submit should activate freeze: {error}"),
        };
        PluginShmemOrdering::clear_device_io_active(&slot);
        assert!(!PluginShmemOrdering::device_io_active(&slot));
        assert!(freeze.pending_requests() != 0);

        let request = match PluginIdleHotLoop::begin_idle(
            &slot,
            &clock,
            &deadline_reader(deadline_20),
            None,
            Some(&freeze),
        ) {
            Ok(request) => request,
            Err(error) => panic!("pending-only freeze should suppress timer: {error}"),
        };

        assert_eq!(request.plan().timer_deadline_icount(), Some(20));
        assert!(request.plan().device_io_holding_ticks());
        assert_eq!(request.plan().desired_wake_icount(), 50);
        assert_eq!(request.plan().cause(), IdleWakeCause::DeviceIoFreeze);
    }

    #[test]
    fn idle_loop_publishes_current_then_idle_and_prepares_futex_wait() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 0);
        publish_ceiling(&slot, ceiling(0, 10));

        let request = match PluginIdleHotLoop::begin_idle(
            &slot,
            &clock,
            &deadline_reader(deadline_20),
            None,
            None,
        ) {
            Ok(request) => request,
            Err(error) => panic!("idle publish should succeed: {error}"),
        };

        assert_eq!(request.plan().current_icount(), 10);
        assert_eq!(request.plan().desired_wake_icount(), 20);
        assert_eq!(request.plan().cause(), IdleWakeCause::TimerDeadline);
        assert_eq!(request.futex_wait(), FutexWait::Wait { expected: 1 });

        let snapshot = slot.snapshot();
        assert_eq!(snapshot.current_icount, 10);
        assert_eq!(snapshot.current_ns, 10);
        assert_eq!(snapshot.idle_wake_icount, 20);
        assert_eq!(snapshot.status, STATUS_IDLE);
        assert!(slot.futex_wait_still_valid(1));
    }

    #[test]
    fn idle_loop_wait_uses_futex_release_without_wall_clock_timeout() {
        let slot = NodeSlot::new(KIND_VM);
        publish_ceiling(&slot, ceiling(0, 10));
        let clock = owned_clock(10, 0);
        let request = match PluginIdleHotLoop::begin_idle(
            &slot,
            &clock,
            &deadline_reader(deadline_10),
            None,
            None,
        ) {
            Ok(request) => request,
            Err(error) => panic!("idle publish should be immediately runnable: {error}"),
        };

        assert_eq!(request.futex_wait(), FutexWait::Runnable);
        assert_eq!(
            PluginIdleHotLoop::wait_for_scheduler_release(&header(), &slot, &request),
            Ok(IdleWaitOutcome::SchedulerReleased)
        );
    }

    #[test]
    fn idle_loop_shutdown_wake_marks_done_and_returns_teardown_outcome() {
        let header = header();
        let slot = NodeSlot::new(KIND_VM);
        publish_ceiling(&slot, ceiling(0, 10));
        let clock = owned_clock(10, 0);
        let request = match PluginIdleHotLoop::begin_idle(
            &slot,
            &clock,
            &deadline_reader(deadline_20),
            None,
            None,
        ) {
            Ok(request) => request,
            Err(error) => panic!("idle publish should park for future timer: {error}"),
        };

        if let Err(error) = header.request_shutdown([&slot]) {
            panic!("shutdown should wake idle slot: {error}");
        }
        assert_eq!(
            PluginIdleHotLoop::wait_for_scheduler_release(&header, &slot, &request),
            Ok(IdleWaitOutcome::ShutdownRequested)
        );

        let snapshot = slot.snapshot();
        assert_eq!(snapshot.current_icount, 10);
        assert_eq!(snapshot.current_ns, 10);
        assert_eq!(snapshot.status, STATUS_DONE);
        assert_eq!(clock.current_icount(), 10);
    }

    #[test]
    fn idle_loop_release_waits_for_qemu_completion_before_mutating_state() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 1);
        publish_ceiling(&slot, ceiling(0, 10));
        let request = match PluginIdleHotLoop::begin_idle(
            &slot,
            &clock,
            &deadline_reader(deadline_40),
            Some(40),
            None,
        ) {
            Ok(request) => request,
            Err(error) => panic!("idle begin should succeed: {error}"),
        };
        assert!(request.plan().requires_scheduler_wait());

        publish_ceiling(&slot, ceiling(10, 20));
        let mut clock = clock;
        set_last_direct_advance_ns(-1);
        let queued_idle_advance = queued_idle_advance();
        let pending = expect_pending(PluginIdleHotLoop::complete_after_scheduler_wake(
            &slot,
            &mut clock,
            &queued_idle_advance,
            request,
            [
                frame(20, 9, 4, b"late-by-key"),
                frame(15, 4, 1, b"jumped-over"),
                frame(20, 1, 7, b"first"),
                frame(21, 1, 8, b"future"),
            ],
        ));
        assert_eq!(last_direct_advance_ns(), 40);
        assert_eq!(clock.current_icount(), 10);

        let snapshot = slot.snapshot();
        assert_eq!(snapshot.current_icount, 10);
        assert_eq!(snapshot.current_ns, 20);
        assert_eq!(snapshot.status, STATUS_IDLE);

        let result = PluginIdleHotLoop::complete_after_time_advance(
            &slot,
            &mut clock,
            request,
            pending,
            successful_completion(pending),
            [
                frame(20, 9, 4, b"late-by-key"),
                frame(15, 4, 1, b"jumped-over"),
                frame(20, 1, 7, b"first"),
                frame(21, 1, 8, b"future"),
            ],
        )
        .unwrap_or_else(|error| panic!("idle completion should succeed: {error}"));
        assert_eq!(result.advance().from_icount(), 10);
        assert_eq!(result.advance().to_icount(), 20);
        assert_eq!(result.advance().virtual_ns(), 40);
        assert!(!result.pending_advance().completion_pending());
        assert_eq!(
            result
                .injected_frames()
                .iter()
                .map(FrameEntry::delivery_key)
                .collect::<Vec<_>>(),
            vec![
                frame(15, 4, 1, b"jumped-over").delivery_key(),
                frame(20, 1, 7, b"first").delivery_key(),
                frame(20, 9, 4, b"late-by-key").delivery_key(),
            ]
        );
        assert_eq!(clock.current_icount(), 20);
        assert_eq!(slot.snapshot().status, STATUS_RUNNING);
    }

    #[test]
    fn idle_loop_with_inbound_rings_does_not_consume_before_qemu_completion() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 1);
        let ring_a = RingHeader::new();
        let ring_b = RingHeader::new();
        let mut entries_a = empty_entries();
        let mut entries_b = empty_entries();
        enqueue(&ring_a, &mut entries_a, frame(20, 9, 4, b"third"));
        enqueue(&ring_a, &mut entries_a, frame(20, 1, 7, b"first"));
        enqueue(&ring_b, &mut entries_b, frame(20, 4, 1, b"second"));
        enqueue(&ring_b, &mut entries_b, frame(25, 4, 2, b"future"));
        publish_ceiling(&slot, ceiling(0, 10));

        let request = match PluginIdleHotLoop::begin_idle_with_inbound_rings(
            &slot,
            &clock,
            &deadline_reader(deadline_80),
            [
                InboundFrameRing::new(0, &ring_a, &entries_a),
                InboundFrameRing::new(1, &ring_b, &entries_b),
            ],
            None,
        ) {
            Ok(request) => request,
            Err(error) => panic!("idle begin should peek inbound rings: {error}"),
        };
        assert_eq!(request.plan().desired_wake_icount(), 20);
        assert_eq!(request.plan().cause(), IdleWakeCause::InboundFrame);

        publish_ceiling(&slot, ceiling(10, 20));
        let mut clock = clock;
        set_last_direct_advance_ns(-1);
        let pending = expect_pending(
            PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings(
                &slot,
                &mut clock,
                &queued_idle_advance(),
                request,
                [
                    InboundFrameRing::new(0, &ring_a, &entries_a),
                    InboundFrameRing::new(1, &ring_b, &entries_b),
                ],
            ),
        );

        assert_eq!(last_direct_advance_ns(), 40);
        assert_eq!(clock.current_icount(), 10);
        assert_eq!(ring_a.read_index(), 0);
        assert_eq!(ring_b.read_index(), 0);
        let snapshot = slot.snapshot();
        assert_eq!(snapshot.current_icount, 10);
        assert_eq!(snapshot.current_ns, 20);
        assert_eq!(snapshot.status, STATUS_IDLE);

        let result = PluginIdleHotLoop::complete_after_time_advance_from_inbound_rings(
            &slot,
            &mut clock,
            request,
            pending,
            successful_completion(pending),
            [
                InboundFrameRing::new(0, &ring_a, &entries_a),
                InboundFrameRing::new(1, &ring_b, &entries_b),
            ],
        )
        .unwrap_or_else(|error| panic!("completed idle turn should drain rings: {error}"));
        assert_eq!(clock.current_icount(), 20);
        assert_eq!(ring_a.read_index(), 2);
        assert_eq!(ring_b.read_index(), 1);
        assert_eq!(
            result
                .injected_frames()
                .iter()
                .map(FrameEntry::delivery_key)
                .collect::<Vec<_>>(),
            vec![
                frame(20, 1, 7, b"first").delivery_key(),
                frame(20, 4, 1, b"second").delivery_key(),
                frame(20, 9, 4, b"third").delivery_key(),
            ]
        );
    }

    #[test]
    fn idle_loop_rx_injection_waits_for_qemu_completion() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 1);
        let ring_a = RingHeader::new();
        let ring_b = RingHeader::new();
        let mut entries_a = empty_entries();
        let mut entries_b = empty_entries();
        enqueue(&ring_a, &mut entries_a, frame(20, 9, 4, b"third"));
        enqueue(&ring_a, &mut entries_a, frame(20, 1, 7, b"first"));
        enqueue(&ring_b, &mut entries_b, frame(20, 4, 1, b"second"));
        publish_ceiling(&slot, ceiling(0, 10));

        let request = match PluginIdleHotLoop::begin_idle_with_inbound_rings(
            &slot,
            &clock,
            &deadline_reader(deadline_80),
            [
                InboundFrameRing::new(0, &ring_a, &entries_a),
                InboundFrameRing::new(1, &ring_b, &entries_b),
            ],
            None,
        ) {
            Ok(request) => request,
            Err(error) => panic!("idle begin should peek inbound rings: {error}"),
        };
        assert_eq!(slot.snapshot().status, STATUS_IDLE);

        publish_ceiling(&slot, ceiling(10, 20));
        let mut clock = clock;
        set_last_direct_advance_ns(-1);
        let network_rx = PluginNetworkRx::new();
        let mut rx_queue = RecordingNetworkRxQueue::for_slot(&slot);
        let pending = expect_pending(
            PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings_with_rx_injection(
                &slot,
                &mut clock,
                &queued_idle_advance(),
                request,
                [
                    InboundFrameRing::new(0, &ring_a, &entries_a),
                    InboundFrameRing::new(1, &ring_b, &entries_b),
                ],
                &network_rx,
                &mut rx_queue,
            ),
        );

        assert_eq!(last_direct_advance_ns(), 40);
        assert!(rx_queue.direct_advance_ns_at_queue.is_empty());
        assert!(rx_queue.slot_status_at_queue.is_empty());
        assert!(rx_queue.queued_payloads.is_empty());
        assert_eq!(rx_queue.flush_count, 0);
        assert_eq!(ring_a.read_index(), 0);
        assert_eq!(ring_b.read_index(), 0);
        assert_eq!(clock.current_icount(), 10);
        assert_eq!(slot.snapshot().status, STATUS_IDLE);

        let result =
            PluginIdleHotLoop::complete_after_time_advance_from_inbound_rings_with_rx_injection(
                &slot,
                &mut clock,
                request,
                pending,
                successful_completion(pending),
                [
                    InboundFrameRing::new(0, &ring_a, &entries_a),
                    InboundFrameRing::new(1, &ring_b, &entries_b),
                ],
                &network_rx,
                &mut rx_queue,
            )
            .unwrap_or_else(|error| panic!("completed idle turn should inject RX: {error}"));
        assert_eq!(rx_queue.direct_advance_ns_at_queue, vec![40, 40, 40]);
        assert_eq!(
            rx_queue.slot_status_at_queue,
            vec![STATUS_IDLE, STATUS_IDLE, STATUS_IDLE]
        );
        assert_eq!(
            rx_queue.queued_payloads,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        assert_eq!(rx_queue.flush_count, 1);
        assert_eq!(ring_a.read_index(), 2);
        assert_eq!(ring_b.read_index(), 1);
        assert_eq!(clock.current_icount(), 20);
        assert_eq!(slot.snapshot().status, STATUS_RUNNING);
        assert!(result.network_rx_injection().is_some());
    }

    #[test]
    fn idle_loop_rx_queue_failure_does_not_commit_inbound_ring_reads() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 1);
        let ring = RingHeader::new();
        let mut entries = empty_entries();
        enqueue(&ring, &mut entries, frame(20, 1, 0, b"queued"));
        publish_ceiling(&slot, ceiling(0, 10));
        let request = match PluginIdleHotLoop::begin_idle_with_inbound_rings(
            &slot,
            &clock,
            &deadline_reader(deadline_80),
            [InboundFrameRing::new(0, &ring, &entries)],
            None,
        ) {
            Ok(request) => request,
            Err(error) => panic!("idle begin should peek inbound rings: {error}"),
        };

        publish_ceiling(&slot, ceiling(10, 20));
        let mut clock = clock;
        set_last_direct_advance_ns(-1);
        let network_rx = PluginNetworkRx::new();
        let mut rx_queue = RecordingNetworkRxQueue::for_slot(&slot);
        rx_queue.queue_error_at = Some(0);

        let pending = expect_pending(
            PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings_with_rx_injection(
                &slot,
                &mut clock,
                &queued_idle_advance(),
                request,
                [InboundFrameRing::new(0, &ring, &entries)],
                &network_rx,
                &mut rx_queue,
            ),
        );

        assert_eq!(last_direct_advance_ns(), 40);
        assert_eq!(clock.current_icount(), 10);
        assert_eq!(ring.read_index(), 0);
        assert!(rx_queue.queued_payloads.is_empty());
        assert_eq!(rx_queue.flush_count, 0);
        assert_eq!(slot.snapshot().status, STATUS_IDLE);

        assert_eq!(
            PluginIdleHotLoop::complete_after_time_advance_from_inbound_rings_with_rx_injection(
                &slot,
                &mut clock,
                request,
                pending,
                successful_completion(pending),
                [InboundFrameRing::new(0, &ring, &entries)],
                &network_rx,
                &mut rx_queue,
            ),
            Err(IdleHotLoopError::NetworkRxInjection {
                source: NetworkRxError::Queue {
                    frame: frame(20, 1, 0, b"queued").delivery_key(),
                    source: NetworkRxQueueError::queue("test queue failure"),
                },
            })
        );
        assert_eq!(clock.current_icount(), 20);
        assert_eq!(ring.read_index(), 0);
        assert_eq!(slot.snapshot().status, STATUS_IDLE);
    }

    #[test]
    fn idle_loop_rejects_late_inbound_ring_before_direct_advance() {
        let slot = NodeSlot::new(KIND_VM);
        let mut clock = owned_clock(10, 1);
        let ring = RingHeader::new();
        let mut entries = empty_entries();
        enqueue(&ring, &mut entries, frame(9, 7, 2, b"late"));
        publish_ceiling(&slot, ceiling(10, 20));
        let request = IdleParkRequest {
            plan: IdleWakePlan {
                current_icount: 10,
                desired_wake_icount: 20,
                ceiling_icount: 20,
                timer_deadline_icount: None,
                inbound_delivery_icount: Some(9),
                device_io_holding_ticks: false,
                cause: IdleWakeCause::InboundFrame,
            },
            futex_wait: FutexWait::Runnable,
        };
        let before = slot.snapshot();
        set_blocked_direct_advance_ns(-1);

        assert_eq!(
            PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings(
                &slot,
                &mut clock,
                &blocked_queued_idle_advance(),
                request,
                [InboundFrameRing::new(3, &ring, &entries)]
            ),
            Err(IdleHotLoopError::InboundFrames {
                source: InboundFrameError::DeliveryAlreadyPassed {
                    ring_index: Some(3),
                    consumer_current_icount: 10,
                    frame: frame(9, 7, 2, b"late").delivery_key(),
                },
            })
        );

        assert_eq!(clock.current_icount(), 10);
        assert_eq!(slot.snapshot(), before);
        assert_eq!(ring.read_index(), 0);
        assert_eq!(blocked_direct_advance_ns(), -1);
    }

    #[test]
    fn idle_loop_rejects_late_materialized_frame_before_direct_advance() {
        let slot = NodeSlot::new(KIND_VM);
        let mut clock = owned_clock(10, 1);
        publish_ceiling(&slot, ceiling(10, 20));
        let request = IdleParkRequest {
            plan: IdleWakePlan {
                current_icount: 10,
                desired_wake_icount: 20,
                ceiling_icount: 20,
                timer_deadline_icount: None,
                inbound_delivery_icount: Some(9),
                device_io_holding_ticks: false,
                cause: IdleWakeCause::InboundFrame,
            },
            futex_wait: FutexWait::Runnable,
        };
        let before = slot.snapshot();
        set_blocked_direct_advance_ns(-1);

        assert_eq!(
            PluginIdleHotLoop::complete_after_scheduler_wake(
                &slot,
                &mut clock,
                &blocked_queued_idle_advance(),
                request,
                [frame(9, 7, 2, b"late")]
            ),
            Err(IdleHotLoopError::InboundFrames {
                source: InboundFrameError::DeliveryAlreadyPassed {
                    ring_index: None,
                    consumer_current_icount: 10,
                    frame: frame(9, 7, 2, b"late").delivery_key(),
                },
            })
        );

        assert_eq!(clock.current_icount(), 10);
        assert_eq!(slot.snapshot(), before);
        assert_eq!(blocked_direct_advance_ns(), -1);
    }

    #[test]
    fn idle_loop_rejects_late_inbound_ring_at_begin_without_publishing() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 1);
        let ring = RingHeader::new();
        let mut entries = empty_entries();
        enqueue(&ring, &mut entries, frame(9, 7, 2, b"late"));
        publish_ceiling(&slot, ceiling(0, 20));
        let before = slot.snapshot();

        assert_eq!(
            PluginIdleHotLoop::begin_idle_with_inbound_rings(
                &slot,
                &clock,
                &deadline_reader(deadline_80),
                [InboundFrameRing::new(6, &ring, &entries)],
                None
            ),
            Err(IdleHotLoopError::InboundFrames {
                source: InboundFrameError::DeliveryAlreadyPassed {
                    ring_index: Some(6),
                    consumer_current_icount: 10,
                    frame: frame(9, 7, 2, b"late").delivery_key(),
                },
            })
        );

        assert_eq!(slot.snapshot(), before);
        assert_eq!(ring.read_index(), 0);
        assert_eq!(clock.current_icount(), 10);
    }

    #[test]
    fn idle_loop_rejects_raw_late_inbound_delivery_before_publishing() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 1);
        publish_ceiling(&slot, ceiling(0, 20));
        let before = slot.snapshot();

        assert_eq!(
            PluginIdleHotLoop::begin_idle(
                &slot,
                &clock,
                &deadline_reader(deadline_80),
                Some(9),
                None
            ),
            Err(IdleHotLoopError::InboundFrames {
                source: InboundFrameError::DeliveryAlreadyPassed {
                    ring_index: None,
                    consumer_current_icount: 10,
                    frame: FrameDeliveryKey {
                        delivery_icount: 9,
                        src_node: 0,
                        seq: 0,
                    },
                },
            })
        );

        assert_eq!(slot.snapshot(), before);
        assert_eq!(clock.current_icount(), 10);
    }

    #[test]
    fn idle_loop_rejects_release_before_scheduler_authorizes_wake() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(10, 0);
        publish_ceiling(&slot, ceiling(0, 10));
        let request = match PluginIdleHotLoop::begin_idle(
            &slot,
            &clock,
            &deadline_reader(deadline_20),
            None,
            None,
        ) {
            Ok(request) => request,
            Err(error) => panic!("idle begin should succeed: {error}"),
        };
        let mut clock = clock;

        assert_eq!(
            PluginIdleHotLoop::complete_after_scheduler_wake(
                &slot,
                &mut clock,
                &queued_idle_advance(),
                request,
                []
            ),
            Err(IdleHotLoopError::WakeNotAuthorized {
                desired_wake_icount: 20,
                ceiling_icount: 10,
            })
        );
    }

    #[test]
    fn idle_loop_direct_advance_range_failure_leaves_clock_and_slot_unchanged() {
        let slot = NodeSlot::new(KIND_VM);
        let mut clock = owned_clock(0, crate::MAX_PLUGIN_ICOUNT_SHIFT);
        publish_ceiling(&slot, ceiling(0, 1));
        let before = slot.snapshot();
        set_blocked_direct_advance_ns(-1);
        let request = IdleParkRequest {
            plan: IdleWakePlan {
                current_icount: 0,
                desired_wake_icount: 1,
                ceiling_icount: 1,
                timer_deadline_icount: Some(1),
                inbound_delivery_icount: None,
                device_io_holding_ticks: false,
                cause: IdleWakeCause::TimerDeadline,
            },
            futex_wait: FutexWait::Runnable,
        };

        assert_eq!(
            PluginIdleHotLoop::complete_after_scheduler_wake(
                &slot,
                &mut clock,
                &blocked_queued_idle_advance(),
                request,
                [frame(1, 1, 1, b"would-be-due")]
            ),
            Err(IdleHotLoopError::QueuedIdleAdvance {
                source: QueuedIdleAdvanceError::VirtualTimeOutOfRange {
                    target_virtual_ns: i64::MAX as u64 + 1,
                },
            })
        );

        assert_eq!(clock.current_icount(), 0);
        assert_eq!(slot.snapshot(), before);
        assert_eq!(blocked_direct_advance_ns(), -1);
    }

    #[test]
    fn idle_resume_boundary_republishes_running_without_advancing_time() {
        let slot = NodeSlot::new(KIND_VM);
        let clock = owned_clock(32, 2);
        publish_ceiling(&slot, ceiling(0, 32));

        if let Err(error) = PluginIdleHotLoop::publish_resume_boundary(&slot, &clock) {
            panic!("resume boundary should publish: {error}");
        }

        let snapshot = slot.snapshot();
        assert_eq!(snapshot.current_icount, 32);
        assert_eq!(snapshot.current_ns, 128);
        assert_eq!(snapshot.status, STATUS_RUNNING);
        assert_eq!(clock.current_icount(), 32);
    }

    #[test]
    fn idle_timer_deadline_conversion_ceils_to_icount() {
        assert_eq!(
            timer_deadline_icount(ExactDeadlineReport::Armed { deadline_ns: 41 }, 3),
            Ok(Some(6))
        );
        assert_eq!(
            timer_deadline_icount(ExactDeadlineReport::NoArmedTimer, 3),
            Ok(None)
        );
        assert_eq!(
            timer_deadline_icount(ExactDeadlineReport::Armed { deadline_ns: 1 }, 64),
            Err(IdleHotLoopError::InvalidIcountShift { icount_shift: 64 })
        );
    }

    fn owned_clock(initial_icount: u64, icount_shift: u8) -> PluginVirtualClock {
        match PluginVirtualClock::new(initial_icount, icount_shift, ownership()) {
            Ok(clock) => clock,
            Err(error) => panic!("test clock should construct: {error}"),
        }
    }

    fn deadline_reader(deadline: crate::QemuClockDeadlineFn) -> ExactDeadlineReader {
        match ExactDeadlineReader::require(Some(deadline)) {
            Ok(reader) => reader,
            Err(error) => panic!("test deadline reader should require symbol: {error}"),
        }
    }

    fn queued_idle_advance() -> QueuedIdleAdvance {
        match QueuedIdleAdvance::require(Some(test_direct_advance)) {
            Ok(advance) => advance,
            Err(error) => panic!("test queued advance should require symbol: {error}"),
        }
    }

    fn blocked_queued_idle_advance() -> QueuedIdleAdvance {
        match QueuedIdleAdvance::require(Some(test_blocked_direct_advance)) {
            Ok(advance) => advance,
            Err(error) => panic!("test blocked queued advance should require symbol: {error}"),
        }
    }

    fn expect_pending(result: Result<IdleHotLoopResult, IdleHotLoopError>) -> PendingIdleAdvance {
        match result {
            Err(IdleHotLoopError::TimeAdvanceCompletionPending {
                pending_advance, ..
            }) => pending_advance,
            Ok(_result) => panic!("queued advance must not complete inside the idle callback"),
            Err(error) => panic!("queued advance should return a pending token: {error}"),
        }
    }

    fn successful_completion(pending: PendingIdleAdvance) -> TimeAdvanceCompletion {
        let target = i64::try_from(pending.target_virtual_ns())
            .unwrap_or_else(|error| panic!("test target should fit QEMU ABI: {error}"));
        TimeAdvanceCompletion::from_qemu(0, target)
    }

    extern "C" fn deadline_10() -> i64 {
        10
    }

    extern "C" fn deadline_20() -> i64 {
        20
    }

    extern "C" fn deadline_40() -> i64 {
        40
    }

    extern "C" fn deadline_80() -> i64 {
        80
    }

    extern "C" fn test_direct_advance(target_virtual_ns: i64) -> std::os::raw::c_int {
        set_last_direct_advance_ns(target_virtual_ns);
        0
    }

    extern "C" fn test_blocked_direct_advance(target_virtual_ns: i64) -> std::os::raw::c_int {
        set_blocked_direct_advance_ns(target_virtual_ns);
        0
    }

    fn set_last_direct_advance_ns(value: i64) {
        LAST_DIRECT_ADVANCE_NS.with(|cell| cell.set(value));
    }

    fn last_direct_advance_ns() -> i64 {
        LAST_DIRECT_ADVANCE_NS.with(|cell| cell.get())
    }

    fn set_blocked_direct_advance_ns(value: i64) {
        BLOCKED_DIRECT_ADVANCE_NS.with(|cell| cell.set(value));
    }

    fn blocked_direct_advance_ns() -> i64 {
        BLOCKED_DIRECT_ADVANCE_NS.with(|cell| cell.get())
    }

    fn ownership() -> PluginTimeControlOwnership {
        PluginTimeControlOwnership::acquired_after_registration(registration_ready())
    }

    fn registration_ready() -> crate::PluginRegistrationReady {
        let mut sequence = PluginRegistrationSequence::new();
        let args = PluginArgs::parse("simfd=3,slot=0")
            .unwrap_or_else(|error| panic!("test args should parse: {error}"));
        let mut setup_ack = None;
        for step in CANONICAL_TIME_CONTROL_REGISTRATION_ORDER {
            let result = if step == crate::PluginRegistrationStep::RegisterCallbacks {
                sequence
                    .register_callbacks_for_test(
                        &args,
                        Some(idle_loop_test_deadline),
                        Some(idle_loop_test_direct_advance),
                        CoverageCapabilities::none(),
                    )
                    .map(|_capabilities| ())
            } else if step == crate::PluginRegistrationStep::SendSetupAck {
                sequence.record_test_ready_setup_ack().map(|ack| {
                    setup_ack = Some(ack);
                })
            } else if step == crate::PluginRegistrationStep::WaitBootBarrier {
                let ack = setup_ack
                    .take()
                    .unwrap_or_else(|| panic!("setup ack should precede boot barrier"));
                let slot = NodeSlot::new(KIND_VM);
                publish_ceiling(&slot, ceiling(0, crate::BOOT_BARRIER_FIRST_GUEST_ICOUNT));
                sequence.wait_boot_barrier(ack, &slot, 0).map(|_release| ())
            } else {
                sequence.record_step(step)
            };
            if let Err(error) = result {
                panic!("test registration step {step:?} should record: {error}");
            }
        }
        match sequence.finish() {
            Ok(ready) => ready,
            Err(error) => panic!("test registration should finish: {error}"),
        }
    }

    extern "C" fn idle_loop_test_deadline() -> i64 {
        1
    }

    extern "C" fn idle_loop_test_direct_advance(_target_virtual_ns: i64) -> std::os::raw::c_int {
        0
    }

    fn ceiling(current_icount: u64, max_advance_icount: u64) -> AdvanceCeiling {
        match authorize_advance_ceiling(current_icount, max_advance_icount, None) {
            Ok(ceiling) => ceiling,
            Err(error) => panic!("test ceiling should authorize: {error}"),
        }
    }

    fn publish_ceiling(slot: &NodeSlot, ceiling: AdvanceCeiling) {
        if let Err(error) = slot.publish_scheduler_ceiling(ceiling) {
            panic!("test ceiling should publish: {error}");
        }
    }

    struct RecordingNetworkRxQueue<'a> {
        slot: &'a NodeSlot,
        queued_payloads: Vec<Vec<u8>>,
        direct_advance_ns_at_queue: Vec<i64>,
        slot_status_at_queue: Vec<u8>,
        flush_count: usize,
        queue_error_at: Option<usize>,
    }

    impl<'a> RecordingNetworkRxQueue<'a> {
        fn for_slot(slot: &'a NodeSlot) -> Self {
            Self {
                slot,
                queued_payloads: Vec::new(),
                direct_advance_ns_at_queue: Vec::new(),
                slot_status_at_queue: Vec::new(),
                flush_count: 0,
                queue_error_at: None,
            }
        }
    }

    impl LosslessNetworkRxQueue for RecordingNetworkRxQueue<'_> {
        fn queue_lossless_rx(&mut self, payload: &[u8]) -> Result<(), NetworkRxQueueError> {
            if self.queue_error_at == Some(self.queued_payloads.len()) {
                return Err(NetworkRxQueueError::queue("test queue failure"));
            }
            self.direct_advance_ns_at_queue
                .push(last_direct_advance_ns());
            self.slot_status_at_queue.push(self.slot.snapshot().status);
            self.queued_payloads.push(payload.to_vec());
            Ok(())
        }

        fn flush_lossless_rx(&mut self) -> Result<(), NetworkRxQueueError> {
            self.flush_count += 1;
            Ok(())
        }
    }

    fn header() -> RegionHeader {
        RegionHeader::new(layout())
    }

    fn layout() -> RegionLayout {
        match RegionLayout::for_config(RegionConfig::new(2, 8, 0)) {
            Ok(layout) => layout,
            Err(error) => panic!("test region layout should be valid: {error}"),
        }
    }

    fn empty_entries() -> Vec<FrameEntry> {
        vec![FrameEntry::default(); 4]
    }

    fn enqueue(header: &RingHeader, entries: &mut [FrameEntry], frame: FrameEntry) {
        if let Err(error) = PluginShmemOrdering::enqueue_outbound_frame(header, entries, &frame) {
            panic!("test frame should enqueue: {error}");
        }
    }

    fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
        match FrameEntry::new(delivery_icount, src_node, seq, payload) {
            Ok(frame) => frame,
            Err(error) => panic!("test frame should construct: {error}"),
        }
    }
}
