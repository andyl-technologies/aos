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
    /// Device I/O is in flight and the host published a completion deadline, so
    /// the node idle-jumps directly to that completion icount.
    DeviceIoCompletion,
    /// Device I/O is in flight with no host-published completion deadline, so
    /// guest timer deadlines are held and the node freezes to the ceiling.
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
    device_completion_deadline_icount: Option<u64>,
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

    /// Returns the host-published device-I/O completion deadline that entered the
    /// merge, if device I/O was holding and a nonzero deadline was published.
    ///
    /// This is the clamped value (never earlier than the current icount) that the
    /// merge actually considered, not the raw slot field.
    #[must_use]
    pub const fn device_completion_deadline_icount(&self) -> Option<u64> {
        self.device_completion_deadline_icount
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
        let device_completion_deadline_icount = if device_io_holding_ticks {
            Some(PluginShmemOrdering::device_completion_deadline_icount(slot))
        } else {
            None
        };

        PluginShmemOrdering::publish_reached_icount(slot, current_icount, clock.icount_shift())
            .map_err(|source| IdleHotLoopError::PublishReached { source })?;

        let plan = compute_idle_wake_plan(
            current_icount,
            clock.icount_shift(),
            exact_deadline,
            next_inbound_delivery_icount,
            SchedulerCeiling::new(ceiling_icount),
            device_io_holding_ticks,
            device_completion_deadline_icount,
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

/// Computes the idle wake target from virtual timers, inbound delivery, the
/// host-published device-I/O completion deadline, and the scheduler ceiling.
///
/// # Which live path uses this
///
/// The production live TCG sim loop does **not** drive its advance through this
/// function: it bounds a running guest via the `register_sim_shmem_dispatch`
/// max-advance callback (`max_advance_icount`) and never reaches an idle-plan
/// merge for a device-I/O-blocked guest. This function is retained for the
/// idle-hot-loop path used by non-sim-loop callers and reachable configurations
/// (`PluginIdleHotLoop::begin_idle`); the device-deadline arm below exists so
/// that if that path ever executes it honors device completions with the exact
/// same merge rule the max-advance seam uses, rather than silently diverging.
/// Keep the two in lockstep.
///
/// # Merge rule
///
/// The timer deadline lives in QEMU's own virtual-clock domain (converted to
/// aggregate icount here); the device completion deadline arrives from the host
/// block-I/O servicer in the shared-memory slot, already in icount units. When
/// `device_io_holding_ticks` is set the node is blocked on an in-flight device
/// request, and the wake is the earliest of the pending events:
///
/// - **A host-published completion deadline is present** (`Some`, nonzero):
///   the wake is `min(device_completion, timer, inbound)`. The device
///   completion is the event that unblocks the guest; the timer rejoins the
///   merge because a virtual-timer IRQ can wake a device-blocked vCPU before
///   the I/O completes, after which it re-parks against the same completion.
///   A completion deadline that is `0`/retracted contributes nothing, and a
///   deadline in the past is clamped forward to `current_icount` (wake now) so
///   a stale deadline never rewinds virtual time.
/// - **No completion deadline is published** (`0`/retracted): timer deadlines
///   stay held and the node freezes to the ceiling ([`IdleWakeCause::DeviceIoFreeze`]).
///   Without a completion path, waking to a periodic timer would spin the guest
///   against an I/O that cannot advance within the quantum.
///
/// When `device_io_holding_ticks` is false the device deadline is ignored and
/// the wake is `min(timer, inbound)`, falling back to the ceiling.
///
/// On exact-icount ties the winner is chosen deterministically in the fixed
/// priority order device completion, then timer, then inbound.
///
/// # Errors
///
/// Returns [`IdleHotLoopError`] when the timer deadline cannot be converted to
/// an aggregate icount or the observed ceiling is behind the current icount.
// crucible-lint: allow rust-allow -- the idle wake merge takes the full set of independent wake inputs (current icount, shift, timer deadline, inbound, ceiling, device-hold, device deadline); bundling them would obscure the merge.
#[allow(clippy::too_many_arguments)]
pub fn compute_idle_wake_plan(
    current_icount: u64,
    icount_shift: u8,
    exact_deadline: ExactDeadlineReport,
    next_inbound_delivery_icount: Option<u64>,
    ceiling: SchedulerCeiling,
    device_io_holding_ticks: bool,
    device_completion_deadline_icount: Option<u64>,
) -> Result<IdleWakePlan, IdleHotLoopError> {
    if ceiling.icount() < current_icount {
        return Err(IdleHotLoopError::CeilingBehindCurrent {
            current_icount,
            ceiling_icount: ceiling.icount(),
        });
    }

    let timer_deadline_icount = timer_deadline_icount(exact_deadline, icount_shift)?
        .map(|deadline| deadline.max(current_icount));
    let inbound_delivery_icount = next_inbound_delivery_icount;

    // The device completion deadline only participates while device I/O holds.
    // A zero deadline means "none published / retracted"; a past deadline is
    // clamped forward so it can never rewind virtual time below the current
    // icount (the classic stale-deadline-in-the-past hazard).
    let device_completion_deadline_icount = if device_io_holding_ticks {
        device_completion_deadline_icount
            .filter(|&deadline| deadline != 0)
            .map(|deadline| deadline.max(current_icount))
    } else {
        None
    };

    // While device I/O holds without a completion deadline, timer deadlines are
    // suppressed and the node freezes to the ceiling. Once the host publishes a
    // completion deadline, the timer rejoins the merge as a legitimate earlier
    // wake.
    let effective_timer_deadline_icount =
        if device_io_holding_ticks && device_completion_deadline_icount.is_none() {
            None
        } else {
            timer_deadline_icount
        };

    let mut earliest: Option<(u64, IdleWakeCause)> = None;
    merge_earlier_wake(
        &mut earliest,
        device_completion_deadline_icount,
        IdleWakeCause::DeviceIoCompletion,
    );
    merge_earlier_wake(
        &mut earliest,
        effective_timer_deadline_icount,
        IdleWakeCause::TimerDeadline,
    );
    merge_earlier_wake(
        &mut earliest,
        inbound_delivery_icount,
        IdleWakeCause::InboundFrame,
    );

    let (desired_wake_icount, cause) = earliest.unwrap_or_else(|| {
        if device_io_holding_ticks {
            (ceiling.icount(), IdleWakeCause::DeviceIoFreeze)
        } else {
            (ceiling.icount(), IdleWakeCause::SchedulerCeiling)
        }
    });

    Ok(IdleWakePlan {
        current_icount,
        desired_wake_icount,
        ceiling_icount: ceiling.icount(),
        timer_deadline_icount,
        inbound_delivery_icount,
        device_completion_deadline_icount,
        device_io_holding_ticks,
        cause,
    })
}

/// Keeps `earliest` at the strictly-smallest wake icount seen so far.
///
/// A `None` candidate is ignored. On an exact tie the incumbent is retained, so
/// the caller's invocation order fixes the tie-break priority.
fn merge_earlier_wake(
    earliest: &mut Option<(u64, IdleWakeCause)>,
    candidate: Option<u64>,
    cause: IdleWakeCause,
) {
    if let Some(icount) = candidate
        && earliest.is_none_or(|(current, _)| icount < current)
    {
        *earliest = Some((icount, cause));
    }
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
mod tests;
