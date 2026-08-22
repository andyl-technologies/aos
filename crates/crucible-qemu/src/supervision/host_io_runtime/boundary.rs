//! Stable shared-memory boundary classification helpers.

use super::*;

/// Returns the number of poll attempts that fit within `timeout`, at least one.
pub(super) fn bounded_poll_attempts(timeout: Duration, poll_interval: Duration) -> u64 {
    let interval = poll_interval.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
}

/// Classifies a snapshot while accounting for the latest host wake.
///
/// The initial quantum wake and a servicing pass that publishes a response can
/// both make an idle guest runnable. A snapshot from before QEMU consumes that
/// wake no longer proves that the guest remains parked before its ceiling, so an
/// early-idle pause requires a later stable plugin publication. A node already
/// at its ceiling remains complete, however: the wake cannot authorize it to
/// advance farther, and requiring another publication would deadlock with QEMU
/// waiting for a strictly later ceiling.
pub(super) fn classify_after_host_wake(
    idle: &crate::QemuNodeIdleState,
    ceiling: u64,
    device_wake_unacknowledged: bool,
) -> QuantumBoundary {
    let boundary = classify_quantum_boundary(idle, ceiling);
    if device_wake_unacknowledged && matches!(boundary, QuantumBoundary::Paused { .. }) {
        return QuantumBoundary::Pending;
    }
    boundary
}

/// Classifies a boundary after both scheduler-input and host-device wakes.
///
/// Scheduler input can make an otherwise valid future-idle report runnable, so
/// its pre-wake generation invalidates every boundary class until superseded.
pub(super) fn classify_after_scheduler_and_host_wake(
    idle: &crate::QemuNodeIdleState,
    ceiling: u64,
    scheduler_input_unobserved: bool,
    device_wake_unacknowledged: bool,
) -> QuantumBoundary {
    if scheduler_input_unobserved {
        QuantumBoundary::Pending
    } else {
        classify_after_host_wake(idle, ceiling, device_wake_unacknowledged)
    }
}

/// Returns whether the plugin has not yet published after a device wake.
pub(super) fn device_wake_publication_is_unobserved(
    initial_generation: Option<u32>,
    snapshot: &crucible_shmem::NodeSlotSnapshot,
) -> bool {
    initial_generation.is_some_and(|generation| snapshot.publish_gen == generation)
}

/// Returns the coordinate of an idle publication that authorizes no future time.
pub(super) fn checkpoint_idle_coordinate(
    snapshot: &crucible_shmem::NodeSlotSnapshot,
) -> Option<u64> {
    (snapshot.status == STATUS_IDLE && snapshot.idle_wake_icount <= snapshot.current_icount)
        .then_some(snapshot.current_icount)
}

/// Returns whether a pre-advance zero-length idle marker remains unreleased.
pub(super) fn checkpoint_idle_publication_is_unreleased(
    coordinate: Option<u64>,
    snapshot: &crucible_shmem::NodeSlotSnapshot,
) -> bool {
    coordinate.is_some_and(|coordinate| {
        snapshot.status == STATUS_IDLE
            && snapshot.current_icount == coordinate
            && snapshot.idle_wake_icount <= snapshot.current_icount
    })
}

/// Returns whether checkpoint pause needs a QEMU main-loop control edge.
pub(super) fn checkpoint_pause_requires_control_doorbell(
    snapshot: &crucible_shmem::NodeSlotSnapshot,
    device_servicers_attached: bool,
) -> bool {
    !device_servicers_attached
        || snapshot.status != STATUS_IDLE
        || snapshot.idle_wake_icount == snapshot.current_icount
}

/// Returns whether the plugin release-acknowledged an even host request.
///
/// Other runtime operations may complete their own handshakes while an advance
/// is polling. Consequently, the observed odd token may be a later
/// acknowledgement rather than the request's immediate successor. Tokens use
/// wrapping serial-number order: an odd value less than half the `u32` space
/// ahead of `request` acknowledges it, while the odd predecessor is stale.
pub(super) fn control_boundary_request_is_acknowledged(
    request: u32,
    snapshot: &crucible_shmem::NodeSlotSnapshot,
) -> bool {
    let observed = snapshot.control_boundary_ack;
    let forward_distance = observed.wrapping_sub(request);
    request & 1 == 0
        && observed & 1 == 1
        && forward_distance != 0
        && forward_distance < (1_u32 << 31)
}

/// Returns whether a post-device clamp publication is safe to expose.
///
/// A fresh all-halted publication may conservatively tighten a retained future
/// QEMU timer deadline. It may not extend that deadline or collapse it to the
/// current coordinate. When no future deadline was retained, the control
/// callback first fences at the current coordinate and a later all-halted
/// publication may install any fresh exact future deadline. That deadline is
/// descriptive only: the scheduler ceiling remains clamped at the current
/// coordinate until the next quantum explicitly authorizes progress.
/// A vCPU-resume edge may transiently republish `RUNNING` after the acknowledged
/// callback. That edge is also settled when the exact clamp is still installed:
/// it cannot dispatch guest time, and the retained deadline proves that it did
/// not replace the acknowledged idle coordinate with a later publication.
pub(super) fn completed_quantum_clamp_is_settled(
    boundary_acknowledged: bool,
    expected_current_icount: u64,
    expected_idle_wake_icount: u64,
    device_progress: bool,
    snapshot: &crucible_shmem::NodeSlotSnapshot,
) -> bool {
    let idle_wake_is_canonical = if expected_idle_wake_icount > expected_current_icount {
        snapshot.idle_wake_icount > expected_current_icount
            && snapshot.idle_wake_icount <= expected_idle_wake_icount
    } else {
        snapshot.idle_wake_icount >= expected_current_icount
    };

    let dispatch_is_fenced = snapshot.max_advance_icount == expected_current_icount;
    let status_is_settled = snapshot.status == STATUS_IDLE
        || (snapshot.status == crucible_shmem::STATUS_RUNNING
            && snapshot.idle_wake_icount > expected_current_icount);

    boundary_acknowledged
        && !device_progress
        && snapshot.current_icount == expected_current_icount
        && dispatch_is_fenced
        && status_is_settled
        && idle_wake_is_canonical
        && snapshot.device_io_active == 0
}
