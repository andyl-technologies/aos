//! Deterministic idle-wake planning and deadline conversion.

use super::*;

/// Computes the idle wake target from virtual timers, inbound delivery, the
/// host-published device-I/O completion deadline, and the scheduler ceiling.
///
/// The timer deadline lives in QEMU's virtual-clock domain. The device
/// completion and inbound deadlines already use aggregate icount units. While
/// device I/O holds without a completion deadline, timers are suppressed and
/// the node freezes at the scheduler ceiling. Otherwise the earliest deadline
/// wins, with ties resolved in device, timer, inbound order.
///
/// # Errors
///
/// Returns [`IdleHotLoopError`] when the timer deadline cannot be converted to
/// aggregate icount or the observed ceiling is behind the current icount.
// crucible-lint: allow rust-allow -- the idle wake merge takes independent protocol inputs whose names are clearer than a one-use parameter bundle.
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
    let device_completion_deadline_icount = if device_io_holding_ticks {
        device_completion_deadline_icount
            .filter(|&deadline| deadline != 0)
            .map(|deadline| deadline.max(current_icount))
    } else {
        None
    };
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

pub(super) fn reject_passed_materialized_frames(
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

pub(super) fn reject_passed_inbound_delivery(
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
/// [`IdleHotLoopError::TimerDeadlineOverflow`] when conversion would overflow.
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
