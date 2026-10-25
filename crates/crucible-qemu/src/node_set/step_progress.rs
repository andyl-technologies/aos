//! Progress classification for one scheduler-selected node step.
//!
//! A step reissues its advance while QEMU pauses early. These helpers decide
//! whether a pause at the previous coordinate still made progress: an inbound
//! batch consumed without retiring an instruction, or a fresh timer or
//! control boundary seen once. Only a repeat of the same boundary is a stall.

use crucible::{Icount, StepObservation, VirtualTime};
use crucible_shmem::MAX_FRAME_DELIVERY_ATTEMPTS;

use crate::QemuNodeIdleState;

/// Maximum early-pause reissues for one scheduler-selected node step.
///
/// A backpressured FIFO head can create one exact pause per canonical QEMU RX
/// attempt. Use the public transport hard bound so a valid retained frame can
/// exhaust its own typed retry budget before this adapter reports a generic
/// progress failure.
pub(super) const MAX_STEP_REISSUES: u32 = MAX_FRAME_DELIVERY_ATTEMPTS;

pub(super) fn consumed_input_without_retiring(
    observation: &StepObservation,
    previous: VirtualTime,
    inbound_frames_consumed: usize,
) -> bool {
    observation.reached == previous
        && matches!(observation.outcome, crucible::AdvanceOutcome::Paused { .. })
        && inbound_frames_consumed > 0
}

pub(super) fn stagnant_pause_boundary(
    observation: &StepObservation,
    previous: VirtualTime,
    final_state: Option<QemuNodeIdleState>,
) -> Option<(VirtualTime, Option<Icount>)> {
    (observation.reached == previous
        && matches!(observation.outcome, crucible::AdvanceOutcome::Paused { .. }))
    .then(|| {
        (
            observation.reached,
            final_state.and_then(|state| state.next_deadline),
        )
    })
}

#[cfg(test)]
mod tests {
    use crucible::AdvanceOutcome;

    use super::*;

    #[test]
    fn current_coordinate_input_consumption_is_reissuable_boundary_progress() {
        let previous = VirtualTime { ticks: 41 };
        let paused = StepObservation::from_advance_outcome(
            VirtualTime { ticks: 100 },
            AdvanceOutcome::Paused {
                at: Icount { retired: 41 },
            },
        );

        assert!(consumed_input_without_retiring(&paused, previous, 1));
        assert!(!consumed_input_without_retiring(&paused, previous, 0));

        let regressed = StepObservation::from_advance_outcome(
            VirtualTime { ticks: 100 },
            AdvanceOutcome::Paused {
                at: Icount { retired: 40 },
            },
        );
        assert!(!consumed_input_without_retiring(&regressed, previous, 1));
    }

    #[test]
    fn fresh_stagnant_pause_is_progress_but_an_identical_repeat_is_not() {
        let previous = VirtualTime { ticks: 41 };
        let paused = StepObservation::from_advance_outcome(
            VirtualTime { ticks: 100 },
            AdvanceOutcome::Paused {
                at: Icount { retired: 41 },
            },
        );
        let first = stagnant_pause_boundary(
            &paused,
            previous,
            Some(QemuNodeIdleState {
                current_icount: Icount { retired: 41 },
                next_deadline: Some(Icount { retired: 60 }),
            }),
        );
        assert_eq!(first, Some((previous, Some(Icount { retired: 60 }))));

        let repeated = stagnant_pause_boundary(
            &paused,
            previous,
            Some(QemuNodeIdleState {
                current_icount: Icount { retired: 41 },
                next_deadline: Some(Icount { retired: 60 }),
            }),
        );
        assert_eq!(repeated, first);

        let advanced_boundary = stagnant_pause_boundary(
            &paused,
            previous,
            Some(QemuNodeIdleState {
                current_icount: Icount { retired: 41 },
                next_deadline: Some(Icount { retired: 61 }),
            }),
        );
        assert_ne!(advanced_boundary, first);

        let regressed = StepObservation::from_advance_outcome(
            VirtualTime { ticks: 100 },
            AdvanceOutcome::Paused {
                at: Icount { retired: 40 },
            },
        );
        assert_eq!(stagnant_pause_boundary(&regressed, previous, None), None);
    }
}
