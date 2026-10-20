//! Shared quantum-boundary classification.
//!
//! A plugin-driven quantum ends when the guest either reaches the scheduler's
//! published ceiling, settles through it, parks at an idle deadline that lies
//! beyond the ceiling, or publishes an explicit zero-length quiesced boundary.
//! A ceiling is an upper bound (RFC-0010 SCHED-12): a settled node's clock may
//! stop at its last retirement below the ceiling.
//! [`classify_quantum_boundary`] is the single decision both the M1 quantum-gate
//! scheduler and the production host-I/O runtime use to detect that end from a
//! [`QemuNodeIdleState`] read, so the two observers agree bit-for-bit on whether
//! a quantum has completed.

use crate::{QemuNodeIdleState, QemuQuantumStopCondition};

/// The classification of a node's progress against a quantum ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuantumBoundary {
    /// The node reached or settled through the ceiling, with its clock at `icount`.
    Reached {
        /// Current node icount: at or beyond the ceiling, or below it when settled.
        icount: u64,
    },
    /// The node parked at `at` with no guest time authorized in this quantum.
    Paused {
        /// Current node icount when it parked.
        at: u64,
        /// The next armed deadline. A value equal to `at` is the protocol's
        /// explicit quiesced-boundary encoding; a value beyond the ceiling is
        /// an ordinary deterministic idle park.
        deadline: u64,
    },
    /// The node has not yet reached the ceiling or a beyond-ceiling idle park.
    Pending,
}

/// Classifies a node's progress against the selected completion boundary.
///
/// Reaching the ceiling takes priority over an idle park: a node whose current
/// icount is at or beyond the ceiling, or that `settled` through it, is
/// [`QuantumBoundary::Reached`] even if it also advertises a deadline. The
/// caller derives `settled` from a settlement record naming the advance that
/// published `ceiling`. An idle node parked with a deadline strictly
/// beyond the ceiling is [`QuantumBoundary::Paused`] (it will not advance past
/// the ceiling this quantum), unless the ceiling is an exact event the node
/// must still reach; that quantum stays pending. An idle publication whose
/// deadline equals its current coordinate is also paused: that zero-length
/// deadline is the shared protocol's explicit quiesced-boundary encoding.
/// Any other state is
/// [`QuantumBoundary::Pending`]. With
/// [`QemuQuantumStopCondition::NextAuthenticatedIdle`], any idle publication
/// below the ceiling is paused; the callers separately enforce publication
/// freshness against the pre-wake generation.
pub(crate) fn classify_quantum_boundary(
    idle: &QemuNodeIdleState,
    ceiling: u64,
    stop_condition: QemuQuantumStopCondition,
    settled: bool,
) -> QuantumBoundary {
    let current = idle.current_icount.retired;
    if current >= ceiling || (settled && current <= ceiling) {
        return QuantumBoundary::Reached { icount: current };
    }
    if let Some(deadline) = idle.next_deadline {
        let deadline = deadline.retired;
        // An exact-event ceiling must still be reached by a time-only
        // advance, so a wake beyond it does not park the node there.
        let parks_below_ceiling =
            deadline > ceiling && stop_condition != QemuQuantumStopCondition::ExactEvent;
        if stop_condition == QemuQuantumStopCondition::NextAuthenticatedIdle
            || deadline == current
            || parks_below_ceiling
        {
            return QuantumBoundary::Paused {
                at: current,
                deadline,
            };
        }
    }
    QuantumBoundary::Pending
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::Icount;

    fn idle(current: u64, deadline: Option<u64>) -> QemuNodeIdleState {
        QemuNodeIdleState {
            current_icount: Icount { retired: current },
            next_deadline: deadline.map(|retired| Icount { retired }),
        }
    }

    #[test]
    fn reaching_the_ceiling_is_reached() {
        assert_eq!(
            classify_quantum_boundary(
                &idle(100, None),
                100,
                QemuQuantumStopCondition::Ceiling,
                false
            ),
            QuantumBoundary::Reached { icount: 100 }
        );
        assert_eq!(
            classify_quantum_boundary(
                &idle(150, None),
                100,
                QemuQuantumStopCondition::Ceiling,
                false
            ),
            QuantumBoundary::Reached { icount: 150 }
        );
    }

    #[test]
    fn reaching_the_ceiling_wins_over_a_deadline() {
        assert_eq!(
            classify_quantum_boundary(
                &idle(100, Some(200)),
                100,
                QemuQuantumStopCondition::NextAuthenticatedIdle,
                false,
            ),
            QuantumBoundary::Reached { icount: 100 }
        );
    }

    #[test]
    fn a_deadline_beyond_the_ceiling_is_paused() {
        assert_eq!(
            classify_quantum_boundary(
                &idle(40, Some(200)),
                100,
                QemuQuantumStopCondition::Ceiling,
                false
            ),
            QuantumBoundary::Paused {
                at: 40,
                deadline: 200,
            }
        );
    }

    #[test]
    fn an_explicit_quiesced_boundary_is_paused() {
        assert_eq!(
            classify_quantum_boundary(
                &idle(40, Some(40)),
                100,
                QemuQuantumStopCondition::Ceiling,
                false
            ),
            QuantumBoundary::Paused {
                at: 40,
                deadline: 40,
            }
        );
    }

    #[test]
    fn a_deadline_at_the_ceiling_is_not_paused() {
        assert_eq!(
            classify_quantum_boundary(
                &idle(40, Some(100)),
                100,
                QemuQuantumStopCondition::Ceiling,
                false
            ),
            QuantumBoundary::Pending
        );
    }

    #[test]
    fn a_deadline_before_the_ceiling_is_pending() {
        assert_eq!(
            classify_quantum_boundary(
                &idle(40, Some(80)),
                100,
                QemuQuantumStopCondition::Ceiling,
                false
            ),
            QuantumBoundary::Pending
        );
    }

    #[test]
    fn no_deadline_below_the_ceiling_is_pending() {
        assert_eq!(
            classify_quantum_boundary(
                &idle(40, None),
                100,
                QemuQuantumStopCondition::Ceiling,
                false
            ),
            QuantumBoundary::Pending
        );
    }

    #[test]
    fn next_idle_pauses_below_an_unrelated_large_ceiling() {
        assert_eq!(
            classify_quantum_boundary(
                &idle(40, Some(80)),
                1_000_000,
                QemuQuantumStopCondition::NextAuthenticatedIdle,
                false,
            ),
            QuantumBoundary::Paused {
                at: 40,
                deadline: 80,
            }
        );
    }

    #[test]
    fn settlement_below_the_ceiling_is_reached() {
        assert_eq!(
            classify_quantum_boundary(
                &idle(951, None),
                1_000,
                QemuQuantumStopCondition::Ceiling,
                true
            ),
            QuantumBoundary::Reached { icount: 951 }
        );
        assert_eq!(
            classify_quantum_boundary(
                &idle(951, None),
                1_000,
                QemuQuantumStopCondition::Ceiling,
                false
            ),
            QuantumBoundary::Pending
        );
    }

    #[test]
    fn an_exact_event_ceiling_does_not_park_below_itself() {
        // The node must still arrive at an exact-event ceiling (SCHED-39), so
        // a wake beyond it leaves the quantum pending until it does.
        assert_eq!(
            classify_quantum_boundary(
                &idle(951, Some(1_200)),
                1_000,
                QemuQuantumStopCondition::ExactEvent,
                false
            ),
            QuantumBoundary::Pending
        );
        assert_eq!(
            classify_quantum_boundary(
                &idle(1_000, Some(1_200)),
                1_000,
                QemuQuantumStopCondition::ExactEvent,
                true
            ),
            QuantumBoundary::Reached { icount: 1_000 }
        );
    }

    #[test]
    fn settlement_wins_over_a_deadline_inside_the_bound() {
        // A settled node has no exact event left in the gap; a published wake
        // at or below the ceiling would contradict that, so settlement decides.
        assert_eq!(
            classify_quantum_boundary(
                &idle(951, Some(980)),
                1_000,
                QemuQuantumStopCondition::ExactEvent,
                true
            ),
            QuantumBoundary::Reached { icount: 951 }
        );
    }
}
