//! Shared quantum-boundary classification.
//!
//! A plugin-driven quantum ends when the guest either reaches the scheduler's
//! published ceiling, parks at an idle deadline that lies beyond the ceiling,
//! or publishes an explicit zero-length quiesced boundary.
//! [`classify_quantum_boundary`] is the single decision both the M1 quantum-gate
//! scheduler and the production host-I/O runtime use to detect that end from a
//! [`QemuNodeIdleState`] read, so the two observers agree bit-for-bit on whether
//! a quantum has completed.

use crate::QemuNodeIdleState;

/// The classification of a node's progress against a quantum ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuantumBoundary {
    /// The node reached (or passed) the ceiling at `icount`.
    Reached {
        /// Current node icount at or beyond the ceiling.
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

/// Classifies a node's progress against the published quantum `ceiling`.
///
/// Reaching the ceiling takes priority over an idle park: a node whose current
/// icount is at or beyond the ceiling is [`QuantumBoundary::Reached`] even if it
/// also advertises a deadline. An idle node parked with a deadline strictly
/// beyond the ceiling is [`QuantumBoundary::Paused`] (it will not advance past
/// the ceiling this quantum). An idle publication whose deadline equals its
/// current coordinate is also paused: that zero-length deadline is the shared
/// protocol's explicit quiesced-boundary encoding. Any other state is
/// [`QuantumBoundary::Pending`].
pub(crate) fn classify_quantum_boundary(idle: &QemuNodeIdleState, ceiling: u64) -> QuantumBoundary {
    let current = idle.current_icount.retired;
    if current >= ceiling {
        return QuantumBoundary::Reached { icount: current };
    }
    if let Some(deadline) = idle.next_deadline {
        let deadline = deadline.retired;
        if deadline == current || deadline > ceiling {
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
            classify_quantum_boundary(&idle(100, None), 100),
            QuantumBoundary::Reached { icount: 100 }
        );
        assert_eq!(
            classify_quantum_boundary(&idle(150, None), 100),
            QuantumBoundary::Reached { icount: 150 }
        );
    }

    #[test]
    fn reaching_the_ceiling_wins_over_a_deadline() {
        assert_eq!(
            classify_quantum_boundary(&idle(100, Some(200)), 100),
            QuantumBoundary::Reached { icount: 100 }
        );
    }

    #[test]
    fn a_deadline_beyond_the_ceiling_is_paused() {
        assert_eq!(
            classify_quantum_boundary(&idle(40, Some(200)), 100),
            QuantumBoundary::Paused {
                at: 40,
                deadline: 200,
            }
        );
    }

    #[test]
    fn an_explicit_quiesced_boundary_is_paused() {
        assert_eq!(
            classify_quantum_boundary(&idle(40, Some(40)), 100),
            QuantumBoundary::Paused {
                at: 40,
                deadline: 40,
            }
        );
    }

    #[test]
    fn a_deadline_at_the_ceiling_is_not_paused() {
        assert_eq!(
            classify_quantum_boundary(&idle(40, Some(100)), 100),
            QuantumBoundary::Pending
        );
    }

    #[test]
    fn a_deadline_before_the_ceiling_is_pending() {
        assert_eq!(
            classify_quantum_boundary(&idle(40, Some(80)), 100),
            QuantumBoundary::Pending
        );
    }

    #[test]
    fn no_deadline_below_the_ceiling_is_pending() {
        assert_eq!(
            classify_quantum_boundary(&idle(40, None), 100),
            QuantumBoundary::Pending
        );
    }
}
