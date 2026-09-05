//! Pure projection of future time-predicate transitions from durable trigger state.
//!
//! Exact time predicates are pulses, not overdue predicates. Both their rising
//! and falling edges matter: a repeatable disjunction must observe false between
//! distinct pulses, and negation may become true immediately after a pulse.

use super::*;

/// Reports whether a condition depends on a global time-predicate coordinate.
pub(super) fn requires_global_time(condition: &Condition) -> bool {
    match condition {
        Condition::At { .. } | Condition::After { .. } | Condition::Timer { .. } => true,
        Condition::AllOf { predicates } | Condition::AnyOf { predicates } => {
            predicates.iter().any(requires_global_time)
        }
        Condition::Once { predicate } | Condition::Not { predicate } => {
            requires_global_time(predicate)
        }
        Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. } => false,
    }
}

/// Borrows the durable facts used to project one condition's future transitions.
pub(super) struct TriggerDeadlineProjection<'a> {
    /// Settled boundary, excluded from the future projection.
    pub after: VirtualTime,
    /// Clock resolution used to observe the end of an exact-time pulse.
    pub shift: Shift,
    /// Most recent firing of every observed event.
    pub last_firing: &'a BTreeMap<EventId, VirtualTime>,
    /// Currently armed timer coordinates, after cancellations and replacements.
    pub timer_fires: &'a BTreeMap<TimerId, VirtualTime>,
    /// Inner predicates already latched by `Once`.
    pub once_latches: &'a [Condition],
}

impl TriggerDeadlineProjection<'_> {
    /// Finds the first time transition where the full condition may be true.
    pub fn next_activation(&self, condition: &Condition) -> Option<VirtualTime> {
        let mut transitions = BTreeSet::new();
        self.collect_transitions(condition, &mut transitions);
        transitions
            .into_iter()
            .find(|at| self.possible_truth(condition, *at).can_be_true)
    }

    fn collect_transitions(&self, condition: &Condition, transitions: &mut BTreeSet<VirtualTime>) {
        match condition {
            Condition::AllOf { predicates } | Condition::AnyOf { predicates } => {
                for predicate in predicates {
                    self.collect_transitions(predicate, transitions);
                }
            }
            Condition::Once { predicate } if self.once_latches.contains(predicate) => {}
            Condition::Once { predicate } | Condition::Not { predicate } => {
                self.collect_transitions(predicate, transitions)
            }
            _ => {
                if let Some(at) = self.next_transition(condition, false) {
                    transitions.insert(at);
                    if let Some(ticks) = at.ticks.checked_add(1_u64 << self.shift.bits) {
                        transitions.insert(VirtualTime { ticks });
                    }
                } else if let Some(at) = self.next_transition(condition, true) {
                    transitions.insert(at);
                }
            }
        }
    }

    // Observational leaves remain unknown until their actual evaluation point.
    // A certainly-false time conjunction is only bookkeeping, while a negated
    // pulse can activate on its falling edge and must still prevent termination.
    fn possible_truth(&self, condition: &Condition, at: VirtualTime) -> TemporalTruth {
        match condition {
            Condition::At { at: deadline } => TemporalTruth::known(*deadline == at),
            Condition::After { duration, of } => TemporalTruth::known(
                self.last_firing
                    .get(of)
                    .and_then(|fired| fired.ticks.checked_add(duration.nanos))
                    == Some(at.ticks),
            ),
            Condition::Timer { name } => {
                TemporalTruth::known(self.timer_fires.get(name) == Some(&at))
            }
            Condition::AllOf { predicates } => {
                predicates
                    .iter()
                    .fold(TemporalTruth::known(true), |truth, predicate| {
                        let next = self.possible_truth(predicate, at);
                        TemporalTruth {
                            can_be_true: truth.can_be_true && next.can_be_true,
                            can_be_false: truth.can_be_false || next.can_be_false,
                        }
                    })
            }
            Condition::AnyOf { predicates } => {
                predicates
                    .iter()
                    .fold(TemporalTruth::known(false), |truth, predicate| {
                        let next = self.possible_truth(predicate, at);
                        TemporalTruth {
                            can_be_true: truth.can_be_true || next.can_be_true,
                            can_be_false: truth.can_be_false && next.can_be_false,
                        }
                    })
            }
            Condition::Not { predicate } => {
                let truth = self.possible_truth(predicate, at);
                TemporalTruth {
                    can_be_true: truth.can_be_false,
                    can_be_false: truth.can_be_true,
                }
            }
            Condition::Once { predicate } if self.once_latches.contains(predicate) => {
                TemporalTruth::known(true)
            }
            // A currently unlatched Once may latch at an intervening evaluation.
            Condition::Once { .. }
            | Condition::NetworkMatch { .. }
            | Condition::ConsoleMatch { .. }
            | Condition::CoveragePoint { .. }
            | Condition::MemoryPredicate { .. }
            | Condition::IoPattern { .. }
            | Condition::NodeState { .. }
            | Condition::AssertionState { .. }
            | Condition::Quiescent
            | Condition::Named { .. }
            | Condition::GuestMarker { .. } => TemporalTruth {
                can_be_true: true,
                can_be_false: true,
            },
        }
    }

    /// Finds the first future leaf transition, optionally including pulse ends.
    pub fn next_transition(
        &self,
        condition: &Condition,
        include_falling: bool,
    ) -> Option<VirtualTime> {
        match condition {
            Condition::At { at } => self.next_pulse_transition(*at, include_falling),
            Condition::After { duration, of } => self
                .last_firing
                .get(of)
                .and_then(|fired| fired.ticks.checked_add(duration.nanos))
                .and_then(|ticks| {
                    self.next_pulse_transition(VirtualTime { ticks }, include_falling)
                }),
            Condition::Timer { name } => self
                .timer_fires
                .get(name)
                .and_then(|at| self.next_pulse_transition(*at, include_falling)),
            Condition::AllOf { predicates } | Condition::AnyOf { predicates } => predicates
                .iter()
                .filter_map(|predicate| self.next_transition(predicate, include_falling))
                .min(),
            Condition::Once { predicate } if self.once_latches.contains(predicate) => None,
            Condition::Once { predicate } | Condition::Not { predicate } => {
                self.next_transition(predicate, include_falling)
            }
            Condition::NetworkMatch { .. }
            | Condition::ConsoleMatch { .. }
            | Condition::CoveragePoint { .. }
            | Condition::MemoryPredicate { .. }
            | Condition::IoPattern { .. }
            | Condition::NodeState { .. }
            | Condition::AssertionState { .. }
            | Condition::Quiescent
            | Condition::Named { .. }
            | Condition::GuestMarker { .. } => None,
        }
    }

    fn next_pulse_transition(&self, at: VirtualTime, include_falling: bool) -> Option<VirtualTime> {
        if at > self.after {
            return Some(at);
        }
        if !include_falling {
            return None;
        }
        // A clock cannot represent a boundary beyond u64::MAX. An overflowing
        // falling edge therefore has no future scheduler coordinate.
        at.ticks
            .checked_add(1_u64 << self.shift.bits)
            .filter(|ticks| *ticks > self.after.ticks)
            .map(|ticks| VirtualTime { ticks })
    }
}

struct TemporalTruth {
    can_be_true: bool,
    can_be_false: bool,
}

impl TemporalTruth {
    const fn known(value: bool) -> Self {
        Self {
            can_be_true: value,
            can_be_false: !value,
        }
    }
}
