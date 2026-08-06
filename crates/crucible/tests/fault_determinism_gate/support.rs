//! Decision-stream divergence localization helpers for the fault gate.

use crucible::{Decision, EffectOutcomeDecision, MembershipFault};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DecisionDivergence {
    pub(super) index: usize,
    pub(super) expected: Option<Decision>,
    pub(super) actual: Option<Decision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EffectOutcomeDecisionDivergence {
    pub(super) index: usize,
    pub(super) expected: Option<EffectOutcomeDecision>,
    pub(super) actual: Option<EffectOutcomeDecision>,
}

pub(super) fn first_differing_fault_decision(
    expected: &[Decision],
    actual: &[Decision],
) -> Option<EffectOutcomeDecisionDivergence> {
    let len = expected.len().max(actual.len());
    (0..len).find_map(|index| {
        let expected = expected.get(index);
        let actual = actual.get(index);
        if expected == actual {
            return None;
        }

        let expected = fault_decision(expected);
        let actual = fault_decision(actual);
        if expected.is_some() || actual.is_some() {
            Some(EffectOutcomeDecisionDivergence {
                index,
                expected,
                actual,
            })
        } else {
            None
        }
    })
}

pub(super) fn first_differing_decision(
    expected: &[Decision],
    actual: &[Decision],
) -> Option<DecisionDivergence> {
    let len = expected.len().max(actual.len());
    (0..len).find_map(|index| {
        let expected = expected.get(index).cloned();
        let actual = actual.get(index).cloned();
        if expected == actual {
            None
        } else {
            Some(DecisionDivergence {
                index,
                expected,
                actual,
            })
        }
    })
}

fn fault_decision(decision: Option<&Decision>) -> Option<EffectOutcomeDecision> {
    match decision {
        Some(Decision::EffectOutcome(decision)) => Some(decision.clone()),
        _ => None,
    }
}

pub(super) fn membership_kind(fault: &MembershipFault) -> &'static str {
    match fault {
        MembershipFault::Crash { .. } => "crash",
        MembershipFault::Partition { .. } => "partition",
        MembershipFault::Isolate { .. } => "isolate",
        MembershipFault::NotYetJoined { .. } => "not-yet-joined",
        MembershipFault::Taxonomy { fault } => fault.kind_key(),
    }
}
