//! Checks T-ASRT-12 assertion lifecycle states and unified outcomes.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionRunVerdict, ConditionEventLogPrefix, ConditionLeaf,
    HostAssertionEvaluator, HostAssertionOutcome, HostAssertionOutcomeKind, HostAssertionPredicate,
    LintedHostAssertionOracle, ObservedState, Predicate, Properties, Property,
    PropertyLifecycleState, ReachabilityExpectation, ReachableDisposition, VirtualTime, World,
};

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn assertion(id: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: format!("assertion {id}"),
        property,
    }
}

fn properties(assertions: Vec<AssertionDef>) -> Properties {
    let world = World::from_nodes(Vec::new()).expect("empty lifecycle world should build");
    Properties::from_assertions_for_world(&world, assertions)
        .expect("assertion lifecycle properties should validate")
}

fn prefix(ticks: u64) -> ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_observable_events_for_test(ticks, Vec::new())
        .expect("lifecycle test prefix should be checked")
}

fn outcome<'a>(outcomes: &'a [HostAssertionOutcome], assertion: &str) -> &'a HostAssertionOutcome {
    outcomes
        .iter()
        .find(|outcome| outcome.assertion.name == assertion)
        .unwrap_or_else(|| panic!("missing outcome for assertion {assertion}"))
}

fn lifecycle(
    evaluator: &HostAssertionEvaluator,
    assertion: &str,
) -> Option<PropertyLifecycleState> {
    evaluator
        .lifecycle_states()
        .into_iter()
        .find(|state| state.assertion.name == assertion)
        .map(|state| state.state)
}

fn lifecycle_or_panic(
    evaluator: &HostAssertionEvaluator,
    assertion: &str,
) -> PropertyLifecycleState {
    lifecycle(evaluator, assertion)
        .unwrap_or_else(|| panic!("missing lifecycle state for assertion {assertion}"))
}

fn linted_host_oracle<O>(oracle: O) -> LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    crucible::test_support::unchecked_host_assertion_oracle_for_test(oracle)
}

fn lifecycle_oracle(state: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
    match leaf {
        ConditionLeaf::Named { name, nodes } => {
            assert!(nodes.is_empty());
            match name {
                "always-ok" | "hit" | "terminal-ok" => true,
                "trigger" => state.at() == time(1),
                "done" => state.at() == time(3),
                "forbidden" => false,
                _ => panic!("unexpected lifecycle predicate {name}"),
            }
        }
        ConditionLeaf::GuestMarker { .. } => false,
    }
}

#[test]
fn lifecycle_states_progress_and_terminal_outcomes_distinguish_passed_from_satisfied() {
    let properties = properties(vec![
        assertion(
            "after-terminal",
            Property::AfterQuiescence {
                predicate: Predicate::named("terminal-ok"),
            },
        ),
        assertion(
            "always-safe",
            Property::Always {
                predicate: Predicate::named("always-ok"),
            },
        ),
        assertion(
            "eventually-open",
            Property::Eventually {
                trigger: Predicate::named("trigger"),
                property: Predicate::named("done"),
                deadline: time(5),
            },
        ),
        assertion(
            "sometimes-hit",
            Property::Sometimes {
                predicate: Predicate::named("hit"),
            },
        ),
        assertion(
            "unreachable-safe",
            Property::Reachable {
                predicate: Predicate::named("forbidden"),
                expectation: ReachabilityExpectation::Unreachable,
            },
        ),
    ]);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = linted_host_oracle(lifecycle_oracle);

    assert_eq!(
        lifecycle_or_panic(&evaluator, "after-terminal"),
        PropertyLifecycleState::Declared
    );
    evaluator.observe_prefix(&prefix(1), &mut oracle);

    assert_eq!(
        lifecycle_or_panic(&evaluator, "after-terminal"),
        PropertyLifecycleState::Declared
    );
    assert_eq!(
        lifecycle_or_panic(&evaluator, "always-safe"),
        PropertyLifecycleState::Passing
    );
    assert_eq!(
        lifecycle_or_panic(&evaluator, "eventually-open"),
        PropertyLifecycleState::Failing
    );
    assert_eq!(
        lifecycle_or_panic(&evaluator, "sometimes-hit"),
        PropertyLifecycleState::Satisfied
    );
    assert_eq!(
        lifecycle_or_panic(&evaluator, "unreachable-safe"),
        PropertyLifecycleState::Passing
    );

    let report = evaluator.finalize_prefix(&prefix(3), &mut oracle);

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(report.outcomes().len(), 5);
    assert_eq!(
        outcome(report.outcomes(), "after-terminal").kind,
        HostAssertionOutcomeKind::Passed
    );
    assert_eq!(
        outcome(report.outcomes(), "after-terminal").lifecycle,
        PropertyLifecycleState::Passing
    );
    assert_eq!(
        outcome(report.outcomes(), "always-safe").kind,
        HostAssertionOutcomeKind::Passed
    );
    assert_eq!(
        outcome(report.outcomes(), "eventually-open").kind,
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome(report.outcomes(), "sometimes-hit").kind,
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome(report.outcomes(), "unreachable-safe").kind,
        HostAssertionOutcomeKind::Passed
    );
}

#[test]
fn edge_outcomes_carry_lifecycle_and_verdict_disposition() {
    let properties = properties(vec![
        assertion(
            "eventually-never-triggered",
            Property::Eventually {
                trigger: Predicate::named("missing-trigger"),
                property: Predicate::named("missing-done"),
                deadline: time(5),
            },
        ),
        assertion(
            "reachable-fail",
            Property::Reachable {
                predicate: Predicate::named("missing-reachable-fail"),
                expectation: ReachabilityExpectation::Reachable {
                    on_unreached: ReachableDisposition::Fail,
                },
            },
        ),
        assertion(
            "reachable-warn",
            Property::Reachable {
                predicate: Predicate::named("missing-reachable-warn"),
                expectation: ReachabilityExpectation::Reachable {
                    on_unreached: ReachableDisposition::Warn,
                },
            },
        ),
        assertion(
            "sometimes-missing",
            Property::Sometimes {
                predicate: Predicate::named("missing-sometimes"),
            },
        ),
    ]);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle =
        linted_host_oracle(
            |_state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
                ConditionLeaf::Named { nodes, .. } => {
                    assert!(nodes.is_empty());
                    false
                }
                ConditionLeaf::GuestMarker { .. } => false,
            },
        );

    let report = evaluator.finalize_prefix(&prefix(1), &mut oracle);

    assert!(report.verdict().is_failed());
    assert_eq!(
        outcome(report.outcomes(), "eventually-never-triggered").kind,
        HostAssertionOutcomeKind::NeverTriggered
    );
    assert_eq!(
        outcome(report.outcomes(), "eventually-never-triggered").lifecycle,
        PropertyLifecycleState::Passing
    );
    assert_eq!(
        outcome(report.outcomes(), "reachable-warn").kind,
        HostAssertionOutcomeKind::NeverReachedWarn
    );
    assert_eq!(
        outcome(report.outcomes(), "reachable-warn").lifecycle,
        PropertyLifecycleState::Passing
    );
    assert_eq!(
        outcome(report.outcomes(), "reachable-fail").kind,
        HostAssertionOutcomeKind::NeverReachedFail
    );
    assert_eq!(
        outcome(report.outcomes(), "reachable-fail").lifecycle,
        PropertyLifecycleState::Violated
    );
    assert_eq!(
        outcome(report.outcomes(), "sometimes-missing").kind,
        HostAssertionOutcomeKind::Violated
    );
    assert_eq!(
        report.verdict().failures().len(),
        2,
        "only violated and fail-disposition outcomes fail the run",
    );
}

#[test]
fn empty_log_always_remains_declared_and_reports_never_evaluated() {
    let properties = properties(vec![assertion(
        "always-empty-scope",
        Property::Always {
            predicate: Predicate::named("unused"),
        },
    )]);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = linted_host_oracle(|_state: ObservedState<'_>, _leaf: ConditionLeaf<'_>| true);

    let report = evaluator.finalize_prefix(&ConditionEventLogPrefix::genesis(), &mut oracle);

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(report.outcomes(), "always-empty-scope").kind,
        HostAssertionOutcomeKind::NeverEvaluated
    );
    assert_eq!(
        outcome(report.outcomes(), "always-empty-scope").lifecycle,
        PropertyLifecycleState::Declared
    );
}
