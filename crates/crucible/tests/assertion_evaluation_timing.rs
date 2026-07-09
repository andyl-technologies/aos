//! Checks T-ASRT-10 assertion evaluation timing.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::cell::RefCell;

use crucible::{
    AssertionDef, AssertionId, AssertionRunVerdict, BlackBoxHostOracle, ConditionLeaf,
    FramePredicate, HostAssertionEvaluator, HostAssertionOutcome, HostAssertionOutcomeKind,
    HostAssertionPredicate, LintedHostAssertionOracle, ObservableEvent, ObservedState,
    OfflineAssertionChecker, Predicate, Properties, Property, RecordedAssertionLog,
    SchedulerEvaluationBoundaryKind, VirtualTime, World,
};

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn assertion(id: &str, message: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: String::from(message),
        property,
    }
}

fn properties(assertions: Vec<AssertionDef>) -> Properties {
    let world = World::from_nodes(Vec::new()).expect("empty assertion timing world should build");
    Properties::from_assertions_for_world(&world, assertions)
        .expect("assertion timing properties should validate")
}

fn observable_prefix(
    ticks: u64,
    events: Vec<ObservableEvent>,
) -> crucible::ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_observable_events_for_test(ticks, events)
        .expect("observable timing prefix should be checked")
}

fn outcome<'a>(outcomes: &'a [HostAssertionOutcome], assertion: &str) -> &'a HostAssertionOutcome {
    outcomes
        .iter()
        .find(|outcome| outcome.assertion.name == assertion)
        .unwrap_or_else(|| panic!("missing outcome for assertion {assertion}"))
}

fn linted_host_oracle<O>(oracle: O) -> LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    crucible::test_support::unchecked_host_assertion_oracle_for_test(oracle)
}

#[test]
fn eventually_evaluates_deadline_point_between_recorded_prefixes() {
    let properties = properties(vec![assertion(
        "eventually-deadline-point",
        "deadline point is evaluated even without a log entry",
        Property::Eventually {
            trigger: Predicate::network_match(None, FramePredicate::contains(b"trigger".to_vec())),
            property: Predicate::named("deadline-point"),
            deadline: time(2),
        },
    )]);
    let trigger = ObservableEvent::network_delivered(time(3), None, b"trigger".to_vec());
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let evaluated_at = RefCell::new(Vec::new());
    let mut oracle =
        linted_host_oracle(
            |state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
                ConditionLeaf::Named { name, nodes } => {
                    evaluated_at.borrow_mut().push(state.at().ticks);
                    name == "deadline-point"
                        && nodes.is_empty()
                        && state.at() == time(5)
                        && state.event_log_offset().events == 1
                }
                ConditionLeaf::GuestMarker { .. } => false,
            },
        );

    evaluator.observe_prefix(&observable_prefix(3, vec![trigger.clone()]), &mut oracle);
    let report = evaluator.finalize_prefix(&observable_prefix(10, vec![trigger]), &mut oracle);

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(report.outcomes(), "eventually-deadline-point").kind,
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome(report.outcomes(), "eventually-deadline-point").at,
        time(5)
    );
    assert!(evaluated_at.borrow().contains(&5));
}

#[test]
fn eventually_can_satisfy_at_exact_deadline_event_inside_later_prefix() {
    let properties = properties(vec![assertion(
        "eventually-exact-deadline",
        "ack at the exact deadline is still inside the window",
        Property::Eventually {
            trigger: Predicate::network_match(None, FramePredicate::contains(b"request".to_vec())),
            property: Predicate::network_match(None, FramePredicate::contains(b"ack".to_vec())),
            deadline: time(2),
        },
    )]);
    let request = ObservableEvent::network_delivered(time(3), None, b"request".to_vec());
    let ack = ObservableEvent::network_delivered(time(5), None, b"ack".to_vec());
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = BlackBoxHostOracle;

    evaluator.observe_prefix(&observable_prefix(3, vec![request.clone()]), &mut oracle);
    let report = evaluator.finalize_prefix(&observable_prefix(10, vec![request, ack]), &mut oracle);

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(report.outcomes(), "eventually-exact-deadline").kind,
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome(report.outcomes(), "eventually-exact-deadline").at,
        time(5)
    );
}

#[test]
fn offline_checker_observes_relevant_events_before_later_terminal_boundary() {
    let properties = properties(vec![assertion(
        "sometimes-ack",
        "ack must be observed at its event point",
        Property::Sometimes {
            predicate: Predicate::network_match(None, FramePredicate::contains(b"ack".to_vec())),
        },
    )]);
    let ack = ObservableEvent::network_delivered(time(5), None, b"ack".to_vec());
    let event_log = vec![
        crucible::test_support::condition_observation_entry_for_test(0, &ack),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            time(10),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = BlackBoxHostOracle;
    let ack_prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(
        event_log[..1].to_vec(),
    )
    .expect("ack prefix should be checked");
    evaluator.observe_prefix(&ack_prefix, &mut oracle);
    let terminal_prefix =
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(event_log.clone())
            .expect("terminal prefix should be checked");
    let online = evaluator.finalize_prefix(&terminal_prefix, &mut oracle);
    let offline = OfflineAssertionChecker::new()
        .check_run(&properties, &event_log)
        .expect("offline assertion timing check should grade retained log");

    assert_eq!(offline, online);
    assert_eq!(offline.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(offline.outcomes(), "sometimes-ack").kind,
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(outcome(offline.outcomes(), "sometimes-ack").at, time(5));
}

#[test]
fn synthetic_deadline_prefix_preserves_retained_event_log_offset() {
    let properties = properties(vec![assertion(
        "eventually-deadline-offset",
        "custom oracle sees the retained offset at synthetic deadlines",
        Property::Eventually {
            trigger: Predicate::network_match(None, FramePredicate::contains(b"trigger".to_vec())),
            property: Predicate::named("deadline-offset"),
            deadline: time(2),
        },
    )]);
    let trigger = ObservableEvent::network_delivered(time(3), None, b"trigger".to_vec());
    let event_log = [
        crucible::test_support::condition_observation_entry_for_test(0, &trigger),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            time(10),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    let recorded_log =
        RecordedAssertionLog::from_segments(vec![event_log[..1].to_vec(), event_log[1..].to_vec()])
            .expect("per-prefix recorded assertion log should fold");
    let expected_offset = recorded_log
        .event_log_offset(1)
        .expect("deadline prefix offset should be retained");
    let mut oracle =
        linted_host_oracle(
            |state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
                ConditionLeaf::Named { name, nodes } => {
                    name == "deadline-offset"
                        && nodes.is_empty()
                        && state.at() == time(5)
                        && state.event_log_offset() == expected_offset
                }
                ConditionLeaf::GuestMarker { .. } => false,
            },
        );

    let report = OfflineAssertionChecker::new()
        .check_run_with_oracle(&properties, &recorded_log, &mut oracle)
        .expect("offline synthetic deadline should use retained prefix offset");

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(report.outcomes(), "eventually-deadline-offset").kind,
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome(report.outcomes(), "eventually-deadline-offset").at,
        time(5)
    );
}

#[test]
fn after_quiescence_evaluates_once_at_terminal_prefix() {
    let properties = properties(vec![assertion(
        "after-quiescence-terminal-only",
        "terminal predicate is not evaluated while streaming",
        Property::AfterQuiescence {
            predicate: Predicate::named("terminal-only"),
        },
    )]);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let evaluated_at = RefCell::new(Vec::new());
    let mut oracle =
        linted_host_oracle(
            |state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
                ConditionLeaf::Named { name, nodes } => {
                    evaluated_at.borrow_mut().push(state.at().ticks);
                    name == "terminal-only" && nodes.is_empty() && state.at() == time(10)
                }
                ConditionLeaf::GuestMarker { .. } => false,
            },
        );

    evaluator.observe_prefix(&observable_prefix(3, Vec::new()), &mut oracle);
    evaluator.observe_prefix(&observable_prefix(7, Vec::new()), &mut oracle);
    assert!(evaluated_at.borrow().is_empty());

    let report = evaluator.finalize_prefix(&observable_prefix(10, Vec::new()), &mut oracle);

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(*evaluated_at.borrow(), vec![10]);
    assert_eq!(
        outcome(report.outcomes(), "after-quiescence-terminal-only").kind,
        HostAssertionOutcomeKind::Passed
    );
}
