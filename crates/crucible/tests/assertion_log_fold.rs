//! Checks T-ASRT-8 shared assertion log-fold edge outcomes.

#![forbid(unsafe_code)]

use crucible::{
    AssertionDef, AssertionId, AssertionRunVerdict, BlackBoxHostOracle, FramePredicate,
    HostAssertionEvaluator, HostAssertionOutcome, HostAssertionOutcomeKind,
    OfflineAssertionChecker, Predicate, Properties, Property, ReachabilityExpectation,
    ReachableDisposition, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, VirtualTime,
    World,
};

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn assertion(id: &str, message: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: assertion_id(id),
        message: String::from(message),
        property,
    }
}

fn properties(assertions: Vec<AssertionDef>) -> Properties {
    let world = World::from_nodes(Vec::new()).expect("empty assertion log-fold world should build");
    Properties::from_assertions_for_world(&world, assertions)
        .expect("assertion log-fold properties should validate")
}

fn retained_log() -> Vec<SchedulerEventLogEntry> {
    vec![
        crucible::test_support::condition_boundary_entry_for_test(
            0,
            time(5),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            time(10),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ]
}

fn edge_case_properties() -> Properties {
    properties(vec![
        assertion(
            "always-passed",
            "always predicate evaluates and passes",
            Property::Always {
                predicate: Predicate::not(Predicate::network_match(
                    None,
                    FramePredicate::contains(b"forbidden".to_vec()),
                )),
            },
        ),
        assertion(
            "eventually-never-triggered",
            "eventual trigger never fires",
            Property::Eventually {
                trigger: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"trigger".to_vec()),
                ),
                property: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"done".to_vec()),
                ),
                deadline: time(5),
            },
        ),
        assertion(
            "reachable-warn",
            "optional coverage is absent",
            Property::Reachable {
                predicate: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"optional".to_vec()),
                ),
                expectation: ReachabilityExpectation::Reachable {
                    on_unreached: ReachableDisposition::Warn,
                },
            },
        ),
        assertion(
            "reachable-fail",
            "required coverage is absent",
            Property::Reachable {
                predicate: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"required".to_vec()),
                ),
                expectation: ReachabilityExpectation::Reachable {
                    on_unreached: ReachableDisposition::Fail,
                },
            },
        ),
    ])
}

fn online_report(
    properties: &Properties,
    event_log: &[SchedulerEventLogEntry],
) -> crucible::HostAssertionReport {
    let mut evaluator = HostAssertionEvaluator::new(properties);
    let mut oracle = BlackBoxHostOracle;
    if !event_log.is_empty() {
        for index in 0..event_log.len() - 1 {
            let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(
                event_log[..=index].to_vec(),
            )
            .expect("online intermediate assertion prefix should be checked");
            evaluator.observe_prefix(&prefix, &mut oracle);
        }
    }
    let terminal_prefix = if event_log.is_empty() {
        crucible::ConditionEventLogPrefix::genesis()
    } else {
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(event_log.to_vec())
            .expect("online assertion prefix should be checked")
    };

    evaluator.finalize_prefix(&terminal_prefix, &mut oracle)
}

fn outcome<'a>(outcomes: &'a [HostAssertionOutcome], assertion: &str) -> &'a HostAssertionOutcome {
    outcomes
        .iter()
        .find(|outcome| outcome.assertion.name == assertion)
        .unwrap_or_else(|| panic!("missing outcome for assertion {assertion}"))
}

#[test]
fn online_and_offline_fold_report_distinct_never_outcomes_identically() {
    let properties = edge_case_properties();
    let event_log = retained_log();
    let online = online_report(&properties, &event_log);
    let offline = OfflineAssertionChecker::new()
        .check_run(&properties, &event_log)
        .expect("offline assertion checker should grade retained log");

    assert_eq!(offline, online);
    assert!(matches!(
        offline.verdict(),
        AssertionRunVerdict::Failed { .. }
    ));
    assert_eq!(
        outcome(offline.outcomes(), "always-passed").kind,
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome(offline.outcomes(), "eventually-never-triggered").kind,
        HostAssertionOutcomeKind::NeverTriggered
    );
    assert_eq!(
        outcome(offline.outcomes(), "reachable-warn").kind,
        HostAssertionOutcomeKind::NeverReachedWarn
    );
    assert_eq!(
        outcome(offline.outcomes(), "reachable-fail").kind,
        HostAssertionOutcomeKind::NeverReachedFail
    );
    assert!(
        !offline
            .verdict()
            .failures()
            .iter()
            .any(|failure| failure.assertion.name == "reachable-warn")
    );
    assert!(
        !offline
            .verdict()
            .failures()
            .iter()
            .any(|failure| failure.assertion.name == "eventually-never-triggered")
    );
    assert!(
        offline
            .verdict()
            .failures()
            .iter()
            .any(|failure| failure.assertion.name == "reachable-fail")
    );
}

#[test]
fn online_and_offline_fold_report_never_evaluated_identically() {
    let properties = properties(vec![assertion(
        "always-empty-scope",
        "empty retained log never enters the always scope",
        Property::Always {
            predicate: Predicate::not(Predicate::network_match(
                None,
                FramePredicate::contains(b"forbidden".to_vec()),
            )),
        },
    )]);
    let event_log = Vec::new();
    let online = online_report(&properties, &event_log);
    let offline = OfflineAssertionChecker::new()
        .check_run(&properties, &event_log)
        .expect("offline assertion checker should grade empty retained log");

    assert_eq!(offline, online);
    assert_eq!(offline.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(offline.outcomes(), "always-empty-scope").kind,
        HostAssertionOutcomeKind::NeverEvaluated
    );
}

#[test]
fn assertion_log_fold_implementation_exposes_distinct_never_taxonomy() {
    let trigger = include_str!("../src/trigger.rs");

    for required in [
        "HostAssertionOutcomeKind::NeverEvaluated",
        "HostAssertionOutcomeKind::NeverTriggered",
        "HostAssertionOutcomeKind::NeverReachedWarn",
        "HostAssertionOutcomeKind::NeverReachedFail",
        "host_assertion_outcome_fails_run",
        "HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail",
        "HostAssertionEvaluator::new",
        "observe_prefix",
        "finalize_prefix",
    ] {
        assert!(
            trigger.contains(required),
            "shared assertion log fold must include {required}"
        );
    }
}
