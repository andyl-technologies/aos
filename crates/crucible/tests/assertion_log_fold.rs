//! Checks T-ASRT-8 shared assertion log-fold edge outcomes.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionPhase, AssertionQuantifierKind, AssertionRunVerdict,
    BlackBoxHostOracle, ConditionLeaf, EventClass, FramePredicate, GuestAssertionDetail,
    GuestAssertionKind, GuestAssertionMarker, HostAssertionEvaluator, HostAssertionOracle,
    HostAssertionOutcome, HostAssertionOutcomeKind, HostAssertionPredicate, Icount, NodeId,
    ObservableEvent, ObservableEventPayload, ObservedState, OfflineAssertionChecker, Predicate,
    Properties, Property, ReachabilityExpectation, ReachableDisposition, RecordedAssertionLog,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, VirtualTime, WhiteBoxPolicy, World,
};

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
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

fn observation_entry(sequence: u64, event: &ObservableEvent) -> SchedulerEventLogEntry {
    crucible::test_support::condition_observation_entry_for_test(sequence, event)
}

fn boundary_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
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
    online_report_with_evaluator(HostAssertionEvaluator::new(properties), event_log)
}

fn online_report_with_evaluator(
    evaluator: HostAssertionEvaluator,
    event_log: &[SchedulerEventLogEntry],
) -> crucible::HostAssertionReport {
    let mut oracle = BlackBoxHostOracle;
    online_report_with_oracle(evaluator, event_log, &mut oracle)
}

fn online_report_with_oracle<O>(
    mut evaluator: HostAssertionEvaluator,
    event_log: &[SchedulerEventLogEntry],
    oracle: &mut O,
) -> crucible::HostAssertionReport
where
    O: HostAssertionOracle + ?Sized,
{
    if !event_log.is_empty() {
        for index in 0..event_log.len() - 1 {
            let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(
                event_log[..=index].to_vec(),
            )
            .expect("online intermediate assertion prefix should be checked");
            evaluator.observe_prefix(&prefix, oracle);
        }
    }
    let terminal_prefix = if event_log.is_empty() {
        crucible::ConditionEventLogPrefix::genesis()
    } else {
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(event_log.to_vec())
            .expect("online assertion prefix should be checked")
    };

    evaluator.finalize_prefix(&terminal_prefix, oracle)
}

fn outcome<'a>(outcomes: &'a [HostAssertionOutcome], assertion: &str) -> &'a HostAssertionOutcome {
    outcomes
        .iter()
        .find(|outcome| outcome.assertion.name == assertion)
        .unwrap_or_else(|| panic!("missing outcome for assertion {assertion}"))
}

#[derive(Clone, Debug)]
struct AssertionEvaluatedOracle;

impl HostAssertionPredicate for AssertionEvaluatedOracle {
    fn leaf_is_true(&self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, nodes } => {
                assert!(nodes.is_empty());
                name == "saw-assertion-evaluated"
                    && observed.observable_events().iter().any(|event| {
                        event.at() == observed.at()
                            && matches!(
                                event.payload(),
                                ObservableEventPayload::AssertionEvaluated {
                                    name,
                                    flavor: AssertionQuantifierKind::Sometimes,
                                    condition: true,
                                    message,
                                    details,
                                } if name.name == "inner-evaluated"
                                    && message == "inner assertion evaluated"
                                    && details.first().is_some_and(|detail| {
                                        detail.key == "case" && detail.value == "event-log-fold"
                                    })
                            )
                    })
            }
            ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

#[test]
fn online_and_offline_fold_read_assertion_evaluated_entries_from_one_event_log() {
    let properties = properties(vec![assertion(
        "host-saw-assertion-evaluation",
        "host assertion observes assertion_evaluated log entry",
        Property::Sometimes {
            predicate: Predicate::named("saw-assertion-evaluated"),
        },
    )]);
    let assertion_evaluated = ObservableEvent::assertion_evaluated(
        time(4),
        assertion_id("inner-evaluated"),
        AssertionQuantifierKind::Sometimes,
        true,
        "inner assertion evaluated",
        vec![GuestAssertionDetail::new("case", "event-log-fold")],
    );
    let event_log = vec![
        observation_entry(0, &assertion_evaluated),
        boundary_entry(1, 6),
    ];
    let recorded_log = RecordedAssertionLog::from_segments(vec![
        vec![event_log[0].clone()],
        vec![event_log[1].clone()],
    ])
    .expect("recorded assertion evaluation log should retain prefix offsets");
    let mut online_oracle =
        crucible::test_support::unchecked_host_assertion_oracle_for_test(AssertionEvaluatedOracle);
    let online = online_report_with_oracle(
        HostAssertionEvaluator::new(&properties),
        &event_log,
        &mut online_oracle,
    );
    let mut offline_oracle =
        crucible::test_support::unchecked_host_assertion_oracle_for_test(AssertionEvaluatedOracle);
    let offline = OfflineAssertionChecker::new()
        .check_run_with_oracle(&properties, &recorded_log, &mut offline_oracle)
        .expect("offline assertion checker should grade retained assertion_evaluated log");

    assert_eq!(event_log[0].event_payload().kind(), "assertion_evaluated");
    assert_eq!(
        event_log[0].event_payload().string("id"),
        Some("inner-evaluated")
    );
    assert_eq!(
        event_log[0].event_payload().string("flavor"),
        Some("Sometimes")
    );
    assert_eq!(event_log[0].event_payload().bool("condition"), Some(true));
    assert_eq!(event_log[0].event_payload().u64("details_len"), Some(1));
    assert_eq!(event_log[0].class(), EventClass::Causal);
    assert_eq!(offline, online);
    assert_eq!(offline.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(offline.outcomes(), "host-saw-assertion-evaluation").kind,
        HostAssertionOutcomeKind::Satisfied
    );
}

#[test]
fn online_and_offline_fold_read_assertion_state_changes_from_one_event_log() {
    let properties = properties(vec![
        assertion(
            "inner-assertion",
            "inner assertion is declared so state leaves validate",
            Property::Always {
                predicate: Predicate::not(Predicate::network_match(
                    None,
                    FramePredicate::contains(b"forbidden".to_vec()),
                )),
            },
        ),
        assertion(
            "outer-saw-inner-satisfied",
            "outer assertion observes inner assertion state",
            Property::Sometimes {
                predicate: Predicate::assertion_state(
                    assertion_id("inner-assertion"),
                    AssertionPhase::Satisfied,
                ),
            },
        ),
    ]);
    let state_changed = ObservableEvent::assertion_state_changed(
        time(6),
        assertion_id("inner-assertion"),
        AssertionPhase::Satisfied,
    );
    let event_log = vec![observation_entry(0, &state_changed), boundary_entry(1, 8)];

    assert_eq!(
        event_log[0].event_payload().kind(),
        "assertion_state_changed"
    );
    assert_eq!(
        event_log[0].event_payload().string("id"),
        Some("inner-assertion")
    );
    assert_eq!(
        event_log[0].event_payload().string("new_state"),
        Some("Satisfied")
    );
    assert_eq!(event_log[0].class(), EventClass::Causal);
    let online = online_report(&properties, &event_log);
    let offline = OfflineAssertionChecker::new()
        .check_run(&properties, &event_log)
        .expect("offline assertion checker should grade retained assertion state log");

    assert_eq!(offline, online);
    assert_eq!(offline.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(offline.outcomes(), "outer-saw-inner-satisfied").kind,
        HostAssertionOutcomeKind::Satisfied
    );
}

#[test]
fn online_and_offline_fold_read_white_box_markers_from_one_event_log() {
    let properties = properties(Vec::new());
    let marker = GuestAssertionMarker::new(
        assertion_id("guest-sometimes"),
        "guest sometimes marker",
        GuestAssertionKind::Sometimes,
        true,
        false,
        vec![GuestAssertionDetail::new("case", "event-log-fold")],
        "guest.rs:11",
    );
    let marker_event = ObservableEvent::guest_assertion_marker(icount(7), node("guest"), marker);
    let event_log = vec![observation_entry(0, &marker_event), boundary_entry(1, 9)];
    let policies = [(node("guest"), WhiteBoxPolicy::Enabled)];
    let online = online_report_with_evaluator(
        HostAssertionEvaluator::new(&properties).with_white_box_policies(policies.clone()),
        &event_log,
    );
    let offline = OfflineAssertionChecker::new()
        .with_white_box_policies(policies)
        .check_run(&properties, &event_log)
        .expect("offline assertion checker should grade retained guest marker log");

    assert_eq!(event_log[0].event_payload().kind(), "guest_marker");
    assert_eq!(
        event_log[0].event_payload().string("marker_kind"),
        Some("assert")
    );
    assert_eq!(event_log[0].class(), EventClass::Observational);
    assert_eq!(offline, online);
    assert_eq!(offline.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(offline.outcomes(), "guest-sometimes").kind,
        HostAssertionOutcomeKind::Satisfied
    );
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
        HostAssertionOutcomeKind::Passed
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
    let trigger = concat!(
        include_str!("../src/trigger/assertions.rs"),
        include_str!("../src/trigger/conditions.rs"),
        include_str!("../src/trigger/evaluation.rs"),
        include_str!("../src/trigger/event_graph.rs"),
        include_str!("../src/trigger/evidence.rs"),
        include_str!("../src/trigger/observability.rs"),
    );

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
        "ObservableEventPayload::AssertionStateChanged",
        "ObservableEventPayload::GuestAssertionMarker",
        "condition_prefix_from_recorded_log",
    ] {
        assert!(
            trigger.contains(required),
            "shared assertion log fold must include {required}"
        );
    }
}
