//! Checks T-ASRT-11 deterministic assertion evaluation order.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionRunVerdict, ConditionLeaf, HostAssertionEvaluator,
    HostAssertionOutcomeKind, HostAssertionPredicate, LintedHostAssertionOracle, ObservedState,
    OfflineAssertionChecker, Predicate, Properties, Property, RecordedAssertionLog,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, VirtualTime, World,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvaluationCall {
    at: u64,
    events: u64,
    name: String,
}

#[derive(Debug, Default)]
struct RecordingOracle {
    calls: std::cell::RefCell<Vec<EvaluationCall>>,
}

impl HostAssertionPredicate for RecordingOracle {
    fn leaf_is_true(&self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, nodes } => {
                assert!(nodes.is_empty());
                self.calls.borrow_mut().push(EvaluationCall {
                    at: observed.at().ticks,
                    events: observed.event_log_offset().events,
                    name: name.to_owned(),
                });
                true
            }
            ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

fn linted_host_oracle<O>(oracle: O) -> LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    crucible::test_support::unchecked_host_assertion_oracle_for_test(oracle)
}

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
    let world = World::from_nodes(Vec::new()).expect("empty assertion order world should build");
    Properties::from_assertions_for_world(&world, assertions)
        .expect("assertion order properties should validate")
}

fn ordered_properties() -> Properties {
    properties(vec![
        assertion(
            "z-last",
            Property::Always {
                predicate: Predicate::named("a-last-leaf"),
            },
        ),
        assertion(
            "a-first",
            Property::Always {
                predicate: Predicate::named("z-first-leaf"),
            },
        ),
        assertion(
            "m-middle",
            Property::Always {
                predicate: Predicate::named("m-middle-leaf"),
            },
        ),
    ])
}

fn boundary_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn prefix(entries: Vec<SchedulerEventLogEntry>) -> crucible::ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_scheduler_entries_for_test(entries)
        .expect("assertion order prefix should be checked")
}

fn expected_calls_at(at: u64, events: u64) -> Vec<EvaluationCall> {
    vec![
        EvaluationCall {
            at,
            events,
            name: String::from("z-first-leaf"),
        },
        EvaluationCall {
            at,
            events,
            name: String::from("m-middle-leaf"),
        },
        EvaluationCall {
            at,
            events,
            name: String::from("a-last-leaf"),
        },
    ]
}

#[test]
fn properties_are_evaluated_by_stable_id_and_each_named_predicate_once_per_point() {
    let properties = ordered_properties();
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = linted_host_oracle(RecordingOracle::default());

    let outcomes = evaluator.observe_prefix(&prefix(vec![boundary_entry(0, 1)]), &mut oracle);

    assert!(outcomes.is_empty());
    assert_eq!(&*oracle.oracle().calls.borrow(), &expected_calls_at(1, 1));
}

#[test]
fn duplicate_named_leaves_inside_one_predicate_are_evaluated_once_per_point() {
    let properties = properties(vec![assertion(
        "single-leaf-evaluation",
        Property::Always {
            predicate: Predicate::all_of(vec![
                Predicate::named("shared-leaf"),
                Predicate::named("shared-leaf"),
            ]),
        },
    )]);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = linted_host_oracle(RecordingOracle::default());

    let outcomes = evaluator.observe_prefix(&prefix(vec![boundary_entry(0, 1)]), &mut oracle);

    assert!(outcomes.is_empty());
    assert_eq!(
        &*oracle.oracle().calls.borrow(),
        &vec![EvaluationCall {
            at: 1,
            events: 1,
            name: String::from("shared-leaf"),
        }]
    );
}

#[test]
fn eventually_trigger_and_property_share_one_named_leaf_evaluation_per_point() {
    let properties = properties(vec![assertion(
        "eventually-single-leaf-evaluation",
        Property::Eventually {
            trigger: Predicate::named("shared-eventually-leaf"),
            property: Predicate::named("shared-eventually-leaf"),
            deadline: time(4),
        },
    )]);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = linted_host_oracle(RecordingOracle::default());

    let outcomes = evaluator.observe_prefix(&prefix(vec![boundary_entry(0, 1)]), &mut oracle);

    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0].kind,
        HostAssertionOutcomeKind::Satisfied,
        "a discharged Eventually obligation emits at its evaluation point"
    );
    assert_eq!(
        &*oracle.oracle().calls.borrow(),
        &vec![EvaluationCall {
            at: 1,
            events: 1,
            name: String::from("shared-eventually-leaf"),
        }]
    );
}

#[test]
fn online_and_offline_custom_oracles_observe_identical_order() {
    let properties = ordered_properties();
    let event_log = vec![boundary_entry(0, 1), boundary_entry(1, 2)];
    let recorded_log =
        RecordedAssertionLog::from_segments(vec![event_log[..1].to_vec(), event_log[1..].to_vec()])
            .expect("recorded assertion order log should fold");
    let mut online_oracle = linted_host_oracle(RecordingOracle::default());
    let mut online_evaluator = HostAssertionEvaluator::new(&properties);

    online_evaluator.observe_prefix(&prefix(event_log[..1].to_vec()), &mut online_oracle);
    let online_report =
        online_evaluator.finalize_prefix(&prefix(event_log.clone()), &mut online_oracle);

    let mut offline_oracle = linted_host_oracle(RecordingOracle::default());
    let offline_report = OfflineAssertionChecker::new()
        .check_run_with_oracle(&properties, &recorded_log, &mut offline_oracle)
        .expect("offline assertion order check should grade retained log");
    let mut expected_calls = expected_calls_at(1, 1);
    expected_calls.extend(expected_calls_at(2, 2));

    assert_eq!(online_report, offline_report);
    assert_eq!(online_report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(&*online_oracle.oracle().calls.borrow(), &expected_calls);
    assert_eq!(
        &*offline_oracle.oracle().calls.borrow(),
        &*online_oracle.oracle().calls.borrow()
    );
}
