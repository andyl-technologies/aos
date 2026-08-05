//! Checks T-ASRT-5 host-side assertion evaluation over observable state.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionRunVerdict, BlackBoxHostOracle, CodePoint, ConditionLeaf,
    Decision, DeliveryOrderDecision, EventKey, FramePredicate, HostAssertionEvaluator,
    HostAssertionOutcome, HostAssertionOutcomeKind, HostAssertionPredicate, Icount,
    LintedHostAssertionOracle, NodeId, NodeLifecycle, NodeTemplate, ObservableEvent, ObservedState,
    Predicate, Properties, Property, ReachabilityExpectation, ReachableDisposition, ReadyPoint,
    RegexProgram, SchedulerEvaluationBoundaryKind, SchedulerEventLogPayload, SchedulerNodeId,
    SchedulingNodeKind, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind: SchedulingNodeKind::Vm,
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn assertion(id: &str, message: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: String::from(message),
        property,
    }
}

fn ready_node(name: &str) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount { icount: icount(1) },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn observable_world() -> World {
    World::from_nodes(vec![ready_node("db-0"), ready_node("client")])
        .expect("observable assertion world should build")
}

fn empty_world() -> World {
    World::from_nodes(Vec::new()).expect("empty world should build")
}

fn properties(assertions: Vec<AssertionDef>) -> Properties {
    Properties::from_assertions_for_world(&observable_world(), assertions)
        .expect("host-side assertion properties should validate")
}

fn named_properties(assertions: Vec<AssertionDef>) -> Properties {
    Properties::from_assertions_for_world(&empty_world(), assertions)
        .expect("named host-side assertion properties should validate")
}

fn observable_prefix(
    ticks: u64,
    events: Vec<ObservableEvent>,
) -> crucible::ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_observable_events_for_test(ticks, events)
        .expect("observable test prefix should be checked")
}

fn payload_prefix(
    ticks: u64,
    payload: SchedulerEventLogPayload,
) -> crucible::ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
        crucible::test_support::condition_payload_entry_for_test(0, time(ticks), payload),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            time(ticks),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ])
    .expect("payload test prefix should be checked")
}

fn outcome<'a>(outcomes: &'a [HostAssertionOutcome], assertion: &str) -> &'a HostAssertionOutcome {
    outcomes
        .iter()
        .find(|outcome| outcome.assertion.name == assertion)
        .unwrap_or_else(|| panic!("missing outcome for assertion {assertion}"))
}

fn assert_outcome(
    outcomes: &[HostAssertionOutcome],
    assertion: &str,
    kind: HostAssertionOutcomeKind,
) {
    assert_eq!(outcome(outcomes, assertion).kind, kind);
}

fn linted_host_oracle<O>(oracle: O) -> LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    crucible::test_support::unchecked_host_assertion_oracle_for_test(oracle)
}

#[test]
fn host_side_assertions_grade_all_five_quantifiers_in_black_box_mode() {
    let properties = properties(vec![
        assertion(
            "always-no-forbidden-frame",
            "forbidden frames stay absent",
            Property::Always {
                predicate: Predicate::not(Predicate::network_match(
                    None,
                    FramePredicate::contains(b"forbidden".to_vec()),
                )),
            },
        ),
        assertion(
            "sometimes-ack",
            "ack frame is eventually observed",
            Property::Sometimes {
                predicate: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"ack".to_vec()),
                ),
            },
        ),
        assertion(
            "eventually-request-acks",
            "request receives an ack",
            Property::Eventually {
                trigger: Predicate::console_match(
                    node("db-0"),
                    RegexProgram::from_pattern("request started"),
                ),
                property: Predicate::network_match(None, FramePredicate::contains(b"ack".to_vec())),
                deadline: time(5),
            },
        ),
        assertion(
            "after-quiescence-exited",
            "db exits at terminal quiescence",
            Property::AfterQuiescence {
                predicate: Predicate::node_state(node("db-0"), NodeLifecycle::Exited),
            },
        ),
        assertion(
            "reachable-coverage",
            "coverage point is reached",
            Property::Reachable {
                predicate: Predicate::coverage_point(
                    node("db-0"),
                    CodePoint::guest_address(0x4010),
                ),
                expectation: ReachabilityExpectation::Reachable {
                    on_unreached: ReachableDisposition::Warn,
                },
            },
        ),
    ]);
    let request =
        ObservableEvent::console_output(time(10), node("db-0"), b"request started\n".to_vec());
    let ack = ObservableEvent::network_delivered(time(12), None, b"raft ack".to_vec());
    let coverage = ObservableEvent::coverage_block(icount(15), node("db-0"), 0x4000, 0x20);
    let exited = ObservableEvent::node_state(time(20), node("db-0"), NodeLifecycle::Exited);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = BlackBoxHostOracle;

    evaluator.observe_prefix(&observable_prefix(1, Vec::new()), &mut oracle);
    evaluator.observe_prefix(&observable_prefix(10, vec![request.clone()]), &mut oracle);
    let satisfied = evaluator.observe_prefix(
        &observable_prefix(12, vec![request.clone(), ack.clone()]),
        &mut oracle,
    );
    assert_outcome(
        &satisfied,
        "sometimes-ack",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert_outcome(
        &satisfied,
        "eventually-request-acks",
        HostAssertionOutcomeKind::Satisfied,
    );
    evaluator.observe_prefix(
        &observable_prefix(15, vec![request.clone(), ack.clone(), coverage.clone()]),
        &mut oracle,
    );
    let report = evaluator.finalize_prefix(
        &observable_prefix(20, vec![request, ack, coverage, exited]),
        &mut oracle,
    );

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(report.outcomes().len(), 5);
    assert_outcome(
        report.outcomes(),
        "always-no-forbidden-frame",
        HostAssertionOutcomeKind::Passed,
    );
    assert_outcome(
        report.outcomes(),
        "sometimes-ack",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert_outcome(
        report.outcomes(),
        "eventually-request-acks",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert_outcome(
        report.outcomes(),
        "after-quiescence-exited",
        HostAssertionOutcomeKind::Passed,
    );
    assert_outcome(
        report.outcomes(),
        "reachable-coverage",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert_eq!(
        outcome(report.outcomes(), "eventually-request-acks").at,
        time(12)
    );
}

#[test]
fn host_side_assertions_preserve_once_latches_across_prefixes() {
    let properties = properties(vec![assertion(
        "sometimes-exit-after-ack",
        "exit happens after the ack was seen",
        Property::Sometimes {
            predicate: Predicate::all_of(vec![
                Predicate::node_state(node("db-0"), NodeLifecycle::Exited),
                Predicate::once(Predicate::network_match(
                    None,
                    FramePredicate::contains(b"ack".to_vec()),
                )),
            ]),
        },
    )]);
    let ack = ObservableEvent::network_delivered(time(12), None, b"raft ack".to_vec());
    let exited = ObservableEvent::node_state(time(20), node("db-0"), NodeLifecycle::Exited);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = BlackBoxHostOracle;

    evaluator.observe_prefix(&observable_prefix(12, vec![ack.clone()]), &mut oracle);
    let report = evaluator.finalize_prefix(&observable_prefix(20, vec![ack, exited]), &mut oracle);

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_outcome(
        report.outcomes(),
        "sometimes-exit-after-ack",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert_eq!(
        outcome(report.outcomes(), "sometimes-exit-after-ack").at,
        time(20)
    );
}

#[test]
fn host_side_assertions_report_failures_and_warnings_without_guest_cooperation() {
    let properties = properties(vec![
        assertion(
            "always-no-forbidden-frame",
            "forbidden frames stay absent",
            Property::Always {
                predicate: Predicate::not(Predicate::network_match(
                    None,
                    FramePredicate::contains(b"forbidden".to_vec()),
                )),
            },
        ),
        assertion(
            "sometimes-ack",
            "ack frame is eventually observed",
            Property::Sometimes {
                predicate: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"ack".to_vec()),
                ),
            },
        ),
        assertion(
            "eventually-request-acks",
            "request receives an ack",
            Property::Eventually {
                trigger: Predicate::console_match(
                    node("db-0"),
                    RegexProgram::from_pattern("request started"),
                ),
                property: Predicate::network_match(None, FramePredicate::contains(b"ack".to_vec())),
                deadline: time(2),
            },
        ),
        assertion(
            "after-quiescence-exited",
            "db exits at terminal quiescence",
            Property::AfterQuiescence {
                predicate: Predicate::node_state(node("db-0"), NodeLifecycle::Exited),
            },
        ),
        assertion(
            "eventually-never-triggered",
            "never-triggered eventual is reported without failing",
            Property::Eventually {
                trigger: Predicate::console_match(
                    node("db-0"),
                    RegexProgram::from_pattern("never happens"),
                ),
                property: Predicate::network_match(None, FramePredicate::contains(b"ack".to_vec())),
                deadline: time(2),
            },
        ),
        assertion(
            "reachable-warn",
            "warn if optional coverage is never reached",
            Property::Reachable {
                predicate: Predicate::coverage_point(
                    node("db-0"),
                    CodePoint::guest_address(0x4010),
                ),
                expectation: ReachabilityExpectation::Reachable {
                    on_unreached: ReachableDisposition::Warn,
                },
            },
        ),
        assertion(
            "reachable-fail",
            "fail if required coverage is never reached",
            Property::Reachable {
                predicate: Predicate::coverage_point(
                    node("db-0"),
                    CodePoint::guest_address(0x4020),
                ),
                expectation: ReachabilityExpectation::Reachable {
                    on_unreached: ReachableDisposition::Fail,
                },
            },
        ),
        assertion(
            "unreachable-forbidden",
            "forbidden coverage stays unreachable",
            Property::Reachable {
                predicate: Predicate::coverage_point(
                    node("db-0"),
                    CodePoint::guest_address(0x5000),
                ),
                expectation: ReachabilityExpectation::Unreachable,
            },
        ),
    ]);
    let forbidden = ObservableEvent::network_delivered(time(2), None, b"forbidden frame".to_vec());
    let request =
        ObservableEvent::console_output(time(3), node("db-0"), b"request started\n".to_vec());
    let forbidden_coverage = ObservableEvent::coverage_block(icount(4), node("db-0"), 0x5000, 0x20);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = BlackBoxHostOracle;

    evaluator.observe_prefix(&observable_prefix(2, vec![forbidden.clone()]), &mut oracle);
    evaluator.observe_prefix(
        &observable_prefix(3, vec![forbidden.clone(), request.clone()]),
        &mut oracle,
    );
    evaluator.observe_prefix(
        &observable_prefix(
            4,
            vec![
                forbidden.clone(),
                request.clone(),
                forbidden_coverage.clone(),
            ],
        ),
        &mut oracle,
    );
    let report = evaluator.finalize_prefix(
        &observable_prefix(10, vec![forbidden, request, forbidden_coverage]),
        &mut oracle,
    );

    assert!(report.verdict().is_failed());
    assert_eq!(report.verdict().failures().len(), 6);
    assert_outcome(
        report.outcomes(),
        "always-no-forbidden-frame",
        HostAssertionOutcomeKind::Violated,
    );
    assert_outcome(
        report.outcomes(),
        "sometimes-ack",
        HostAssertionOutcomeKind::Violated,
    );
    assert_outcome(
        report.outcomes(),
        "eventually-request-acks",
        HostAssertionOutcomeKind::Violated,
    );
    assert_outcome(
        report.outcomes(),
        "after-quiescence-exited",
        HostAssertionOutcomeKind::Violated,
    );
    assert_outcome(
        report.outcomes(),
        "eventually-never-triggered",
        HostAssertionOutcomeKind::NeverTriggered,
    );
    assert_outcome(
        report.outcomes(),
        "reachable-warn",
        HostAssertionOutcomeKind::NeverReachedWarn,
    );
    assert_outcome(
        report.outcomes(),
        "reachable-fail",
        HostAssertionOutcomeKind::NeverReachedFail,
    );
    assert_outcome(
        report.outcomes(),
        "unreachable-forbidden",
        HostAssertionOutcomeKind::Violated,
    );
    assert_eq!(
        outcome(report.outcomes(), "eventually-request-acks").at,
        time(5)
    );
    assert!(
        !report
            .verdict()
            .failures()
            .iter()
            .any(|failure| failure.assertion.name == "reachable-warn")
    );
    assert!(
        !report
            .verdict()
            .failures()
            .iter()
            .any(|failure| failure.assertion.name == "eventually-never-triggered")
    );
}

#[test]
fn host_named_predicates_receive_read_only_observed_state() {
    let properties = named_properties(vec![assertion(
        "named-ordering",
        "ordering fact is visible to host predicate",
        Property::Sometimes {
            predicate: Predicate::named("saw-ordering"),
        },
    )]);
    let order = EventKey::new(time(7), scheduler_node("db-0"), scheduler_node("client"), 0);
    let prefix = payload_prefix(
        7,
        SchedulerEventLogPayload::Decision(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: time(7),
            order: vec![order],
        })),
    );
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle =
        linted_host_oracle(
            |state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
                ConditionLeaf::Named { name, nodes } => {
                    name == "saw-ordering" && nodes.is_empty() && !state.ordering_facts().is_empty()
                }
                ConditionLeaf::GuestMarker { .. } => false,
            },
        );

    let outcomes = evaluator.observe_prefix(&prefix, &mut oracle);

    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].assertion.name, "named-ordering");
    assert_eq!(outcomes[0].kind, HostAssertionOutcomeKind::Satisfied);
}

#[test]
fn host_assertion_evaluator_avoids_host_time_rng_and_unordered_maps() {
    let trigger = concat!(
        include_str!("../src/trigger/assertions.rs"),
        include_str!("../src/trigger/evaluation.rs"),
    );
    let evaluator_block = trigger
        .split("pub struct HostAssertionEvaluator")
        .nth(1)
        .expect("host assertion evaluator block should exist")
        .split("pub(crate) fn evaluate_condition")
        .next()
        .expect("shared condition evaluator should follow host assertion evaluator");

    for forbidden in [
        "HashMap",
        "HashSet",
        "SystemTime",
        "Instant",
        "std::time",
        "thread_rng",
        "rand::",
    ] {
        assert!(
            !evaluator_block.contains(forbidden),
            "host assertion evaluator must not use {forbidden}"
        );
    }
}
