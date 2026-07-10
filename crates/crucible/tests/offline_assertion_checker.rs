//! Checks T-ASRT-7 offline assertion re-grading over retained event logs.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionRunVerdict, BlackBoxHostOracle, ConditionEvaluationError,
    ConditionLeaf, ContentHash, FramePredicate, HostAssertionEvaluator, HostAssertionOutcome,
    HostAssertionOutcomeKind, HostAssertionPredicate, HostAssertionReport, Icount,
    LintedHostAssertionOracle, MarkerId, NodeId, NodeTemplate, ObservableEvent, ObservedState,
    OfflineAssertionCheckError, OfflineAssertionChecker, Predicate, Properties, Property,
    ReachabilityExpectation, ReachableDisposition, ReadyPoint, RecordedAssertionLog,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode,
};

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn marker_id(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn ready_node(name: &str, white_box: WhiteBoxPolicy) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount { icount: icount(1) },
        white_box,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn world() -> World {
    World::from_nodes(vec![ready_node("guest", WhiteBoxPolicy::Enabled)])
        .expect("offline assertion checker world should build")
}

fn assertion(id: &str, message: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: assertion_id(id),
        message: String::from(message),
        property,
    }
}

fn properties(world: &World, assertions: Vec<AssertionDef>) -> Properties {
    Properties::from_assertions_for_world(world, assertions)
        .expect("offline assertion checker properties should validate")
}

fn recorded_log() -> Vec<SchedulerEventLogEntry> {
    let ack = ObservableEvent::network_delivered(time(3), None, b"ack".to_vec());
    let coverage = ObservableEvent::guest_marker(icount(5), node("guest"), marker_id("coverage"));

    vec![
        crucible::test_support::condition_observation_entry_for_test(0, &ack),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            time(3),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
        crucible::test_support::condition_observation_entry_for_test(2, &coverage),
        crucible::test_support::condition_boundary_entry_for_test(
            3,
            time(5),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ]
}

fn recorded_assertion_log() -> RecordedAssertionLog {
    let entries = recorded_log();
    RecordedAssertionLog::from_segments(vec![entries[..2].to_vec(), entries[2..].to_vec()])
        .expect("recorded assertion log segments should fold")
}

fn all_quantifier_properties(world: &World) -> Properties {
    properties(
        world,
        vec![
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
                "ack frame is observed",
                Property::Sometimes {
                    predicate: Predicate::network_match(
                        None,
                        FramePredicate::contains(b"ack".to_vec()),
                    ),
                },
            ),
            assertion(
                "eventually-coverage-after-ack",
                "coverage follows ack",
                Property::Eventually {
                    trigger: Predicate::network_match(
                        None,
                        FramePredicate::contains(b"ack".to_vec()),
                    ),
                    property: Predicate::guest_marker(marker_id("coverage")),
                    deadline: time(4),
                },
            ),
            assertion(
                "after-quiescence-coverage",
                "coverage marker is present at the end",
                Property::AfterQuiescence {
                    predicate: Predicate::guest_marker(marker_id("coverage")),
                },
            ),
            assertion(
                "reachable-coverage",
                "coverage marker is reached",
                Property::Reachable {
                    predicate: Predicate::guest_marker(marker_id("coverage")),
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Warn,
                    },
                },
            ),
        ],
    )
}

fn amended_properties(world: &World) -> Properties {
    properties(
        world,
        vec![
            assertion(
                "sometimes-ack-amended",
                "ack frame is observed by an amended property",
                Property::Sometimes {
                    predicate: Predicate::network_match(
                        None,
                        FramePredicate::contains(b"ack".to_vec()),
                    ),
                },
            ),
            assertion(
                "unreachable-forbidden-marker",
                "forbidden marker stays absent",
                Property::Reachable {
                    predicate: Predicate::guest_marker(marker_id("forbidden")),
                    expectation: ReachabilityExpectation::Unreachable,
                },
            ),
        ],
    )
}

fn online_report(
    world: &World,
    properties: &Properties,
    event_log: &[SchedulerEventLogEntry],
) -> HostAssertionReport {
    let mut evaluator =
        HostAssertionEvaluator::new(properties).with_world_white_box_policies(world);
    let mut oracle = BlackBoxHostOracle;
    let first_boundary = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(
        event_log[..2].to_vec(),
    )
    .expect("first online prefix should be checked");
    let terminal = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(
        event_log.to_vec(),
    )
    .expect("terminal online prefix should be checked");

    evaluator.observe_prefix(&first_boundary, &mut oracle);
    evaluator.finalize_prefix(&terminal, &mut oracle)
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
fn offline_assertion_checker_matches_online_report_for_recorded_log() {
    let world = world();
    let properties = all_quantifier_properties(&world);
    let event_log = recorded_log();
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);

    let offline = checker
        .check_run(&properties, &event_log)
        .expect("offline assertion checker should grade retained log");
    let online = online_report(&world, &properties, &event_log);

    assert_eq!(offline, online);
    assert_eq!(offline.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(offline.outcomes().len(), 5);
}

#[test]
fn offline_assertion_checker_regrades_amended_properties_idempotently() {
    let world = world();
    let properties = amended_properties(&world);
    let event_log = recorded_log();
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);

    let first = checker
        .check_run(&properties, &event_log)
        .expect("first offline re-grade should succeed");
    let second = checker
        .check_run(&properties, &event_log)
        .expect("second offline re-grade should succeed");

    assert_eq!(first, second);
    assert_eq!(first.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(first.outcomes(), "sometimes-ack-amended").kind,
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome(first.outcomes(), "unreachable-forbidden-marker").kind,
        HostAssertionOutcomeKind::Passed
    );
}

#[test]
fn offline_assertion_checker_uses_custom_host_oracle_over_recorded_state() {
    let world = world();
    let properties = properties(
        &world,
        vec![assertion(
            "named-offline-ack",
            "offline named predicate sees the retained log",
            Property::Sometimes {
                predicate: Predicate::named("saw-ack-observation"),
            },
        )],
    );
    let recorded_log = recorded_assertion_log();
    let expected_offset = recorded_log
        .event_log_offset(2)
        .expect("first recorded segment offset should exist");
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let mut oracle =
        linted_host_oracle(
            |state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
                ConditionLeaf::Named { name, nodes } => {
                    name == "saw-ack-observation"
                        && nodes.is_empty()
                        && state.event_log_offset() == expected_offset
                        && state
                            .observable_events()
                            .iter()
                            .any(|event| event.at() == time(3))
                }
                ConditionLeaf::GuestMarker { .. } => false,
            },
        );

    let report = checker
        .check_run_with_oracle(&properties, &recorded_log, &mut oracle)
        .expect("offline custom oracle should grade retained observations");

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(report.outcomes(), "named-offline-ack").kind,
        HostAssertionOutcomeKind::Satisfied
    );
}

#[test]
fn offline_assertion_checker_requires_offsets_for_custom_host_oracle() {
    let world = world();
    let properties = properties(
        &world,
        vec![assertion(
            "named-offset-required",
            "custom oracle requires exact recorded offsets",
            Property::Sometimes {
                predicate: Predicate::named("always-true"),
            },
        )],
    );
    let recorded_log = RecordedAssertionLog::from_entries(recorded_log());
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let mut oracle =
        linted_host_oracle(
            |_state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
                ConditionLeaf::Named { name, .. } => name == "always-true",
                ConditionLeaf::GuestMarker { .. } => false,
            },
        );

    let error = checker
        .check_run_with_oracle(&properties, &recorded_log, &mut oracle)
        .expect_err("custom-oracle offline checks must require exact offsets");

    assert!(matches!(
        error,
        OfflineAssertionCheckError::MissingEventLogOffset { prefix_len: 4 }
    ));
}

#[test]
fn offline_assertion_checker_preserves_empty_run_offset_for_custom_oracle() {
    let world = world();
    let properties = properties(
        &world,
        vec![assertion(
            "named-genesis-offset",
            "custom oracle sees the recorded genesis offset",
            Property::AfterQuiescence {
                predicate: Predicate::named("genesis-offset"),
            },
        )],
    );
    let recorded_log =
        RecordedAssertionLog::from_segments(Vec::<Vec<SchedulerEventLogEntry>>::new())
            .expect("empty recorded assertion log should fold");
    let expected_offset = recorded_log
        .event_log_offset(0)
        .expect("genesis offset should be retained");
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let mut oracle =
        linted_host_oracle(
            |state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
                ConditionLeaf::Named { name, nodes } => {
                    name == "genesis-offset"
                        && nodes.is_empty()
                        && state.event_log_offset() == expected_offset
                        && expected_offset.prefix != ContentHash::default()
                }
                ConditionLeaf::GuestMarker { .. } => false,
            },
        );

    let report = checker
        .check_run_with_oracle(&properties, &recorded_log, &mut oracle)
        .expect("empty offline custom-oracle check should use retained genesis offset");

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        outcome(report.outcomes(), "named-genesis-offset").kind,
        HostAssertionOutcomeKind::Passed
    );
}

#[test]
fn offline_assertion_checker_rejects_invalid_recorded_log() {
    let world = world();
    let properties = all_quantifier_properties(&world);
    let mut event_log = recorded_log();
    event_log[1] = crucible::test_support::condition_entry_with_content_hash_for_test(
        event_log[1].clone(),
        ContentHash::from_bytes(b"not the recorded boundary"),
    );

    let error = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run(&properties, &event_log)
        .expect_err("corrupt recorded log should be rejected");

    assert!(matches!(
        error,
        OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::InvalidEventLogEntryHash { sequence: 1 }
        )
    ));
}

#[test]
fn offline_assertion_checker_implementation_reads_log_without_guest_reexecution() {
    let trigger = include_str!("../src/trigger/assertions.rs");
    let checker_block = trigger
        .split("pub struct OfflineAssertionChecker")
        .nth(1)
        .expect("offline assertion checker should exist")
        .split("pub struct HostAssertionEvaluator")
        .next()
        .expect("host assertion evaluator follows offline checker");

    for required in [
        "pub fn check_run",
        "pub fn check_run_with_oracle",
        "SchedulerEventLogEntry",
        "ConditionEventLogPrefix",
        "HostAssertionEvaluator::new",
        "finalize_prefix",
        "for index in 0..event_log.len()",
    ] {
        assert!(
            checker_block.contains(required),
            "offline assertion checker must include {required}"
        );
    }
    for forbidden in [
        "SingleScheduler::new",
        "SimBackend",
        "drive_authoritative_quantum",
        "drive_concurrent_authoritative_quantum",
        "append_observable_events",
        "append_evaluation_boundary",
        "thread_rng",
        "SystemTime",
        "Instant",
    ] {
        assert!(
            !checker_block.contains(forbidden),
            "offline assertion checker must not re-execute or add nondeterminism: {forbidden}"
        );
    }
}
