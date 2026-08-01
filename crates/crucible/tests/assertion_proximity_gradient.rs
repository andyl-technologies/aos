//! Checks T-ASRT-18 assertion proximity gradient reporting.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionRunVerdict, BlackBoxHostOracle, ConditionEventLogPrefix,
    FramePredicate, HostAssertionEvaluator, HostAssertionOutcomeKind, HostAssertionProximity,
    Icount, MemPlace, MemoryCmp, MemoryWidth, NodeId, NodeTemplate, ObservableEvent,
    OfflineAssertionChecker, Predicate, Properties, Property, ReachabilityExpectation,
    ReachableDisposition, ReadyPoint, ResolvedMemPlace, SchedulerEventLogEntry, VirtualTime,
    VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
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

fn world() -> World {
    World::from_nodes(vec![ready_node("guest")]).expect("assertion proximity world should build")
}

fn assertion(id: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: assertion_id(id),
        message: format!("{id} proximity"),
        property,
    }
}

fn properties(assertions: Vec<AssertionDef>) -> Properties {
    Properties::from_assertions_for_world(&world(), assertions)
        .expect("assertion proximity properties should validate")
}

fn memory_predicate(cmp: MemoryCmp, value: u64) -> Predicate {
    Predicate::memory_predicate(
        node("guest"),
        MemPlace::register("rax", MemoryWidth::U64),
        cmp,
        value,
    )
}

fn memory_sample(sequence: u64, ticks: u64, value: u64) -> SchedulerEventLogEntry {
    let event = ObservableEvent::memory_sample(
        time(ticks),
        icount(ticks),
        node("guest"),
        ResolvedMemPlace::register("rax", 8),
        value,
    );
    crucible::test_support::condition_observation_entry_for_test(sequence, &event)
}

fn network_entry(sequence: u64, ticks: u64, payload: &[u8]) -> SchedulerEventLogEntry {
    let event = ObservableEvent::network_delivered(time(ticks), None, payload.to_vec());
    crucible::test_support::condition_observation_entry_for_test(sequence, &event)
}

fn online_report(
    properties: &Properties,
    log: &[SchedulerEventLogEntry],
) -> crucible::HostAssertionReport {
    let mut evaluator = HostAssertionEvaluator::new(properties);
    let mut oracle = BlackBoxHostOracle;
    if !log.is_empty() {
        for index in 0..log.len() - 1 {
            let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(
                log[..=index].to_vec(),
            )
            .expect("online proximity prefix should validate");
            evaluator.observe_prefix(&prefix, &mut oracle);
        }
    }
    let terminal = if log.is_empty() {
        ConditionEventLogPrefix::genesis()
    } else {
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(log.to_vec())
            .expect("terminal proximity prefix should validate")
    };
    evaluator.finalize_prefix(&terminal, &mut oracle)
}

fn proximity<'a>(
    proximities: &'a [HostAssertionProximity],
    assertion: &str,
) -> &'a HostAssertionProximity {
    proximities
        .iter()
        .find(|proximity| proximity.assertion.name == assertion)
        .unwrap_or_else(|| panic!("missing proximity for assertion {assertion}"))
}

#[test]
fn proximity_gradient_folds_minimum_threshold_gap_for_unsatisfied_sometimes() {
    let properties = properties(vec![assertion(
        "counter-reaches-ten",
        Property::Sometimes {
            predicate: memory_predicate(MemoryCmp::Ge, 10),
        },
    )]);
    let log = vec![
        memory_sample(0, 1, 2),
        memory_sample(1, 2, 7),
        memory_sample(2, 3, 5),
    ];

    let offline = OfflineAssertionChecker::new()
        .check_run(&properties, &log)
        .expect("offline proximity check should grade retained log");
    let online = online_report(&properties, &log);

    assert_eq!(offline, online);
    assert!(matches!(
        offline.verdict(),
        AssertionRunVerdict::Failed { .. }
    ));
    assert_eq!(
        offline.outcomes()[0].kind,
        HostAssertionOutcomeKind::Violated
    );
    let proximity = proximity(offline.proximities(), "counter-reaches-ten");
    assert_eq!(proximity.distance, 3);
    assert_eq!(proximity.at, time(2));
    assert_eq!(proximity.event_log_offset.events, 2);
}

#[test]
fn proximity_gradient_reports_boolean_unit_for_unreached_boolean_conditions() {
    let properties = properties(vec![assertion(
        "required-frame",
        Property::Reachable {
            predicate: Predicate::network_match(
                None,
                FramePredicate::contains(b"required".to_vec()),
            ),
            expectation: ReachabilityExpectation::Reachable {
                on_unreached: ReachableDisposition::Fail,
            },
        },
    )]);
    let log = vec![network_entry(0, 1, b"noise")];

    let report = OfflineAssertionChecker::new()
        .check_run(&properties, &log)
        .expect("offline boolean proximity check should grade retained log");

    assert_eq!(
        report.outcomes()[0].kind,
        HostAssertionOutcomeKind::NeverReachedFail
    );
    let proximity = proximity(report.proximities(), "required-frame");
    assert_eq!(proximity.distance, 1);
}

#[test]
fn proximity_gradient_tracks_armed_eventually_without_changing_verdict() {
    let properties = properties(vec![assertion(
        "counter-after-trigger",
        Property::Eventually {
            trigger: Predicate::network_match(None, FramePredicate::contains(b"start".to_vec())),
            property: memory_predicate(MemoryCmp::Gt, 10),
            deadline: time(5),
        },
    )]);
    let log = vec![
        network_entry(0, 1, b"start"),
        memory_sample(1, 2, 4),
        memory_sample(2, 3, 9),
        memory_sample(3, 4, 8),
    ];

    let report = OfflineAssertionChecker::new()
        .check_run(&properties, &log)
        .expect("offline eventually proximity check should grade retained log");

    assert!(matches!(
        report.verdict(),
        AssertionRunVerdict::Failed { .. }
    ));
    assert_eq!(
        report.outcomes()[0].kind,
        HostAssertionOutcomeKind::Violated
    );
    let proximity = proximity(report.proximities(), "counter-after-trigger");
    assert_eq!(proximity.distance, 2);
    assert_eq!(proximity.at, time(3));
}

#[test]
fn proximity_gradient_omits_satisfied_and_never_triggered_obligations() {
    let properties = properties(vec![
        assertion(
            "satisfied-sometimes",
            Property::Sometimes {
                predicate: memory_predicate(MemoryCmp::Ge, 10),
            },
        ),
        assertion(
            "never-triggered-eventually",
            Property::Eventually {
                trigger: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"start".to_vec()),
                ),
                property: memory_predicate(MemoryCmp::Ge, 1),
                deadline: time(5),
            },
        ),
    ]);
    let log = vec![memory_sample(0, 1, 10)];

    let report = OfflineAssertionChecker::new()
        .check_run(&properties, &log)
        .expect("offline satisfied proximity check should grade retained log");

    assert!(report.proximities().is_empty());
    assert!(
        report
            .outcomes()
            .iter()
            .any(|outcome| outcome.kind == HostAssertionOutcomeKind::Satisfied)
    );
    assert!(
        report
            .outcomes()
            .iter()
            .any(|outcome| outcome.kind == HostAssertionOutcomeKind::NeverTriggered)
    );
}
