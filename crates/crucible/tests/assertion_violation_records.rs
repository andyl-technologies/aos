//! Checks T-ASRT-14 deterministic assertion violation records.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionQuantifierKind, AssertionRunVerdict, BlackBoxHostOracle,
    ExternalFormalTraceExporter, HostAssertionEvaluator, HostAssertionOutcomeKind, Icount,
    MarkerId, NodeId, NodeTemplate, ObservableEvent, OfflineAssertionChecker, Predicate,
    Properties, Property, ReadyPoint, RecordedAssertionLog, SchedulerEvaluationBoundaryKind,
    SchedulerEventLogEntry, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn marker_id(name: &str) -> MarkerId {
    MarkerId::from_name(name)
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
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn world() -> World {
    World::from_nodes(vec![ready_node("decoy"), ready_node("guest")])
        .expect("violation record world should build")
}

fn assertion(id: &str, message: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: assertion_id(id),
        message: message.to_owned(),
        property,
    }
}

fn properties(world: &World) -> Properties {
    Properties::from_assertions_for_world(
        world,
        vec![assertion(
            "no-forbidden-marker",
            "forbidden marker must stay absent",
            Property::Always {
                predicate: Predicate::not(Predicate::guest_marker(marker_id("forbidden"))),
            },
        )],
    )
    .expect("violation record properties should validate")
}

fn event_log() -> Vec<SchedulerEventLogEntry> {
    let decoy = ObservableEvent::guest_marker(icount(7), node("decoy"), marker_id("decoy"));
    let forbidden = ObservableEvent::guest_marker(icount(7), node("guest"), marker_id("forbidden"));
    vec![
        crucible::test_support::condition_observation_entry_for_test(0, &decoy),
        crucible::test_support::condition_observation_entry_for_test(1, &forbidden),
        crucible::test_support::condition_boundary_entry_for_test(
            2,
            time(7),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ]
}

fn prefix(entries: Vec<SchedulerEventLogEntry>) -> crucible::ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_scheduler_entries_for_test(entries)
        .expect("violation record prefix should be checked")
}

#[test]
fn violation_records_are_derived_from_retained_log_and_reproduction_artifact() {
    let world = world();
    let properties = properties(&world);
    let event_log = event_log();
    let recorded_log =
        RecordedAssertionLog::from_segments(vec![event_log[..2].to_vec(), event_log[2..].to_vec()])
            .expect("violation record log should fold");
    let reproduction_artifact = ExternalFormalTraceExporter::export_event_log(&event_log)
        .expect("violation record log should export")
        .content_hash();

    let mut oracle = BlackBoxHostOracle;
    let mut evaluator =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
    evaluator.observe_prefix(&prefix(event_log[..1].to_vec()), &mut oracle);
    let online = evaluator.finalize_prefix(&prefix(event_log.clone()), &mut oracle);

    let offline = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run(&properties, &event_log)
        .expect("offline violation record check should grade retained log");
    let offline_recorded = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run_with_oracle(&properties, &recorded_log, &mut BlackBoxHostOracle)
        .expect("offline recorded violation record check should grade retained log");

    assert_eq!(online, offline);
    assert_eq!(offline, offline_recorded);
    assert!(matches!(
        online.verdict(),
        AssertionRunVerdict::Failed { .. }
    ));
    assert_eq!(
        online.outcomes()[0].kind,
        HostAssertionOutcomeKind::Violated
    );

    let violations = online.violations();
    assert_eq!(violations.len(), 1);
    let violation = &violations[0];
    assert_eq!(violation.assertion, assertion_id("no-forbidden-marker"));
    assert_eq!(violation.message, "forbidden marker must stay absent");
    assert_eq!(violation.quantifier, AssertionQuantifierKind::Always);
    assert_eq!(violation.at_icount, Some(icount(7)));
    assert_eq!(violation.at_virtual_time, time(7));
    assert_eq!(violation.node, Some(node("guest")));
    assert_eq!(violation.reproduction_artifact, reproduction_artifact);
    assert!(
        violation
            .detail
            .contains("expected=always predicate remains true")
    );
    assert!(
        violation.detail.contains(
            "observed=not predicate was false; inner guest marker marker=forbidden matched"
        )
    );
    assert!(
        violation
            .detail
            .contains("reason=always predicate was false")
    );
}
