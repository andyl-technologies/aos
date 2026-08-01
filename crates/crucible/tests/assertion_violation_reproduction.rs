//! Checks T-ASRT-15 assertion violation replay and divergence reporting.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    AssertionDef, AssertionId, AssertionQuantifierKind, AssertionViolationArtifactReplay,
    AssertionViolationReplayError, ConditionLeaf, Decision, EventDiagnosticPayload, EventLevel,
    EventSource, HostAssertionPredicate, Icount, LintedHostAssertionOracle, MarkerId, NodeId,
    NodeTemplate, ObservableEvent, ObservedState, Plan, Predicate, Properties, Property,
    ReadyPoint, RecordedAssertionLog, ReproductionArtifact, RngDecision, RngStreamId,
    ScenarioDefForm, Schedule, SchedulerEventLogPayload, Seed, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode, check_assertion_violation_reproduction,
    check_assertion_violation_reproduction_with_oracles,
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
        .expect("violation reproduction world should build")
}

fn properties(world: &World) -> Properties {
    Properties::from_assertions_for_world(
        world,
        vec![AssertionDef {
            id: assertion_id("no-forbidden-marker"),
            message: "forbidden marker must stay absent".to_owned(),
            property: Property::Always {
                predicate: Predicate::not(Predicate::guest_marker(marker_id("forbidden"))),
            },
        }],
    )
    .expect("violation reproduction properties should validate")
}

fn reproduction_schedule(value: u64) -> Schedule {
    Schedule::empty().appended(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("assertion-violation-reproduction"),
        value,
    }))
}

fn reproduction_artifact(
    world: &World,
    properties: &Properties,
    schedule_value: u64,
) -> ReproductionArtifact {
    let scenario = ScenarioDefForm::from_components(
        world,
        &Plan::empty(),
        properties,
        Seed::from_u64(0xa15e_0015),
    )
    .expect("violation reproduction scenario should build");
    ReproductionArtifact::capture(&scenario, &reproduction_schedule(schedule_value))
        .expect("violation reproduction artifact should reduce")
}

fn event_log_with_decision_value(
    marker: MarkerId,
    decision_value: u64,
) -> Vec<crucible::SchedulerEventLogEntry> {
    let decision = SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("assertion-violation-reproduction"),
        value: decision_value,
    }));
    let decoy = ObservableEvent::guest_marker(icount(7), node("decoy"), marker_id("decoy"));
    let observed = ObservableEvent::guest_marker(icount(7), node("guest"), marker);
    vec![
        crucible::test_support::condition_payload_entry_for_test(0, time(0), decision),
        crucible::test_support::condition_observation_entry_for_test(1, &decoy),
        crucible::test_support::condition_observation_entry_for_test(2, &observed),
        crucible::test_support::condition_boundary_entry_for_test(
            3,
            time(7),
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ]
}

fn event_log(marker: MarkerId) -> Vec<crucible::SchedulerEventLogEntry> {
    event_log_with_decision_value(marker, 0xa15e_0015)
}

fn recorded_log(marker: MarkerId) -> RecordedAssertionLog {
    let event_log = event_log(marker);
    RecordedAssertionLog::from_segments(vec![event_log[..3].to_vec(), event_log[3..].to_vec()])
        .expect("violation reproduction log should fold")
}

fn recorded_log_with_decision_value(marker: MarkerId, decision_value: u64) -> RecordedAssertionLog {
    let event_log = event_log_with_decision_value(marker, decision_value);
    RecordedAssertionLog::from_segments(vec![event_log[..3].to_vec(), event_log[3..].to_vec()])
        .expect("violation reproduction log should fold")
}

fn event_log_with_diagnostic(marker: MarkerId) -> Vec<crucible::SchedulerEventLogEntry> {
    let decision = SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("assertion-violation-reproduction"),
        value: 0xa15e_0015,
    }));
    let diagnostic = SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
        "replay.poll",
        EventLevel::Debug,
        BTreeMap::new(),
    ));
    let decoy = ObservableEvent::guest_marker(icount(7), node("decoy"), marker_id("decoy"));
    let observed = ObservableEvent::guest_marker(icount(7), node("guest"), marker);
    vec![
        crucible::test_support::condition_payload_entry_for_test(0, time(0), decision),
        crucible::test_support::condition_payload_entry_for_test(1, time(0), diagnostic),
        crucible::test_support::condition_observation_entry_for_test(2, &decoy),
        crucible::test_support::condition_observation_entry_for_test(3, &observed),
        crucible::test_support::condition_boundary_entry_for_test(
            4,
            time(7),
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ]
}

fn recorded_log_with_diagnostic(marker: MarkerId) -> RecordedAssertionLog {
    let event_log = event_log_with_diagnostic(marker);
    RecordedAssertionLog::from_segments(vec![event_log[..2].to_vec(), event_log[2..].to_vec()])
        .expect("diagnostic reproduction log should fold")
}

fn artifact_replay(
    artifact: &ReproductionArtifact,
    assertion_log: RecordedAssertionLog,
) -> AssertionViolationArtifactReplay {
    AssertionViolationArtifactReplay::from_artifact(artifact, assertion_log)
        .expect("artifact replay evidence should reduce")
}

fn linted_host_oracle<O>(oracle: O) -> LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    crucible::test_support::unchecked_host_assertion_oracle_for_test(oracle)
}

#[test]
fn violation_reproduction_replays_same_artifact_and_violation() {
    let world = world();
    let properties = properties(&world);
    let artifact = reproduction_artifact(&world, &properties, 0xa15e_0015);
    let recorded = recorded_log(marker_id("forbidden"));
    let replayed = artifact_replay(&artifact, recorded.clone());
    let artifact_id = artifact.id();

    let report = check_assertion_violation_reproduction(&artifact, &recorded, &replayed)
        .expect("same retained log should reproduce the violation");

    assert_eq!(report.artifact, artifact_id);
    assert_eq!(report.replay.artifact, artifact_id);
    assert_eq!(report.replay.schedule, artifact.schedule().content_hash());
    assert_eq!(report.expected, report.reproduced);
    let violations = report.reproduced.violations();
    assert_eq!(violations.len(), 1);
    let violation = &violations[0];
    assert_eq!(violation.assertion, assertion_id("no-forbidden-marker"));
    assert_eq!(violation.quantifier, AssertionQuantifierKind::Always);
    assert_eq!(violation.at_icount, Some(icount(7)));
    assert_eq!(violation.node, Some(node("guest")));
    assert_eq!(violation.reproduction_artifact, artifact_id);
}

#[test]
fn violation_reproduction_ignores_observational_diagnostic_replay_entries() {
    let world = world();
    let properties = properties(&world);
    let artifact = reproduction_artifact(&world, &properties, 0xa15e_0015);
    let recorded = recorded_log(marker_id("forbidden"));
    let replayed = artifact_replay(
        &artifact,
        recorded_log_with_diagnostic(marker_id("forbidden")),
    );

    let report = check_assertion_violation_reproduction(&artifact, &recorded, &replayed)
        .expect("diagnostic-only replay log difference should reproduce the violation");

    assert_eq!(report.expected, report.reproduced);
    assert_eq!(report.reproduced.violations().len(), 1);
}

#[test]
fn violation_reproduction_localizes_non_reproduction_as_divergence() {
    let world = world();
    let properties = properties(&world);
    let artifact = reproduction_artifact(&world, &properties, 0xa15e_0015);
    let artifact_id = artifact.id();
    let recorded = recorded_log(marker_id("forbidden"));
    let replayed = artifact_replay(&artifact, recorded_log(marker_id("allowed")));

    let error = check_assertion_violation_reproduction(&artifact, &recorded, &replayed)
        .expect_err("changed replay log should be reported as divergence");
    let AssertionViolationReplayError::Divergence { divergence } = error else {
        panic!("expected localized divergence");
    };

    assert_eq!(divergence.artifact, artifact_id);
    assert_eq!(divergence.first_different_prefix_len, 4);
    assert_eq!(divergence.first_different_icount, Some(icount(7)));
    assert_eq!(divergence.bisection.artifact, artifact_id);
    assert_eq!(divergence.bisection.last_matching_event_prefix_len, 4);
    assert_eq!(divergence.bisection.first_different_event_prefix_len, 4);
    assert_eq!(divergence.bisection.schedule_decision_count, 1);
    assert_eq!(
        divergence.bisection.first_different_decision_prefix_len,
        None
    );
    assert!(divergence.expected_event.is_none());
    assert!(divergence.reproduced_event.is_none());
    assert_eq!(
        divergence
            .expected_violation
            .as_ref()
            .map(|violation| violation.assertion.clone()),
        Some(assertion_id("no-forbidden-marker"))
    );
    assert!(divergence.reproduced_violation.is_none());
}

#[test]
fn violation_reproduction_bisection_reports_first_differing_causal_entry() {
    let world = world();
    let properties = properties(&world);
    let artifact = reproduction_artifact(&world, &properties, 0xa15e_0015);
    let artifact_id = artifact.id();
    let recorded = recorded_log_with_decision_value(marker_id("forbidden"), 0xa15e_0015);
    let replayed = artifact_replay(
        &artifact,
        recorded_log_with_decision_value(marker_id("forbidden"), 0xa15e_0016),
    );

    let error = check_assertion_violation_reproduction(&artifact, &recorded, &replayed)
        .expect_err("changed causal replay log should be reported as divergence");
    let AssertionViolationReplayError::Divergence { divergence } = error else {
        panic!("expected localized divergence");
    };
    let location = divergence
        .first_different_causal_entry
        .as_ref()
        .expect("event-log divergence should report the first causal entry");
    let request_location = divergence
        .bisection
        .first_different_causal_entry
        .as_ref()
        .expect("bisection request should carry the event-log location");

    assert_eq!(divergence.artifact, artifact_id);
    assert_eq!(divergence.first_different_prefix_len, 1);
    assert_eq!(divergence.first_different_icount, Some(icount(0)));
    assert_eq!(location, request_location);
    assert_eq!(location.raw_index, 0);
    assert_eq!(location.at.node.as_ref(), None);
    assert_eq!(location.at.icount, icount(0));
    assert_eq!(&location.source, &EventSource::Engine);
    assert_eq!(location.kind.as_str(), "rng_draw");
    assert_eq!(
        divergence
            .expected_event
            .as_ref()
            .map(|event| event.event_payload().kind()),
        Some("rng_draw")
    );
    assert_eq!(
        divergence
            .reproduced_event
            .as_ref()
            .map(|event| event.event_payload().kind()),
        Some("rng_draw")
    );
    assert!(
        divergence.expected_violation.is_none(),
        "event-log bisection should not smooth the first causal mismatch into a report difference"
    );
    assert!(divergence.reproduced_violation.is_none());
}

#[test]
fn violation_reproduction_rejects_logs_without_recorded_violation() {
    let world = world();
    let properties = properties(&world);
    let artifact = reproduction_artifact(&world, &properties, 0xa15e_0015);
    let artifact_id = artifact.id();
    let recorded = recorded_log(marker_id("allowed"));
    let replayed = artifact_replay(&artifact, recorded.clone());

    let error = check_assertion_violation_reproduction(&artifact, &recorded, &replayed)
        .expect_err("passing recorded log should not satisfy violation reproduction");
    let AssertionViolationReplayError::MissingRecordedViolation { artifact } = error else {
        panic!("expected missing recorded violation");
    };

    assert_eq!(artifact, artifact_id);
}

#[test]
fn violation_reproduction_rejects_replay_from_different_artifact_schedule() {
    let world = world();
    let properties = properties(&world);
    let artifact = reproduction_artifact(&world, &properties, 0xa15e_0015);
    let wrong_artifact = reproduction_artifact(&world, &properties, 0xa15e_0016);
    let recorded = recorded_log(marker_id("forbidden"));
    let replayed = artifact_replay(&wrong_artifact, recorded.clone());

    let error = check_assertion_violation_reproduction(&artifact, &recorded, &replayed)
        .expect_err("replay from another artifact schedule should be rejected");
    let AssertionViolationReplayError::ReplayArtifactMismatch {
        expected,
        reproduced,
    } = error
    else {
        panic!("expected replay artifact mismatch");
    };

    assert_eq!(expected.artifact, artifact.id());
    assert_eq!(expected.schedule, artifact.schedule().content_hash());
    assert_eq!(reproduced.artifact, wrong_artifact.id());
    assert_eq!(
        reproduced.schedule,
        wrong_artifact.schedule().content_hash()
    );
}

#[test]
fn violation_reproduction_with_oracles_preserves_recorded_offsets() {
    let world = world();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion_id("host-offset-violation"),
            message: "host predicate fails at retained offset".to_owned(),
            property: Property::Always {
                predicate: Predicate::named("prefix-before-violation-offset"),
            },
        }],
    )
    .expect("host oracle properties should validate");
    let artifact = reproduction_artifact(&world, &properties, 0xa15e_0015);
    let recorded = recorded_log(marker_id("forbidden"));
    let replayed = artifact_replay(&artifact, recorded.clone());
    let mut expected_oracle = linted_host_oracle(
        |state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
            ConditionLeaf::Named { name, nodes } => {
                name == "prefix-before-violation-offset"
                    && nodes.is_empty()
                    && state.event_log_offset().events < 3
            }
            ConditionLeaf::GuestMarker { .. } => false,
        },
    );
    let mut reproduced_oracle = linted_host_oracle(
        |state: ObservedState<'_>, leaf: ConditionLeaf<'_>| match leaf {
            ConditionLeaf::Named { name, nodes } => {
                name == "prefix-before-violation-offset"
                    && nodes.is_empty()
                    && state.event_log_offset().events < 3
            }
            ConditionLeaf::GuestMarker { .. } => false,
        },
    );

    let report = check_assertion_violation_reproduction_with_oracles(
        &artifact,
        &recorded,
        &replayed,
        &mut expected_oracle,
        &mut reproduced_oracle,
    )
    .expect("custom host oracle replay should preserve retained offsets");

    assert_eq!(report.expected, report.reproduced);
    let violation = &report.reproduced.violations()[0];
    assert_eq!(violation.assertion, assertion_id("host-offset-violation"));
    assert_eq!(violation.reproduction_artifact, artifact.id());
}
