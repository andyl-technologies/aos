//! Checks scenario-declared assertions evaluated by structured guest markers.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use crucible::{
    AssertionDef, AssertionId, BlackBoxHostOracle, GuestAssertionDetail, GuestAssertionKind,
    GuestAssertionMarker, HostAssertionEvaluator, HostAssertionOutcomeKind, Icount, NodeId,
    NodeTemplate, ObservableEvent, Properties, ReachableDisposition, ReadyPoint, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode,
};

#[test]
fn declared_guest_assertion_uses_marker_truth_without_duplicate_host_outcome() {
    let world = world();
    let assertion_id = assertion_id("curl-receives-http-200");
    let properties = properties(
        &world,
        vec![AssertionDef::guest_sometimes(
            assertion_id.clone(),
            "curl-receives-http-200 message",
        )],
    );
    let mut evaluator =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
    let mut oracle = BlackBoxHostOracle;

    let marker = guest_marker(42, &assertion_id.name);
    let outcomes =
        evaluator.observe_prefix(&observable_prefix(50, vec![marker.clone()]), &mut oracle);

    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].assertion, assertion_id);
    assert_eq!(
        outcomes[0].quantifier,
        crucible::AssertionQuantifierKind::GuestSometimes
    );
    assert_eq!(outcomes[0].kind, HostAssertionOutcomeKind::Satisfied);
    assert_eq!(outcomes[0].at.ticks, 50);
    assert!(
        evaluator
            .observe_prefix(&observable_prefix(51, vec![marker.clone()]), &mut oracle)
            .is_empty()
    );
    let report = evaluator.finalize_prefix(&observable_prefix(52, vec![marker]), &mut oracle);
    assert_eq!(report.outcomes().len(), 1);
    assert_eq!(
        report.outcomes()[0].kind,
        HostAssertionOutcomeKind::Satisfied
    );
}

#[test]
fn declared_guest_assertion_rejects_marker_message_drift() {
    let world = world();
    let properties = properties(
        &world,
        vec![AssertionDef::guest_sometimes(
            assertion_id("curl-receives-http-200"),
            "authored scenario message",
        )],
    );
    let mut evaluator =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
    let mut oracle = BlackBoxHostOracle;

    let outcomes = evaluator.observe_prefix(
        &observable_prefix(42, vec![guest_marker(42, "curl-receives-http-200")]),
        &mut oracle,
    );

    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].kind, HostAssertionOutcomeKind::Violated);
    assert_eq!(outcomes[0].message, "authored scenario message");
    assert!(outcomes[0].reason.contains("differs"));
}

#[test]
fn declared_guest_assertion_helpers_cover_every_guest_flavor() {
    let world = world();
    let properties = properties(
        &world,
        vec![
            AssertionDef::guest_always(assertion_id("invariant"), "invariant message"),
            AssertionDef::guest_reachable(
                assertion_id("reachable"),
                "reachable message",
                ReachableDisposition::Fail,
            ),
            AssertionDef::guest_unreachable(assertion_id("unreachable"), "unreachable message"),
        ],
    );
    let mut evaluator =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
    let mut oracle = BlackBoxHostOracle;

    let outcomes = evaluator.observe_prefix(
        &observable_prefix(
            50,
            vec![
                guest_marker_with_kind(42, "invariant", GuestAssertionKind::Always, true),
                guest_marker_with_kind(43, "reachable", GuestAssertionKind::Reachable, true),
                guest_marker_with_kind(44, "unreachable", GuestAssertionKind::Unreachable, true),
            ],
        ),
        &mut oracle,
    );
    assert!(outcomes.iter().any(|outcome| {
        outcome.assertion.name == "reachable" && outcome.kind == HostAssertionOutcomeKind::Satisfied
    }));
    assert!(outcomes.iter().any(|outcome| {
        outcome.assertion.name == "unreachable"
            && outcome.kind == HostAssertionOutcomeKind::Violated
    }));

    let report = evaluator.finalize_prefix(&observable_prefix(51, Vec::new()), &mut oracle);
    assert!(report.outcomes().iter().any(|outcome| {
        outcome.assertion.name == "invariant" && outcome.kind == HostAssertionOutcomeKind::Passed
    }));
}

fn world() -> World {
    World::from_nodes(vec![WorldNode {
        id: node("guest"),
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
    }])
    .expect("guest assertion declaration world should build")
}

fn properties(world: &World, assertions: Vec<AssertionDef>) -> Properties {
    Properties::from_assertions_for_world(world, assertions)
        .expect("guest assertion declarations should validate")
}

fn observable_prefix(
    ticks: u64,
    events: Vec<ObservableEvent>,
) -> crucible::ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_observable_events_for_test(ticks, events)
        .expect("guest assertion observation prefix should validate")
}

fn guest_marker(ticks: u64, id: &str) -> ObservableEvent {
    guest_marker_with_kind(ticks, id, GuestAssertionKind::Sometimes, true)
}

fn guest_marker_with_kind(
    ticks: u64,
    id: &str,
    kind: GuestAssertionKind,
    condition: bool,
) -> ObservableEvent {
    ObservableEvent::guest_assertion_marker(
        icount(ticks),
        node("guest"),
        GuestAssertionMarker::new(
            assertion_id(id),
            format!("{id} message"),
            kind,
            condition,
            true,
            vec![GuestAssertionDetail::new("case", id)],
            format!("{id}.rs:1"),
        ),
    )
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
