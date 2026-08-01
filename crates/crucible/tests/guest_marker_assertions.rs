//! Checks T-ASRT-6 guest-side assertion markers over the white-box channel.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, AssertionDef, AssertionId, AssertionRunVerdict, BlackBoxHostOracle,
    ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle, Event, EventGraph,
    EventGraphState, EventId, FramePredicate, GuestAssertionDetail, GuestAssertionKind,
    GuestAssertionMarker, HostAssertionEvaluator, HostAssertionOutcome, HostAssertionOutcomeKind,
    Icount, MarkerId, NodeId, NodeTemplate, ObservableEvent, ObservableEventPayload, Predicate,
    Properties, Property, ReachabilityExpectation, ReachableDisposition, ReadyPoint, VirtualTime,
    VmArchitecture, WhiteBoxPolicy, World, WorldNode,
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
    World::from_nodes(vec![
        ready_node("guest", WhiteBoxPolicy::Enabled),
        ready_node("blackbox", WhiteBoxPolicy::Disabled),
    ])
    .expect("guest marker assertion world should build")
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
        .expect("guest marker assertion properties should validate")
}

fn observable_prefix(
    ticks: u64,
    events: Vec<ObservableEvent>,
) -> crucible::ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_observable_events_for_test(ticks, events)
        .expect("observable guest marker prefix should be checked")
}

fn guest_marker(
    ticks: u64,
    node_name: &str,
    id: &str,
    kind: GuestAssertionKind,
    condition: bool,
    must_hit: bool,
) -> ObservableEvent {
    ObservableEvent::guest_assertion_marker(
        icount(ticks),
        node(node_name),
        GuestAssertionMarker::new(
            assertion_id(id),
            format!("{id} message"),
            kind,
            condition,
            must_hit,
            vec![GuestAssertionDetail::new("case", id)],
            format!("{id}.rs:1"),
        ),
    )
}

fn bare_guest_marker(ticks: u64, node_name: &str, id: &str) -> ObservableEvent {
    ObservableEvent::guest_marker(icount(ticks), node(node_name), marker_id(id))
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("guest marker assertion tests use event-backed leaves")
            }
        }
    }
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

#[test]
fn guest_assertion_marker_payload_carries_finalize_fields() {
    let event = guest_marker(
        42,
        "guest",
        "catalog-entry",
        GuestAssertionKind::Reachable,
        false,
        true,
    );

    assert_eq!(event.at(), time(42));
    match event.payload() {
        ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } => {
            assert_eq!(retired_icount.retired, 42);
            assert_eq!(node.name, "guest");
            assert_eq!(marker.id.name, "catalog-entry");
            assert_eq!(marker.kind, GuestAssertionKind::Reachable);
            assert!(!marker.condition);
            assert!(marker.must_hit);
            assert_eq!(marker.details[0].key, "case");
            assert_eq!(marker.details[0].value, "catalog-entry");
            assert_eq!(marker.location, "catalog-entry.rs:1");
        }
        other => {
            panic!("guest assertion marker constructor should build assertion payload: {other:?}")
        }
    }
}

#[test]
fn guest_marker_assertions_fold_into_unified_report() {
    let world = world();
    let host_properties = properties(
        &world,
        vec![assertion(
            "host-network-ack",
            "host network ack",
            Property::Sometimes {
                predicate: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"ack".to_vec()),
                ),
            },
        )],
    );
    let mut evaluator =
        HostAssertionEvaluator::new(&host_properties).with_world_white_box_policies(&world);
    let mut oracle = BlackBoxHostOracle;
    let ack = ObservableEvent::network_delivered(time(8), None, b"ack".to_vec());

    evaluator.observe_prefix(
        &observable_prefix(
            8,
            vec![
                ack.clone(),
                guest_marker(
                    8,
                    "guest",
                    "guest-always",
                    GuestAssertionKind::Always,
                    true,
                    true,
                ),
                guest_marker(
                    8,
                    "guest",
                    "guest-sometimes",
                    GuestAssertionKind::Sometimes,
                    true,
                    true,
                ),
                guest_marker(
                    8,
                    "guest",
                    "guest-reachable-warn",
                    GuestAssertionKind::Reachable,
                    false,
                    false,
                ),
                guest_marker(
                    8,
                    "guest",
                    "guest-reachable-fail",
                    GuestAssertionKind::Reachable,
                    false,
                    true,
                ),
                guest_marker(
                    8,
                    "guest",
                    "guest-unreachable",
                    GuestAssertionKind::Unreachable,
                    true,
                    true,
                ),
            ],
        ),
        &mut oracle,
    );
    let report = evaluator.finalize_prefix(&observable_prefix(12, vec![ack]), &mut oracle);

    assert!(report.verdict().is_failed());
    assert_outcome(
        report.outcomes(),
        "host-network-ack",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert_outcome(
        report.outcomes(),
        "guest-always",
        HostAssertionOutcomeKind::Passed,
    );
    assert_outcome(
        report.outcomes(),
        "guest-sometimes",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert_outcome(
        report.outcomes(),
        "guest-reachable-warn",
        HostAssertionOutcomeKind::NeverReachedWarn,
    );
    assert_outcome(
        report.outcomes(),
        "guest-reachable-fail",
        HostAssertionOutcomeKind::NeverReachedFail,
    );
    assert_outcome(
        report.outcomes(),
        "guest-unreachable",
        HostAssertionOutcomeKind::Violated,
    );
    assert!(
        !report
            .verdict()
            .failures()
            .iter()
            .any(|failure| failure.assertion.name == "guest-reachable-warn")
    );
}

#[test]
fn catalog_declared_guest_markers_finalize_without_emitted_events() {
    let world = world();
    let host_properties = Properties::empty();
    let mut evaluator = HostAssertionEvaluator::new(&host_properties)
        .with_world_white_box_policies(&world)
        .with_guest_assertion_catalog(vec![
            GuestAssertionMarker::new(
                assertion_id("catalog-always"),
                "catalog always",
                GuestAssertionKind::Always,
                true,
                true,
                vec![GuestAssertionDetail::new("declared", "always")],
                "catalog.rs:10",
            ),
            GuestAssertionMarker::new(
                assertion_id("catalog-reachable-fail"),
                "catalog reachable fail",
                GuestAssertionKind::Reachable,
                false,
                true,
                vec![GuestAssertionDetail::new("declared", "required")],
                "catalog.rs:20",
            ),
            GuestAssertionMarker::new(
                assertion_id("catalog-reachable-warn"),
                "catalog reachable warn",
                GuestAssertionKind::Reachable,
                false,
                false,
                vec![GuestAssertionDetail::new("declared", "optional")],
                "catalog.rs:30",
            ),
        ]);
    let mut oracle = BlackBoxHostOracle;

    let report = evaluator.finalize_prefix(&observable_prefix(99, Vec::new()), &mut oracle);

    assert!(report.verdict().is_failed());
    assert_outcome(
        report.outcomes(),
        "catalog-always",
        HostAssertionOutcomeKind::Passed,
    );
    assert_outcome(
        report.outcomes(),
        "catalog-reachable-fail",
        HostAssertionOutcomeKind::NeverReachedFail,
    );
    assert_outcome(
        report.outcomes(),
        "catalog-reachable-warn",
        HostAssertionOutcomeKind::NeverReachedWarn,
    );
    assert!(
        outcome(report.outcomes(), "catalog-reachable-fail")
            .reason
            .contains("catalog.rs:20")
    );
}

#[test]
fn guest_marker_predicates_work_in_all_five_property_quantifiers() {
    let world = world();
    let properties = properties(
        &world,
        vec![
            assertion(
                "always-no-forbidden-guest-marker",
                "forbidden marker stays absent",
                Property::Always {
                    predicate: Predicate::not(Predicate::guest_marker(marker_id("forbidden"))),
                },
            ),
            assertion(
                "sometimes-guest-marker",
                "sometimes marker is observed",
                Property::Sometimes {
                    predicate: Predicate::guest_marker(marker_id("sometimes-marker")),
                },
            ),
            assertion(
                "eventually-guest-marker",
                "eventual guest marker follows trigger",
                Property::Eventually {
                    trigger: Predicate::guest_marker(marker_id("trigger-marker")),
                    property: Predicate::guest_marker(marker_id("done-marker")),
                    deadline: time(5),
                },
            ),
            assertion(
                "after-quiescence-guest-marker",
                "terminal marker is visible at final point",
                Property::AfterQuiescence {
                    predicate: Predicate::guest_marker(marker_id("quiesced-marker")),
                },
            ),
            assertion(
                "reachable-guest-marker",
                "coverage marker is reached",
                Property::Reachable {
                    predicate: Predicate::guest_marker(marker_id("coverage-marker")),
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Warn,
                    },
                },
            ),
        ],
    );
    let trigger = bare_guest_marker(10, "guest", "trigger-marker");
    let sometimes = bare_guest_marker(12, "guest", "sometimes-marker");
    let done = bare_guest_marker(12, "guest", "done-marker");
    let coverage = bare_guest_marker(15, "guest", "coverage-marker");
    let quiesced = bare_guest_marker(20, "guest", "quiesced-marker");
    let mut evaluator =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
    let mut oracle = BlackBoxHostOracle;

    evaluator.observe_prefix(&observable_prefix(1, Vec::new()), &mut oracle);
    evaluator.observe_prefix(&observable_prefix(10, vec![trigger.clone()]), &mut oracle);
    evaluator.observe_prefix(
        &observable_prefix(12, vec![trigger.clone(), sometimes.clone(), done.clone()]),
        &mut oracle,
    );
    evaluator.observe_prefix(
        &observable_prefix(
            15,
            vec![
                trigger.clone(),
                sometimes.clone(),
                done.clone(),
                coverage.clone(),
            ],
        ),
        &mut oracle,
    );
    let report = evaluator.finalize_prefix(
        &observable_prefix(20, vec![trigger, sometimes, done, coverage, quiesced]),
        &mut oracle,
    );

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_outcome(
        report.outcomes(),
        "always-no-forbidden-guest-marker",
        HostAssertionOutcomeKind::Passed,
    );
    assert_outcome(
        report.outcomes(),
        "sometimes-guest-marker",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert_outcome(
        report.outcomes(),
        "eventually-guest-marker",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert_outcome(
        report.outcomes(),
        "after-quiescence-guest-marker",
        HostAssertionOutcomeKind::Passed,
    );
    assert_outcome(
        report.outcomes(),
        "reachable-guest-marker",
        HostAssertionOutcomeKind::Satisfied,
    );
}

#[test]
fn assertion_markers_do_not_fire_guest_marker_triggers() {
    let world = world();
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            EventId::from_name("pass-on-marker"),
            Some(Predicate::guest_marker(marker_id("assertion-marker"))),
            Action::Pass,
        )],
        &world,
    )
    .expect("guest marker trigger graph should build");
    let prefix = observable_prefix(
        33,
        vec![guest_marker(
            33,
            "guest",
            "assertion-marker",
            GuestAssertionKind::Reachable,
            true,
            true,
        )],
    );
    let mut pass = ConditionEvaluationPass::from_log_prefix(prefix, NoLeaves)
        .with_world_white_box_policies(&world);
    let mut state = EventGraphState::new();

    let firings = pass.evaluate_event_graph(&graph, &mut state);

    assert!(firings.is_empty());
}

#[test]
fn terminal_marker_reasons_use_current_payload_details() {
    let world = world();
    let properties = Properties::empty();
    let mut evaluator =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
    let mut oracle = BlackBoxHostOracle;
    let first = ObservableEvent::guest_assertion_marker(
        icount(5),
        node("guest"),
        GuestAssertionMarker::new(
            assertion_id("always-current-details"),
            "first message",
            GuestAssertionKind::Always,
            true,
            true,
            vec![GuestAssertionDetail::new("phase", "first")],
            "first.rs:1",
        ),
    );
    let second = ObservableEvent::guest_assertion_marker(
        icount(6),
        node("guest"),
        GuestAssertionMarker::new(
            assertion_id("always-current-details"),
            "second message",
            GuestAssertionKind::Always,
            false,
            true,
            vec![GuestAssertionDetail::new("phase", "second")],
            "second.rs:2",
        ),
    );

    evaluator.observe_prefix(&observable_prefix(5, vec![first.clone()]), &mut oracle);
    evaluator.observe_prefix(&observable_prefix(6, vec![first, second]), &mut oracle);
    let report = evaluator.finalize_prefix(&observable_prefix(7, Vec::new()), &mut oracle);
    let outcome = outcome(report.outcomes(), "always-current-details");

    assert_eq!(outcome.kind, HostAssertionOutcomeKind::Violated);
    assert_eq!(outcome.message, "second message");
    assert!(outcome.reason.contains("second.rs:2"));
    assert!(outcome.reason.contains("phase=second"));
}

#[test]
fn terminal_marker_outcome_ignores_later_payload_updates() {
    let world = world();
    let properties = Properties::empty();
    let mut evaluator =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
    let mut oracle = BlackBoxHostOracle;
    let terminal = ObservableEvent::guest_assertion_marker(
        icount(5),
        node("guest"),
        GuestAssertionMarker::new(
            assertion_id("immutable-terminal"),
            "terminal message",
            GuestAssertionKind::Always,
            false,
            true,
            vec![GuestAssertionDetail::new("phase", "terminal")],
            "terminal.rs:5",
        ),
    );
    let later = ObservableEvent::guest_assertion_marker(
        icount(6),
        node("guest"),
        GuestAssertionMarker::new(
            assertion_id("immutable-terminal"),
            "later message",
            GuestAssertionKind::Always,
            true,
            true,
            vec![GuestAssertionDetail::new("phase", "later")],
            "later.rs:6",
        ),
    );

    evaluator.observe_prefix(&observable_prefix(5, vec![terminal]), &mut oracle);
    evaluator.observe_prefix(&observable_prefix(6, vec![later]), &mut oracle);
    let report = evaluator.finalize_prefix(&observable_prefix(7, Vec::new()), &mut oracle);
    let outcome = outcome(report.outcomes(), "immutable-terminal");

    assert_eq!(outcome.kind, HostAssertionOutcomeKind::Violated);
    assert_eq!(outcome.message, "terminal message");
    assert!(outcome.reason.contains("terminal.rs:5"));
    assert!(outcome.reason.contains("phase=terminal"));
    assert!(!outcome.reason.contains("later.rs:6"));
    assert!(!outcome.reason.contains("phase=later"));
}

#[test]
fn guest_marker_catalog_kind_mismatch_is_reported() {
    let world = world();
    let properties = Properties::empty();
    let mut evaluator = HostAssertionEvaluator::new(&properties)
        .with_world_white_box_policies(&world)
        .with_guest_assertion_catalog(vec![GuestAssertionMarker::new(
            assertion_id("catalog-kind"),
            "catalog message",
            GuestAssertionKind::Reachable,
            false,
            true,
            vec![GuestAssertionDetail::new("declared", "reachable")],
            "catalog.rs:20",
        )]);
    let mut oracle = BlackBoxHostOracle;
    let emitted = ObservableEvent::guest_assertion_marker(
        icount(9),
        node("guest"),
        GuestAssertionMarker::new(
            assertion_id("catalog-kind"),
            "emitted message",
            GuestAssertionKind::Always,
            false,
            true,
            vec![GuestAssertionDetail::new("observed", "always")],
            "emitted.rs:9",
        ),
    );

    evaluator.observe_prefix(&observable_prefix(9, vec![emitted]), &mut oracle);
    let report = evaluator.finalize_prefix(&observable_prefix(10, Vec::new()), &mut oracle);
    let outcome = outcome(report.outcomes(), "catalog-kind");

    assert!(report.verdict().is_failed());
    assert_eq!(outcome.kind, HostAssertionOutcomeKind::Violated);
    assert_eq!(outcome.message, "emitted message");
    assert!(outcome.reason.contains("kind mismatch"));
    assert!(outcome.reason.contains("declared Reachable"));
    assert!(outcome.reason.contains("observed Always"));
    assert!(outcome.reason.contains("emitted.rs:9"));
    assert!(outcome.reason.contains("observed=always"));
}

#[test]
fn guest_marker_assertions_ignore_disabled_white_box_nodes() {
    let world = world();
    let properties = properties(
        &world,
        vec![assertion(
            "host-network-ack",
            "host network ack",
            Property::Sometimes {
                predicate: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"ack".to_vec()),
                ),
            },
        )],
    );
    let mut evaluator =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
    let mut oracle = BlackBoxHostOracle;
    let ack = ObservableEvent::network_delivered(time(8), None, b"ack".to_vec());

    evaluator.observe_prefix(
        &observable_prefix(
            8,
            vec![
                ack.clone(),
                guest_marker(
                    8,
                    "blackbox",
                    "disabled-node-marker",
                    GuestAssertionKind::Unreachable,
                    true,
                    true,
                ),
            ],
        ),
        &mut oracle,
    );
    let report = evaluator.finalize_prefix(&observable_prefix(12, vec![ack]), &mut oracle);

    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_outcome(
        report.outcomes(),
        "host-network-ack",
        HostAssertionOutcomeKind::Satisfied,
    );
    assert!(
        !report
            .outcomes()
            .iter()
            .any(|outcome| outcome.assertion.name == "disabled-node-marker")
    );
}

#[test]
fn guest_marker_assertion_implementation_is_observational_and_deterministic() {
    let trigger = concat!(
        include_str!("../src/trigger/conditions.rs"),
        include_str!("../src/trigger/assertions.rs"),
        include_str!("../src/trigger/evaluation.rs"),
    );
    let marker_block = trigger
        .split("pub enum GuestAssertionKind")
        .nth(1)
        .expect("guest assertion marker kind should exist")
        .split("/// Host-authored resolver for assertion leaves")
        .next()
        .expect("host assertion resolver follows guest assertion marker payload");

    for required in [
        "pub id: AssertionId",
        "pub kind: GuestAssertionKind",
        "pub condition: bool",
        "pub must_hit: bool",
        "pub details: Vec<GuestAssertionDetail>",
        "pub location: String",
    ] {
        assert!(
            marker_block.contains(required),
            "guest assertion marker implementation must include {required}"
        );
    }
    for required in [
        "GuestAssertionKind::Always",
        "GuestAssertionKind::Sometimes",
        "GuestAssertionKind::Reachable",
        "GuestAssertionKind::Unreachable",
        "white_box_policies",
        "with_guest_assertion_catalog",
    ] {
        assert!(
            trigger.contains(required),
            "guest assertion marker implementation must include {required}"
        );
    }
    assert!(
        trigger.contains("ObservableEventPayload::GuestAssertionMarker { .. } => false"),
        "assertion marker events must not satisfy trigger guest-marker leaves"
    );
    for forbidden in [
        "HashMap",
        "HashSet",
        "SystemTime",
        "Instant",
        "std::time",
        "thread_rng",
        "rand::",
        "Decision::",
    ] {
        assert!(
            !marker_block.contains(forbidden),
            "guest assertion marker implementation must remain observational and deterministic: {forbidden}"
        );
    }
}
