//! Checks T-GHC-11 emitter absence for black-box determinism.

#![cfg(feature = "test-double")]
#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use crucible::{
    Action, AdvanceOutcome, AssertionId, Backend, BackendInput, BlackBoxObservationKind, CodePoint,
    ComposedRunVerdict, ConditionLeaf, ConditionLeafOracle, ContentHash, Decision, EventClass,
    EventGraph, EventGraphState, ExecutionFingerprint, ExecutionHorizon, FaultTag, FramePredicate,
    Icount, IoEventKind, LinkDef, LinkId, MembershipFault, NodeId, NodeLifecycle, NodeTemplate,
    ObservableEvent, ObservableEventPayload, OfflineAssertionChecker, PartitionDirection, Plan,
    Predicate, Properties, Property, ReachabilityExpectation, ReachableDisposition, ReadyPoint,
    RegexProgram, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerLivenessScenario, Seed, Shift, SimBackend, SimDuration,
    SimInstant, SingleScheduler, TimerId, TriggerActionState, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode, compare_event_log_determinism, event_log_causal_projection,
    event_log_coverage_projection,
};

#[test]
fn emitter_absence_preserves_black_box_determinism_faults_coverage_and_io() {
    let absent_world = absence_world(WhiteBoxPolicy::Disabled);
    let absent_properties = absence_properties(&absent_world);
    let absent_graph = absence_graph(&absent_world);
    let absent_plan = absence_plan(&absent_world, absent_graph.clone());

    assert_world_has_no_guest_content(&absent_world, WhiteBoxPolicy::Disabled);
    assert!(!graph_has_guest_side_leaf(&absent_graph));
    assert!(!properties_have_guest_side_leaf(&absent_properties));
    crucible::ScenarioDefForm::from_components(
        &absent_world,
        &absent_plan,
        &absent_properties,
        Seed::from_u64(0x16_11),
    )
    .expect("emitter-absent scenario form should validate");

    let first = run_absence_scenario(
        "emitter-absent",
        &absent_world,
        &absent_graph,
        &absent_properties,
    );
    let second = run_absence_scenario(
        "emitter-absent",
        &absent_world,
        &absent_graph,
        &absent_properties,
    );

    assert_eq!(
        first, second,
        "no-emitter runs must retain identical determinism, fault, coverage, I/O, and backend material"
    );
    assert_absence_material(&first);
    assert_event_log_determinism_matches(&first.event_log, &second.event_log);

    let enabled_world = absence_world(WhiteBoxPolicy::Enabled);
    let enabled_properties = absence_properties(&enabled_world);
    let enabled_graph = absence_graph(&enabled_world);
    let enabled_plan = absence_plan(&enabled_world, enabled_graph.clone());

    assert_world_has_no_guest_content(&enabled_world, WhiteBoxPolicy::Enabled);
    assert!(!graph_has_guest_side_leaf(&enabled_graph));
    assert!(!properties_have_guest_side_leaf(&enabled_properties));
    crucible::ScenarioDefForm::from_components(
        &enabled_world,
        &enabled_plan,
        &enabled_properties,
        Seed::from_u64(0x16_11),
    )
    .expect("emitter-capable unused scenario form should validate");

    let enabled_unused = run_absence_scenario(
        "emitter-capable-unused",
        &enabled_world,
        &enabled_graph,
        &enabled_properties,
    );

    assert_absence_material(&enabled_unused);
    assert_eq!(
        first.behavior_material(),
        enabled_unused.behavior_material(),
        "enabling the white-box channel without guest content or markers must not perturb black-box behavior material"
    );
}

fn assert_absence_material(material: &AbsenceRunMaterial) {
    assert_no_guest_marker_entries(&material.event_log);
    assert_observed_payloads(&material.event_log);
    assert_eq!(
        material.observed_surface,
        BTreeSet::from([
            BlackBoxObservationKind::NetworkTraffic,
            BlackBoxObservationKind::DiskOrNinePIo,
            BlackBoxObservationKind::ConsoleSerialOutput,
            BlackBoxObservationKind::BasicBlockCoverage,
            BlackBoxObservationKind::RunOutcome,
        ])
    );
    assert_eq!(material.coverage_entries, 1);
    assert_eq!(
        material.fault_snapshots,
        vec![
            vec![String::from("split")],
            Vec::<String>::new(),
            Vec::<String>::new(),
        ]
    );
    assert!(matches!(
        material.verdict,
        ComposedRunVerdict::Passed { .. }
    ));
}

fn assert_event_log_determinism_matches(
    expected: &[SchedulerEventLogEntry],
    reproduced: &[SchedulerEventLogEntry],
) {
    let comparison = compare_event_log_determinism(expected, reproduced);
    assert!(
        comparison.passes(),
        "emitter absence should preserve event-log determinism"
    );
    assert_eq!(
        comparison.expected().canonical_bytes(),
        comparison.reproduced().canonical_bytes()
    );
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AbsenceRunMaterial {
    configuration: ContentHash,
    decisions: Vec<Decision>,
    causal_event_log_fingerprint: ContentHash,
    coverage_fingerprint: ContentHash,
    coverage_entries: usize,
    observed_surface: BTreeSet<BlackBoxObservationKind>,
    fault_snapshots: Vec<Vec<String>>,
    trigger_actions: TriggerActionState,
    verdict: ComposedRunVerdict,
    backend_fingerprint: ExecutionFingerprint,
    event_log: Vec<SchedulerEventLogEntry>,
    segment_bytes: Vec<Vec<u8>>,
}

impl AbsenceRunMaterial {
    fn behavior_material(&self) -> AbsenceBehaviorMaterial {
        AbsenceBehaviorMaterial {
            causal_event_log_fingerprint: self.causal_event_log_fingerprint,
            coverage_fingerprint: self.coverage_fingerprint,
            coverage_entries: self.coverage_entries,
            observed_surface: self.observed_surface.clone(),
            fault_snapshots: self.fault_snapshots.clone(),
            trigger_actions: self.trigger_actions.clone(),
            verdict: self.verdict.clone(),
            backend_fingerprint: self.backend_fingerprint.clone(),
            event_log: self.event_log.clone(),
            segment_bytes: self.segment_bytes.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AbsenceBehaviorMaterial {
    causal_event_log_fingerprint: ContentHash,
    coverage_fingerprint: ContentHash,
    coverage_entries: usize,
    observed_surface: BTreeSet<BlackBoxObservationKind>,
    fault_snapshots: Vec<Vec<String>>,
    trigger_actions: TriggerActionState,
    verdict: ComposedRunVerdict,
    backend_fingerprint: ExecutionFingerprint,
    event_log: Vec<SchedulerEventLogEntry>,
    segment_bytes: Vec<Vec<u8>>,
}

fn run_absence_scenario(
    name: &str,
    world: &World,
    graph: &EventGraph,
    properties: &Properties,
) -> AbsenceRunMaterial {
    let mut scheduler = SingleScheduler::new(absence_scheduler(name, world))
        .expect("emitter-absent scheduler should build");
    let mut state = EventGraphState::new();
    let mut event_log = Vec::new();
    let mut segment_bytes = Vec::new();
    let mut fault_snapshots = Vec::new();

    record_append(
        scheduler
            .append_observable_events(readiness_observations())
            .expect("black-box readiness observations should append"),
        &mut event_log,
        &mut segment_bytes,
    );
    let ready = scheduler.evaluate_event_graph(graph, &mut state, NoGuestSideLeaves);
    assert_eq!(fired_names(&ready), vec!["wait-ready"]);
    record_append(
        scheduler
            .apply_trigger_firings(&ready)
            .expect("readiness fault action should apply"),
        &mut event_log,
        &mut segment_bytes,
    );
    fault_snapshots.push(active_fault_names(scheduler.trigger_actions()));

    record_append(
        scheduler
            .append_evaluation_boundary(time(40), SchedulerEvaluationBoundaryKind::Quantum)
            .expect("timer boundary should append"),
        &mut event_log,
        &mut segment_bytes,
    );
    let heal = scheduler.evaluate_event_graph(graph, &mut state, NoGuestSideLeaves);
    assert_eq!(fired_names(&heal), vec!["heal"]);
    record_append(
        scheduler
            .apply_trigger_firings(&heal)
            .expect("fault heal action should apply"),
        &mut event_log,
        &mut segment_bytes,
    );
    fault_snapshots.push(active_fault_names(scheduler.trigger_actions()));

    record_append(
        scheduler
            .append_observable_events(convergence_observations())
            .expect("black-box convergence observations should append"),
        &mut event_log,
        &mut segment_bytes,
    );
    let pass = scheduler.evaluate_event_graph(graph, &mut state, NoGuestSideLeaves);
    assert_eq!(fired_names(&pass), vec!["pass-on-black-box-io"]);
    record_append(
        scheduler
            .apply_trigger_firings(&pass)
            .expect("black-box pass action should apply"),
        &mut event_log,
        &mut segment_bytes,
    );
    fault_snapshots.push(active_fault_names(scheduler.trigger_actions()));

    let coverage_projection = event_log_coverage_projection(&event_log);
    assert!(
        !coverage_projection.is_empty(),
        "coverage observations must remain available without the emitter"
    );

    let assertion_report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(world)
        .check_run(properties, &event_log)
        .expect("host-side assertions should evaluate from the no-emitter event log");
    let verdict = scheduler
        .trigger_actions()
        .compose_run_verdict(assertion_report.verdict().clone());

    AbsenceRunMaterial {
        configuration: scheduler.configuration().id(),
        decisions: scheduler.configuration().schedule.decisions().to_vec(),
        causal_event_log_fingerprint: event_log_causal_projection(&event_log).content_hash(),
        coverage_fingerprint: coverage_projection.content_hash(),
        coverage_entries: coverage_projection.len(),
        observed_surface: scheduler
            .condition_event_log_prefix()
            .black_box_observation_kinds()
            .clone(),
        fault_snapshots,
        trigger_actions: scheduler.trigger_actions().clone(),
        verdict,
        backend_fingerprint: backend_fingerprint_without_emitter(),
        event_log,
        segment_bytes,
    }
}

fn record_append(
    append: crucible::SchedulerEventLogAppend,
    event_log: &mut Vec<SchedulerEventLogEntry>,
    segment_bytes: &mut Vec<Vec<u8>>,
) {
    segment_bytes.push(append.segment_bytes);
    event_log.extend(append.entries);
}

fn backend_fingerprint_without_emitter() -> ExecutionFingerprint {
    let mut backend = SimBackend::new();
    backend
        .deliver_input(BackendInput {
            node: node("db-0"),
            payload: b"black-box workload".to_vec(),
        })
        .expect("backend input should deliver without guest emitter content");
    assert_eq!(
        backend.advance_to_horizon(ExecutionHorizon {
            icount: icount(2048),
        }),
        Ok(AdvanceOutcome::ReachedHorizon)
    );
    backend
        .fingerprint()
        .expect("backend fingerprint should read without guest emitter content")
}

fn absence_world(white_box: WhiteBoxPolicy) -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0", white_box), ready_node("db-1", white_box)],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("emitter-absent world should build")
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

fn absence_scheduler(name: &str, world: &World) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        shift(0),
        16,
        SimInstant { nanos: 100 },
        Vec::new(),
        Vec::new(),
    )
    .with_trigger_world(world)
}

fn absence_properties(world: &World) -> Properties {
    Properties::from_assertions_for_world(
        world,
        vec![
            crucible::AssertionDef {
                id: assertion("db-started"),
                message: String::from("db-0 reaches started state"),
                property: Property::Reachable {
                    predicate: Predicate::node_state(node("db-0"), NodeLifecycle::Started),
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Fail,
                    },
                },
            },
            crucible::AssertionDef {
                id: assertion("black-box-observables"),
                message: String::from("black-box console, network, coverage, and I/O are visible"),
                property: Property::Reachable {
                    predicate: Predicate::all_of(vec![
                        Predicate::console_match(
                            node("db-0"),
                            RegexProgram::from_pattern("ready without guest emitter"),
                        ),
                        Predicate::network_match(
                            Some(link("db-0--db-1")),
                            FramePredicate::contains(b"raft:append".to_vec()),
                        ),
                        Predicate::coverage_point(node("db-0"), CodePoint::guest_address(0x4010)),
                        Predicate::io_pattern(node("db-0"), IoEventKind::Fsync),
                    ]),
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Fail,
                    },
                },
            },
        ],
    )
    .expect("host-side absence properties should validate")
}

fn absence_plan(world: &World, graph: EventGraph) -> Plan {
    Plan::from_event_graph_with_assertions_for_world(
        world,
        [assertion("db-started"), assertion("black-box-observables")],
        graph,
    )
    .expect("emitter-absent event graph plan should validate")
}

fn absence_graph(world: &World) -> EventGraph {
    EventGraph::builder()
        .event("wait-ready")
        .when(Predicate::all_of(vec![
            Predicate::console_match(
                node("db-0"),
                RegexProgram::from_pattern("ready without guest emitter"),
            ),
            Predicate::network_match(
                Some(link("db-0--db-1")),
                FramePredicate::contains(b"raft:append".to_vec()),
            ),
            Predicate::coverage_point(node("db-0"), CodePoint::guest_address(0x4010)),
            Predicate::io_pattern(node("db-0"), IoEventKind::Fsync),
            Predicate::node_state(node("db-0"), NodeLifecycle::Started),
        ]))
        .action(Action::group(vec![
            Action::inject_fault(tag("split"), split_fault()),
            Action::arm_timer(timer("heal-after"), duration(30)),
        ]))
        .event("heal")
        .when(Predicate::all_of(vec![
            Predicate::timer(timer("heal-after")),
            Predicate::fault_active(tag("split")),
        ]))
        .action(Action::heal_fault(tag("split")))
        .event("pass-on-black-box-io")
        .when(Predicate::all_of(vec![
            Predicate::network_match(
                Some(link("db-0--db-1")),
                FramePredicate::contains(b"raft:converged".to_vec()),
            ),
            Predicate::io_pattern(node("db-0"), IoEventKind::BlockWrite),
            Predicate::node_state(node("db-0"), NodeLifecycle::Started),
        ]))
        .action(Action::pass())
        .build_with_assertions_for_world(
            [assertion("db-started"), assertion("black-box-observables")],
            world,
        )
        .expect("emitter-absent graph should validate")
}

fn readiness_observations() -> Vec<ObservableEvent> {
    vec![
        ObservableEvent::console_output(
            time(10),
            node("db-0"),
            b"db-0 ready without guest emitter\n".to_vec(),
        ),
        ObservableEvent::network_delivered(
            time(10),
            Some(link("db-0--db-1")),
            b"raft:append:term=7".to_vec(),
        ),
        ObservableEvent::coverage_block(icount(10), node("db-0"), 0x4000, 0x20),
        ObservableEvent::io_completion(time(10), node("db-0"), IoEventKind::Fsync, b"ok".to_vec()),
        ObservableEvent::node_state(time(10), node("db-0"), NodeLifecycle::Started),
    ]
}

fn convergence_observations() -> Vec<ObservableEvent> {
    vec![
        ObservableEvent::network_delivered(
            time(50),
            Some(link("db-0--db-1")),
            b"raft:converged:term=7".to_vec(),
        ),
        ObservableEvent::io_completion(
            time(50),
            node("db-0"),
            IoEventKind::BlockWrite,
            b"flush=done".to_vec(),
        ),
        ObservableEvent::node_state(time(50), node("db-0"), NodeLifecycle::Started),
    ]
}

fn assert_world_has_no_guest_content(world: &World, white_box: WhiteBoxPolicy) {
    for node in world.vm_nodes() {
        assert_eq!(node.white_box, white_box);
        assert!(node.cmdline.is_empty());
        assert!(matches!(node.ready_point, ReadyPoint::FixedIcount { .. }));
        assert!(node.kernel.is_none());
        assert!(node.root_image.is_none());
        assert!(node.initrd.is_none());
    }
}

fn graph_has_guest_side_leaf(graph: &EventGraph) -> bool {
    graph
        .events()
        .iter()
        .filter_map(|event| event.trigger.as_ref())
        .any(predicate_has_guest_side_leaf)
}

fn properties_have_guest_side_leaf(properties: &Properties) -> bool {
    properties
        .assertions()
        .iter()
        .any(|assertion| match &assertion.property {
            Property::Always { predicate }
            | Property::Sometimes { predicate }
            | Property::AfterQuiescence { predicate }
            | Property::Reachable { predicate, .. } => predicate_has_guest_side_leaf(predicate),
            Property::Eventually {
                trigger, property, ..
            } => predicate_has_guest_side_leaf(trigger) || predicate_has_guest_side_leaf(property),
        })
}

fn predicate_has_guest_side_leaf(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::Named { .. } | Predicate::GuestMarker { .. } => true,
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            predicates.iter().any(predicate_has_guest_side_leaf)
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            predicate_has_guest_side_leaf(predicate)
        }
        Predicate::At { .. }
        | Predicate::After { .. }
        | Predicate::Timer { .. }
        | Predicate::NetworkMatch { .. }
        | Predicate::ConsoleMatch { .. }
        | Predicate::CoveragePoint { .. }
        | Predicate::MemoryPredicate { .. }
        | Predicate::IoPattern { .. }
        | Predicate::NodeState { .. }
        | Predicate::AssertionState { .. }
        | Predicate::Quiescent
        | Predicate::FaultActive { .. } => false,
    }
}

fn assert_no_guest_marker_entries(event_log: &[SchedulerEventLogEntry]) {
    for entry in event_log {
        if let SchedulerEventLogPayload::Observable(
            ObservableEventPayload::GuestMarker { .. }
            | ObservableEventPayload::GuestAssertionMarker { .. }
            | ObservableEventPayload::CoverageMarker { .. },
        ) = entry.payload()
        {
            panic!("no-emitter proof must not contain guest marker entries: {entry:?}");
        }
    }
}

fn assert_observed_payloads(event_log: &[SchedulerEventLogEntry]) {
    let payloads = event_log
        .iter()
        .filter(|entry| entry.class() == EventClass::Observational)
        .filter_map(|entry| match entry.payload() {
            SchedulerEventLogPayload::Observable(payload) => Some(payload),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(
        payloads
            .iter()
            .any(|payload| matches!(payload, ObservableEventPayload::ConsoleOutput { .. }))
    );
    assert!(
        payloads
            .iter()
            .any(|payload| matches!(payload, ObservableEventPayload::NetworkDelivered { .. }))
    );
    assert!(
        payloads
            .iter()
            .any(|payload| matches!(payload, ObservableEventPayload::IoCompletion { .. }))
    );
    assert!(payloads.iter().any(|payload| matches!(
        payload,
        ObservableEventPayload::CoverageBlock {
            guest_pc: 0x4000,
            block_len: 0x20,
            ..
        }
    )));
    assert!(
        payloads
            .iter()
            .any(|payload| matches!(payload, ObservableEventPayload::NodeState { .. }))
    );
}

struct NoGuestSideLeaves;

impl ConditionLeafOracle for NoGuestSideLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("emitter absence proof must not consult guest-side leaf fallback")
            }
        }
    }
}

fn fired_names(firings: &crucible::EventFirings) -> Vec<&str> {
    firings
        .iter()
        .map(|firing| firing.event().name.as_str())
        .collect()
}

fn active_fault_names(actions: &TriggerActionState) -> Vec<String> {
    actions
        .active_faults
        .keys()
        .map(|tag| tag.name.clone())
        .collect()
}

fn split_fault() -> MembershipFault {
    MembershipFault::Partition {
        endpoint_a: node("db-0"),
        endpoint_b: node("db-1"),
        direction: PartitionDirection::Bidirectional,
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn link(name: &str) -> LinkId {
    LinkId::from_name(name)
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
}

fn timer(name: &str) -> TimerId {
    TimerId {
        name: name.to_owned(),
    }
}

fn assertion(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn shift(bits: u8) -> Shift {
    Shift { bits }
}
