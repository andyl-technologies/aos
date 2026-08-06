//! Checks T-TRIG-19 black-box-first complete trigger scenarios.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, AssertionDef, AssertionId, AssertionPhase, AssertionRunVerdict,
    AssertionVerdictFailure, CodePoint, ComposedRunVerdict, ComposedRunVerdictFailure,
    ConditionLeaf, ConditionLeafOracle, EventGraph, EventGraphState, FramePredicate, Icount,
    LinkDef, LinkId, LogLevel, MarkerId, NodeId, NodeLifecycle, NodeTemplate, ObservableEvent,
    Plan, Predicate, Properties, Property, ReadyPoint, RegexProgram,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, SchedulerLivenessScenario, Seed,
    Shift, SimDuration, SimInstant, SingleScheduler, TimerId, TriggerActionState, VirtualTime,
    VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn assertion(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn event(name: &str) -> &str {
    name
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_string(),
    }
}

fn timer(name: &str) -> TimerId {
    TimerId {
        name: name.to_string(),
    }
}

fn link(name: &str) -> LinkId {
    LinkId::from_name(name)
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

fn black_box_world() -> World {
    world_with_policy(WhiteBoxPolicy::Disabled)
}

fn white_box_world() -> World {
    world_with_policy(WhiteBoxPolicy::Enabled)
}

fn world_with_policy(white_box: WhiteBoxPolicy) -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0", white_box), ready_node("db-1", white_box)],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("black-box test world should build")
}

fn scenario(name: &str, world: &World) -> SchedulerLivenessScenario {
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

fn black_box_readiness() -> Predicate {
    Predicate::all_of(vec![
        Predicate::console_match(
            node("db-0"),
            RegexProgram::from_pattern("ready to accept connections"),
        ),
        Predicate::console_match(
            node("db-1"),
            RegexProgram::from_pattern("ready to accept connections"),
        ),
        Predicate::once(Predicate::coverage_point(
            node("db-0"),
            CodePoint::guest_address(0x4010),
        )),
    ])
}

fn readiness_condition(include_guest_marker: bool) -> Predicate {
    let readiness = black_box_readiness();
    if include_guest_marker {
        Predicate::any_of(vec![readiness, Predicate::guest_marker(marker("ready"))])
    } else {
        readiness
    }
}

fn properties(world: &World) -> Properties {
    Properties::from_assertions_for_world(
        world,
        vec![AssertionDef {
            id: assertion("cluster-safe"),
            message: String::from("cluster remains in a started state"),
            property: Property::Always {
                predicate: Predicate::node_state(node("db-0"), NodeLifecycle::Started),
            },
        }],
    )
    .expect("black-box properties should validate")
}

fn graph(world: &World, include_guest_marker: bool) -> EventGraph {
    EventGraph::builder()
        .event(event("wait-ready"))
        .when(readiness_condition(include_guest_marker))
        .action(Action::group(vec![
            Action::log(LogLevel::Info, "recovery timer armed"),
            Action::arm_timer(timer("recovery-after"), duration(30)),
        ]))
        .event(event("timer-observed"))
        .when(Predicate::timer(timer("recovery-after")))
        .action(Action::log(LogLevel::Info, "recovery timer observed"))
        .event(event("fail-on-property-violation"))
        .when(Predicate::assertion_state(
            assertion("cluster-safe"),
            AssertionPhase::Violated,
        ))
        .action(Action::fail("cluster-safe assertion violated"))
        .event(event("pass-on-black-box-convergence"))
        .when(Predicate::all_of(vec![
            Predicate::assertion_state(assertion("cluster-safe"), AssertionPhase::Satisfied),
            Predicate::network_match(
                Some(link("db-0--db-1")),
                FramePredicate::contains(b"raft:converged".to_vec()),
            ),
            Predicate::node_state(node("db-0"), NodeLifecycle::Started),
        ]))
        .action(Action::pass())
        .build_with_assertions_for_world([assertion("cluster-safe")], world)
        .expect("black-box-first event graph should validate")
}

fn plan(world: &World, include_guest_marker: bool) -> Plan {
    Plan::from_event_graph_with_assertions_for_world(
        world,
        [assertion("cluster-safe")],
        graph(world, include_guest_marker),
    )
    .expect("black-box graph plan should validate")
}

fn readiness_observations() -> Vec<ObservableEvent> {
    vec![
        ObservableEvent::console_output(
            time(10),
            node("db-0"),
            b"db-0 ready to accept connections\n".to_vec(),
        ),
        ObservableEvent::console_output(
            time(10),
            node("db-1"),
            b"db-1 ready to accept connections\n".to_vec(),
        ),
        ObservableEvent::coverage_block(icount(10), node("db-0"), 0x4000, 0x20),
    ]
}

fn convergence_observations() -> Vec<ObservableEvent> {
    vec![
        ObservableEvent::assertion_state_changed(
            time(50),
            assertion("cluster-safe"),
            AssertionPhase::Satisfied,
        ),
        ObservableEvent::network_delivered(
            time(50),
            Some(link("db-0--db-1")),
            b"raft:converged:term=7".to_vec(),
        ),
        ObservableEvent::node_state(time(50), node("db-0"), NodeLifecycle::Started),
    ]
}

fn violation_observations() -> Vec<ObservableEvent> {
    vec![ObservableEvent::assertion_state_changed(
        time(20),
        assertion("cluster-safe"),
        AssertionPhase::Violated,
    )]
}

fn assertion_failure(name: &str, at: u64, reason: &str) -> AssertionVerdictFailure {
    AssertionVerdictFailure::new(assertion(name), time(at), reason)
}

struct NoGuestSideLeaves;

impl ConditionLeafOracle for NoGuestSideLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("black-box-first scenario must not depend on guest-side leaf fallback")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BlackBoxRun {
    trigger_actions: TriggerActionState,
    verdict: ComposedRunVerdict,
    offline_verdict: ComposedRunVerdict,
    segment_bytes: Vec<Vec<u8>>,
}

fn fired_names(firings: &crucible::EventFirings) -> Vec<&str> {
    firings
        .iter()
        .map(|firing| firing.event().name.as_str())
        .collect()
}

fn append_boundary(scheduler: &mut SingleScheduler, ticks: u64) -> Vec<u8> {
    scheduler
        .append_evaluation_boundary(time(ticks), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("evaluation boundary should append")
        .segment_bytes
}

fn run_complete_black_box_scenario(name: &str, world: &World, graph: &EventGraph) -> BlackBoxRun {
    let mut scheduler = SingleScheduler::new(scenario(name, world)).expect("scheduler builds");
    let mut graph_state = EventGraphState::new();
    let mut segment_bytes = Vec::new();
    let mut trigger_log = Vec::<SchedulerEventLogEntry>::new();

    let ready_observations = scheduler
        .append_observable_events(readiness_observations())
        .expect("readiness observations should append");
    segment_bytes.push(ready_observations.segment_bytes);

    let ready = scheduler.evaluate_event_graph(graph, &mut graph_state, NoGuestSideLeaves);
    assert_eq!(fired_names(&ready), vec!["wait-ready"]);
    let ready_append = scheduler
        .apply_trigger_firings(&ready)
        .expect("readiness action should apply");
    segment_bytes.push(ready_append.segment_bytes);
    trigger_log.extend(ready_append.entries);
    segment_bytes.push(append_boundary(&mut scheduler, 40));
    let timer = scheduler.evaluate_event_graph(graph, &mut graph_state, NoGuestSideLeaves);
    assert_eq!(fired_names(&timer), vec!["timer-observed"]);
    let timer_append = scheduler
        .apply_trigger_firings(&timer)
        .expect("timer action should apply");
    segment_bytes.push(timer_append.segment_bytes);
    trigger_log.extend(timer_append.entries);

    let convergence = scheduler
        .append_observable_events(convergence_observations())
        .expect("convergence observations should append");
    segment_bytes.push(convergence.segment_bytes);

    let pass = scheduler.evaluate_event_graph(graph, &mut graph_state, NoGuestSideLeaves);
    assert_eq!(fired_names(&pass), vec!["pass-on-black-box-convergence"]);
    let pass_append = scheduler
        .apply_trigger_firings(&pass)
        .expect("pass action should apply");
    segment_bytes.push(pass_append.segment_bytes);
    trigger_log.extend(pass_append.entries);

    let verdict = scheduler
        .trigger_actions()
        .compose_run_verdict(AssertionRunVerdict::passed());
    let offline_verdict = TriggerActionState::compose_run_verdict_from_event_log(
        &trigger_log,
        AssertionRunVerdict::passed(),
    )
    .expect("trigger verdict should replay from event log");
    assert!(matches!(verdict, ComposedRunVerdict::Passed { .. }));
    assert_eq!(verdict, offline_verdict);

    BlackBoxRun {
        trigger_actions: scheduler.trigger_actions().clone(),
        verdict,
        offline_verdict,
        segment_bytes,
    }
}

fn run_black_box_violation_path(name: &str, world: &World, graph: &EventGraph) -> BlackBoxRun {
    let mut scheduler = SingleScheduler::new(scenario(name, world)).expect("scheduler builds");
    let mut graph_state = EventGraphState::new();
    let mut segment_bytes = Vec::new();
    let mut trigger_log = Vec::<SchedulerEventLogEntry>::new();

    let ready_observations = scheduler
        .append_observable_events(readiness_observations())
        .expect("readiness observations should append");
    segment_bytes.push(ready_observations.segment_bytes);

    let ready = scheduler.evaluate_event_graph(graph, &mut graph_state, NoGuestSideLeaves);
    assert_eq!(fired_names(&ready), vec!["wait-ready"]);
    let ready_append = scheduler
        .apply_trigger_firings(&ready)
        .expect("readiness action should apply");
    segment_bytes.push(ready_append.segment_bytes);
    trigger_log.extend(ready_append.entries);

    let violation = scheduler
        .append_observable_events(violation_observations())
        .expect("violation observations should append");
    segment_bytes.push(violation.segment_bytes);

    let fail = scheduler.evaluate_event_graph(graph, &mut graph_state, NoGuestSideLeaves);
    assert_eq!(fired_names(&fail), vec!["fail-on-property-violation"]);
    let fail_append = scheduler
        .apply_trigger_firings(&fail)
        .expect("fail action should apply");
    segment_bytes.push(fail_append.segment_bytes);
    trigger_log.extend(fail_append.entries);
    assert!(scheduler.trigger_actions().termination_requested);

    let assertions = AssertionRunVerdict::failed(vec![assertion_failure(
        "cluster-safe",
        20,
        "cluster-safe assertion violated",
    )]);
    let verdict = scheduler
        .trigger_actions()
        .compose_run_verdict(assertions.clone());
    let offline_verdict =
        TriggerActionState::compose_run_verdict_from_event_log(&trigger_log, assertions)
            .expect("trigger fail verdict should replay from event log");
    assert_eq!(verdict, offline_verdict);

    let ComposedRunVerdict::Failed { failures } = &verdict else {
        panic!("property violation and trigger Fail should fail the run");
    };
    assert!(failures.iter().any(|failure| {
        matches!(
            failure,
            ComposedRunVerdictFailure::Trigger(trigger)
                if trigger.event.name == "fail-on-property-violation"
                    && trigger.failed_reason.as_deref()
                        == Some("cluster-safe assertion violated")
        )
    }));

    BlackBoxRun {
        trigger_actions: scheduler.trigger_actions().clone(),
        verdict,
        offline_verdict,
        segment_bytes,
    }
}

fn predicate_has_guest_marker(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::GuestMarker { .. } => true,
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            predicates.iter().any(predicate_has_guest_marker)
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            predicate_has_guest_marker(predicate)
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
        | Predicate::Named { .. } => false,
    }
}

fn graph_has_guest_marker(graph: &EventGraph) -> bool {
    graph
        .events()
        .iter()
        .filter_map(|event| event.trigger.as_ref())
        .any(predicate_has_guest_marker)
}

fn properties_have_guest_marker(properties: &Properties) -> bool {
    properties
        .assertions()
        .iter()
        .any(|assertion| match &assertion.property {
            Property::Always { predicate }
            | Property::Sometimes { predicate }
            | Property::AfterQuiescence { predicate }
            | Property::Reachable { predicate, .. } => predicate_has_guest_marker(predicate),
            Property::Eventually {
                trigger, property, ..
            } => predicate_has_guest_marker(trigger) || predicate_has_guest_marker(property),
        })
}

#[test]
fn complete_black_box_scenario_runs_deterministically_without_guest_marker() {
    let world = black_box_world();
    let properties = properties(&world);
    let plan = plan(&world, false);
    let graph = plan.event_graph();

    assert!(!graph_has_guest_marker(graph));
    assert!(!properties_have_guest_marker(&properties));
    assert!(
        world
            .vm_nodes()
            .iter()
            .all(|node| node.white_box == WhiteBoxPolicy::Disabled)
    );
    crucible::ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(0x19))
        .expect("complete black-box scenario form should validate");

    let left = run_complete_black_box_scenario("black-box-first", &world, graph);
    let right = run_complete_black_box_scenario("black-box-first", &world, graph);

    assert_eq!(left, right);
}

#[test]
fn black_box_property_violation_fails_deterministically_without_guest_marker() {
    let world = black_box_world();
    let plan = plan(&world, false);
    let graph = plan.event_graph();

    assert!(!graph_has_guest_marker(graph));
    let left = run_black_box_violation_path("black-box-first-violation", &world, graph);
    let right = run_black_box_violation_path("black-box-first-violation", &world, graph);

    assert_eq!(left, right);
}

#[test]
fn removing_guest_marker_conditions_leaves_functional_graph() {
    let enriched_world = white_box_world();
    let enriched_graph = graph(&enriched_world, true);
    assert!(graph_has_guest_marker(&enriched_graph));
    let enriched =
        run_complete_black_box_scenario("guest-marker-additive", &enriched_world, &enriched_graph);

    let stripped_world = black_box_world();
    let stripped_graph = graph(&stripped_world, false);
    assert!(!graph_has_guest_marker(&stripped_graph));
    let stripped =
        run_complete_black_box_scenario("guest-marker-additive", &stripped_world, &stripped_graph);

    assert_eq!(enriched.trigger_actions, stripped.trigger_actions);
    assert_eq!(enriched.verdict, stripped.verdict);
    assert_eq!(enriched.offline_verdict, stripped.offline_verdict);
}
