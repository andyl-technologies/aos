//! Checks T-TRIG-7 assertion-state and scheduler-quiescence leaves.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use crucible::{
    Action, AssertionDef, AssertionId, AssertionPhase, ConditionEvaluationPass, ConditionLeaf,
    ConditionLeafOracle, EngineError, Event, EventGraph, EventGraphError, EventGraphState, EventId,
    ExactLocalEvent, Icount, NetworkLookahead, NodeCounter, NodeId, NodeTemplate, ObservableEvent,
    ObservableEventPayload, Predicate, Properties, Property, ReadyPoint, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerNodeVcpuIdleSnapshot, SchedulerQuiescence,
    SchedulerQuiescenceBlocker, SchedulerScenarioNode, SchedulerVcpuIdleState, SchedulingNodeKind,
    Shift, SimDuration, SimInstant, SingleScheduler, VcpuId, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode,
};

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

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

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}

fn evaluator(ticks: u64, events: Vec<ObservableEvent>) -> ConditionEvaluationPass<NoNamedLeaves> {
    support::evaluation_with_observables(ticks, events, NoNamedLeaves)
}

fn assertion(id: &str, predicate: Predicate) -> AssertionDef {
    AssertionDef {
        id: assertion_id(id),
        message: format!("{id} observed"),
        property: Property::Always { predicate },
    }
}

fn ready_node(name: &str) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn world() -> World {
    World::from_nodes(vec![ready_node("server")])
        .expect("assertion/quiescence test world should build")
}

fn halted_vcpu(index: u32) -> SchedulerVcpuIdleState {
    SchedulerVcpuIdleState {
        vcpu: VcpuId { index },
        halted: true,
        next_deadline: None,
        pending_input: false,
    }
}

fn vcpu_snapshot(name: &str, vcpus: Vec<SchedulerVcpuIdleState>) -> SchedulerNodeVcpuIdleSnapshot {
    let vcpu_count = vcpus
        .len()
        .try_into()
        .expect("test VCPU count should fit in u32");
    SchedulerNodeVcpuIdleSnapshot::new(scheduler_node(name), vcpu_count, vcpus)
        .expect("VCPU snapshot should be valid")
}

fn quiescent_scheduler() -> SingleScheduler {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "assertion-quiescence-leaf-scheduler",
        shift(0),
        16,
        SimInstant { nanos: 64 },
        vec![SchedulerScenarioNode {
            id: scheduler_node("server"),
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Idle,
            network_lookahead: NetworkLookahead::Finite(SimDuration { nanos: 8 }),
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    )
    .with_vcpu_idle_snapshot(vcpu_snapshot("server", vec![halted_vcpu(0)]))
    .expect("VCPU snapshot should layer over scheduler scenario");
    SingleScheduler::new(scenario).expect("quiescent scheduler should build")
}

fn properties_for(assertion_name: &str, predicate: Predicate) -> Properties {
    Properties::from_assertions_for_world(&world(), vec![assertion(assertion_name, predicate)])
        .expect("assertion/quiescence properties should validate")
}

struct NoNamedLeaves;

impl ConditionLeafOracle for NoNamedLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!(
                    "assertion-state and quiescence leaves must not require named or guest-marker resolution"
                )
            }
        }
    }
}

#[test]
fn assertion_state_observes_current_causal_entry() {
    let condition =
        Predicate::assertion_state(assertion_id("leader-elected"), AssertionPhase::Satisfied);
    let matching = ObservableEvent::assertion_state_changed(
        time(42),
        assertion_id("leader-elected"),
        AssertionPhase::Satisfied,
    );
    let wrong_state = ObservableEvent::assertion_state_changed(
        time(42),
        assertion_id("leader-elected"),
        AssertionPhase::Violated,
    );
    let wrong_assertion = ObservableEvent::assertion_state_changed(
        time(42),
        assertion_id("log-matches"),
        AssertionPhase::Satisfied,
    );
    let wrong_time = ObservableEvent::assertion_state_changed(
        time(41),
        assertion_id("leader-elected"),
        AssertionPhase::Satisfied,
    );

    assert!(
        evaluator(42, vec![wrong_time, wrong_state, wrong_assertion, matching])
            .evaluate_assertion_condition(&condition)
    );
}

#[test]
fn assertion_state_rejects_wrong_state_assertion_and_time_in_isolation() {
    let condition =
        Predicate::assertion_state(assertion_id("leader-elected"), AssertionPhase::Satisfied);

    assert!(
        !evaluator(
            42,
            vec![ObservableEvent::assertion_state_changed(
                time(42),
                assertion_id("leader-elected"),
                AssertionPhase::Violated,
            )],
        )
        .evaluate_assertion_condition(&condition)
    );
    assert!(
        !evaluator(
            42,
            vec![ObservableEvent::assertion_state_changed(
                time(42),
                assertion_id("log-matches"),
                AssertionPhase::Satisfied,
            )],
        )
        .evaluate_assertion_condition(&condition)
    );
    assert!(
        !evaluator(
            42,
            vec![ObservableEvent::assertion_state_changed(
                time(41),
                assertion_id("leader-elected"),
                AssertionPhase::Satisfied,
            )],
        )
        .evaluate_assertion_condition(&condition)
    );
}

#[test]
fn assertion_state_event_carries_virtual_time_name_and_phase() {
    let event = ObservableEvent::assertion_state_changed(
        time(17),
        assertion_id("split-active"),
        AssertionPhase::Violated,
    );

    assert_eq!(event.at(), time(17));
    match event.payload() {
        ObservableEventPayload::AssertionStateChanged { name, state } => {
            assert_eq!(name.name, "split-active");
            assert_eq!(*state, AssertionPhase::Violated);
        }
        other => panic!("assertion constructor should build assertion payload: {other:?}"),
    }
}

#[test]
fn quiescent_uses_scheduler_owned_evidence() {
    let condition = Predicate::quiescent();
    let quiescent = SchedulerQuiescence::default();
    let non_quiescent = SchedulerQuiescence {
        blockers: vec![SchedulerQuiescenceBlocker::RunnableNode {
            node: scheduler_node("server"),
        }],
    };

    assert!(
        support::evaluation_at(60, NoNamedLeaves)
            .with_scheduler_quiescence(quiescent)
            .evaluate_assertion_condition(&condition)
    );
    assert!(
        !support::evaluation_at(60, NoNamedLeaves)
            .with_scheduler_quiescence(non_quiescent)
            .evaluate_assertion_condition(&condition)
    );
    assert!(!support::evaluation_at(60, NoNamedLeaves).evaluate_assertion_condition(&condition));
}

#[test]
fn quiescent_leaf_consumes_scheduler_computed_quiescence() {
    let scheduler = quiescent_scheduler();
    let quiescence = scheduler
        .quiescence()
        .expect("scheduler quiescence should compute from authoritative state");

    assert!(quiescence.is_quiescent());
    assert!(
        support::evaluation_at(scheduler.frontier().ticks, NoNamedLeaves)
            .with_scheduler_quiescence(quiescence)
            .evaluate_assertion_condition(&Predicate::quiescent())
    );
}

#[test]
fn event_graph_fires_from_assertion_state_with_declared_assertion() {
    let graph = EventGraph::new_with_assertions(
        vec![Event::once(
            EventId::from_name("pass-on-leader"),
            Some(Predicate::assertion_state(
                assertion_id("leader-elected"),
                AssertionPhase::Satisfied,
            )),
            Action::Pass,
        )],
        [assertion_id("leader-elected")],
    )
    .expect("assertion-state event graph should build with declarations");
    let mut state = EventGraphState::new();
    let events = vec![ObservableEvent::assertion_state_changed(
        time(99),
        assertion_id("leader-elected"),
        AssertionPhase::Satisfied,
    )];

    let firings = support::evaluate_graph(&graph, &mut state, evaluator(99, events));

    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "pass-on-leader");
}

#[test]
fn event_graph_rejects_undeclared_assertion_state_reference() {
    let result = EventGraph::new(vec![Event::once(
        EventId::from_name("pass-on-leader"),
        Some(Predicate::assertion_state(
            assertion_id("leader-elected"),
            AssertionPhase::Satisfied,
        )),
        Action::Pass,
    )]);

    match result {
        Err(EventGraphError::UnknownAssertionReference { event, assertion }) => {
            assert_eq!(event.name, "pass-on-leader");
            assert_eq!(assertion.name, "leader-elected");
        }
        other => {
            panic!("bare graph constructor should reject assertion-state reference: {other:?}")
        }
    }
}

#[test]
fn event_graph_fires_from_quiescent_scheduler_evidence() {
    let graph = EventGraph::new(vec![Event::once(
        EventId::from_name("pass-on-quiescence"),
        Some(Predicate::quiescent()),
        Action::Pass,
    )])
    .expect("quiescent event graph should build");
    let mut state = EventGraphState::new();
    let evaluation = support::evaluation_at(120, NoNamedLeaves)
        .with_scheduler_quiescence(SchedulerQuiescence::default());

    let firings = support::evaluate_graph(&graph, &mut state, evaluation);

    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "pass-on-quiescence");
}

#[test]
fn properties_validate_assertion_state_references() {
    let validated = Properties::from_assertions_for_world(
        &world(),
        vec![
            assertion(
                "wait-for-later",
                Predicate::assertion_state(assertion_id("later"), AssertionPhase::Satisfied),
            ),
            assertion("later", Predicate::quiescent()),
        ],
    );
    assert!(validated.is_ok());

    let invalid = Properties::from_assertions_for_world(
        &world(),
        vec![assertion(
            "wait-for-missing",
            Predicate::assertion_state(assertion_id("missing"), AssertionPhase::Violated),
        )],
    );

    match invalid {
        Err(EngineError::PropertyPredicateUnknownAssertion { assertion }) => {
            assert_eq!(assertion.name, "missing");
        }
        other => panic!("properties should reject unknown assertion-state reference: {other:?}"),
    }
}

#[test]
fn assertion_state_and_quiescent_round_trip_through_properties_serialization() {
    let world = world();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![
            assertion("leader-elected", Predicate::quiescent()),
            assertion(
                "pass-after-leader",
                Predicate::all_of(vec![
                    Predicate::assertion_state(
                        assertion_id("leader-elected"),
                        AssertionPhase::Satisfied,
                    ),
                    Predicate::quiescent(),
                ]),
            ),
        ],
    )
    .expect("assertion/quiescence properties should validate");

    let toml = properties
        .to_canonical_toml()
        .expect("properties TOML should serialize");
    assert!(toml.contains("kind = \"assertion_state\""));
    assert!(toml.contains("state = \"satisfied\""));
    assert!(toml.contains("kind = \"quiescent\""));
    let from_toml = Properties::from_canonical_toml_for_world(&world, &toml)
        .expect("properties TOML should parse");
    let binary = properties.to_compact_binary();
    let from_binary = Properties::from_compact_binary_for_world(&world, &binary)
        .expect("properties binary should parse");

    assert_eq!(from_toml, properties);
    assert_eq!(from_binary, properties);
    assert_eq!(from_toml.content_hash(), properties.content_hash());
    assert_eq!(from_binary.content_hash(), properties.content_hash());
}

#[test]
fn assertion_state_material_distinguishes_assertion_name_and_phase() {
    let satisfied = properties_for(
        "leader-elected",
        Predicate::assertion_state(assertion_id("leader-elected"), AssertionPhase::Satisfied),
    );
    let violated = properties_for(
        "leader-elected",
        Predicate::assertion_state(assertion_id("leader-elected"), AssertionPhase::Violated),
    );
    let other = Properties::from_assertions_for_world(
        &world(),
        vec![
            assertion("leader-elected", Predicate::quiescent()),
            assertion("log-matches", Predicate::quiescent()),
            assertion(
                "observed",
                Predicate::assertion_state(assertion_id("log-matches"), AssertionPhase::Satisfied),
            ),
        ],
    )
    .expect("properties with declared assertion reference should validate");
    let leader = Properties::from_assertions_for_world(
        &world(),
        vec![
            assertion("leader-elected", Predicate::quiescent()),
            assertion("log-matches", Predicate::quiescent()),
            assertion(
                "observed",
                Predicate::assertion_state(
                    assertion_id("leader-elected"),
                    AssertionPhase::Satisfied,
                ),
            ),
        ],
    )
    .expect("properties with declared assertion reference should validate");
    let quiescent = properties_for("leader-elected", Predicate::quiescent());

    assert_ne!(satisfied.content_hash(), violated.content_hash());
    assert_ne!(leader.content_hash(), other.content_hash());
    assert_ne!(satisfied.content_hash(), quiescent.content_hash());
}
