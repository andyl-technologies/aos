//! Checks T-TRIG-20 event-graph replay and end-to-end determinism.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, AssertionDef, AssertionId, AssertionPhase, AssertionRunVerdict, ChoiceTag, CodePoint,
    ConditionLeaf, ConditionLeafOracle, ContentHash, Decision, EventGraph, EventGraphState,
    EventId, FramePredicate, Icount, LinkDef, LinkId, LogLevel, NodeId, NodeLifecycle,
    NodeTemplate, ObservableEvent, ObservableEventPayload, OverrideDecision, Plan, Predicate,
    Properties, Property, ReadyPoint, RegexProgram, ReproductionArtifact, ReproductionReplay,
    ScenarioDefForm, Schedule, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerLivenessScenario, SchedulingPoint, Seed, Shift, SimDuration,
    SimInstant, SingleScheduler, TimerId, TriggerActionApplication, TriggerActionState,
    VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn assertion(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn event(name: &str) -> &str {
    name
}

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
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

fn link(left: &str, right: &str) -> LinkId {
    LinkId::for_endpoints(&node(left), &node(right))
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
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1")],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("event-graph replay test world should build")
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

fn readiness_condition() -> Predicate {
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
    .expect("event-graph replay properties should validate")
}

fn graph(world: &World) -> EventGraph {
    EventGraph::builder()
        .event(event("wait-ready"))
        .when(readiness_condition())
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
                Some(link("db-0", "db-1")),
                FramePredicate::contains(b"raft:converged".to_vec()),
            ),
            Predicate::node_state(node("db-0"), NodeLifecycle::Started),
        ]))
        .action(Action::pass())
        .build_with_assertions_for_world([assertion("cluster-safe")], world)
        .expect("event-graph replay graph should validate")
}

fn plan(world: &World, graph: EventGraph) -> Plan {
    Plan::from_event_graph_with_assertions_for_world(world, [assertion("cluster-safe")], graph)
        .expect("event-graph replay plan should validate")
}

fn scenario_form(world: &World, plan: &Plan, properties: &Properties) -> ScenarioDefForm {
    ScenarioDefForm::from_components(world, plan, properties, Seed::from_u64(0x20))
        .expect("event-graph replay scenario form should validate")
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
            Some(link("db-0", "db-1")),
            b"raft:converged:term=7".to_vec(),
        ),
        ObservableEvent::node_state(time(50), node("db-0"), NodeLifecycle::Started),
    ]
}

fn append_boundary(scheduler: &mut SingleScheduler, ticks: u64) -> Vec<u8> {
    scheduler
        .append_evaluation_boundary(time(ticks), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("evaluation boundary should append")
        .segment_bytes
}

struct NoGuestLeaves;

impl ConditionLeafOracle for NoGuestLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("event-graph replay oracle must not depend on guest-side leaf fallback")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ReplayStep {
    Observations(Vec<ObservableEvent>),
    QuantumBoundary(u64),
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn observable_event_material(event: &ObservableEvent) -> String {
    match event.payload() {
        ObservableEventPayload::NetworkDelivered { link, payload } => format!(
            "observable:network-delivered:at={}:link={}:payload={}",
            event.at().ticks,
            link.as_ref().map(|link| link.name.as_str()).unwrap_or("-"),
            bytes_hex(payload)
        ),
        ObservableEventPayload::ConsoleOutput { node, bytes } => format!(
            "observable:console-output:at={}:node={}:bytes={}",
            event.at().ticks,
            node.name,
            bytes_hex(bytes)
        ),
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            guest_pc,
            block_len,
        } => format!(
            "observable:coverage-block:at={}:execution_icount={}:node={}:guest_pc={guest_pc}:block_len={block_len}",
            event.at().ticks,
            execution_icount.retired,
            node.name
        ),
        ObservableEventPayload::CoverageMarker {
            retired_icount,
            node,
            marker,
        } => format!(
            "observable:coverage-marker:at={}:retired_icount={}:node={}:marker={}",
            event.at().ticks,
            retired_icount.retired,
            node.name,
            marker.name
        ),
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            place,
            value,
        } => format!(
            "observable:memory-sample:at={}:sample_icount={}:node={}:place={place:?}:value={value}",
            event.at().ticks,
            sample_icount.retired,
            node.name
        ),
        ObservableEventPayload::IoCompletion {
            node,
            kind,
            payload,
        } => format!(
            "observable:io-completion:at={}:node={}:kind={kind:?}:payload={}",
            event.at().ticks,
            node.name,
            bytes_hex(payload)
        ),
        ObservableEventPayload::NodeState { node, state } => format!(
            "observable:node-state:at={}:node={}:state={state:?}",
            event.at().ticks,
            node.name
        ),
        ObservableEventPayload::AssertionStateChanged { name, state } => format!(
            "observable:assertion-state:at={}:assertion={}:state={state:?}",
            event.at().ticks,
            name.name
        ),
        ObservableEventPayload::AssertionProximity {
            assertion,
            quantifier,
            distance,
            node,
        } => format!(
            "observable:assertion-proximity:at={}:assertion={}:quantifier={quantifier:?}:distance={distance}:node={}",
            event.at().ticks,
            assertion.name,
            node.as_ref().map(|node| node.name.as_str()).unwrap_or("-"),
        ),
        ObservableEventPayload::AssertionEvaluated {
            name,
            flavor,
            condition,
            message,
            details,
        } => {
            let details = details
                .iter()
                .map(|detail| format!("{}={}", detail.key, detail.value))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "observable:assertion-evaluated:at={}:assertion={}:flavor={flavor:?}:condition={condition}:message={message}:details={details}",
                event.at().ticks,
                name.name
            )
        }
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            marker,
        } => format!(
            "observable:guest-marker:at={}:retired_icount={}:node={}:marker={}",
            event.at().ticks,
            retired_icount.retired,
            node.name,
            marker.name
        ),
        ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } => {
            let details = marker
                .details
                .iter()
                .map(|detail| format!("{}={}", detail.key, detail.value))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "observable:guest-assertion-marker:at={}:retired_icount={}:node={}:id={}:kind={:?}:condition={}:must_hit={}:details={details}:location={}",
                event.at().ticks,
                retired_icount.retired,
                node.name,
                marker.id.name,
                marker.kind,
                marker.condition,
                marker.must_hit,
                marker.location
            )
        }
    }
}

fn condition_script_material(script: &[ReplayStep]) -> String {
    let mut lines = vec![String::from("event-graph-replay-condition-script-v1")];
    for (index, step) in script.iter().enumerate() {
        match step {
            ReplayStep::Observations(events) => {
                lines.push(format!("step.{index}.kind=observations"));
                lines.push(format!("step.{index}.count={}", events.len()));
                for (event_index, event) in events.iter().enumerate() {
                    lines.push(format!(
                        "step.{index}.event.{event_index}={}",
                        observable_event_material(event)
                    ));
                }
            }
            ReplayStep::QuantumBoundary(ticks) => {
                lines.push(format!("step.{index}.kind=quantum-boundary"));
                lines.push(format!("step.{index}.ticks={ticks}"));
            }
        }
    }
    lines.join("\n")
}

fn condition_script_hash(script: &[ReplayStep]) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.event-graph.replay-condition-script.v1",
        &condition_script_material(script),
    )
}

fn event_graph_replay_schedule(condition_script_hash: ContentHash) -> Schedule {
    Schedule::empty().appended(Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: String::from("event-graph-replay/condition-script"),
        },
        choice: ChoiceTag {
            name: condition_script_hash.to_hex(),
        },
    }))
}

fn convergence_script() -> Vec<ReplayStep> {
    vec![
        ReplayStep::Observations(readiness_observations()),
        ReplayStep::QuantumBoundary(40),
        ReplayStep::Observations(convergence_observations()),
    ]
}

#[derive(Clone, Debug)]
struct EventGraphReplayArtifact {
    reproduction: ReproductionArtifact,
    condition_script: Vec<ReplayStep>,
    condition_script_hash: ContentHash,
}

impl EventGraphReplayArtifact {
    fn capture_converged() -> Self {
        let world = world();
        let graph = graph(&world);
        let properties = properties(&world);
        let plan = plan(&world, graph);
        let scenario_form = scenario_form(&world, &plan, &properties);
        let condition_script = convergence_script();
        let condition_script_hash = condition_script_hash(&condition_script);
        let schedule = event_graph_replay_schedule(condition_script_hash);
        let reproduction = ReproductionArtifact::capture(&scenario_form, &schedule)
            .expect("event-graph reproduction artifact should reduce");

        Self {
            reproduction,
            condition_script,
            condition_script_hash,
        }
    }

    fn condition_script_matches_recorded_schedule(&self) -> bool {
        let script_hash = condition_script_hash(&self.condition_script);
        let expected_schedule = event_graph_replay_schedule(script_hash);
        script_hash == self.condition_script_hash
            && self.reproduction.schedule() == &expected_schedule
    }
}

#[derive(Debug, PartialEq, Eq)]
struct EventGraphRun {
    artifact_id: ContentHash,
    condition_script_hash: ContentHash,
    reduction_replay: ReproductionReplay,
    scenario_id: ContentHash,
    scenario_seed: Seed,
    schedule: Schedule,
    online_applications: Vec<TriggerActionApplication>,
    offline_applications: Vec<TriggerActionApplication>,
    trigger_firings: Vec<TriggerFiringRecord>,
    trigger_trace: Vec<TriggerTraceEntry>,
    verdict: crucible::ComposedRunVerdict,
    offline_verdict: crucible::ComposedRunVerdict,
    segment_bytes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TriggerFiringRecord {
    event: EventId,
    at: VirtualTime,
    action: Action,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TriggerTraceEntry {
    Fired {
        event: EventId,
        at: VirtualTime,
        action: Action,
    },
    ActionApplied {
        event: EventId,
        at: VirtualTime,
        path: Vec<u64>,
        action: Action,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct TriggerFiringDivergence {
    index: usize,
    expected: Option<TriggerFiringRecord>,
    actual: Option<TriggerFiringRecord>,
}

#[derive(Debug, PartialEq, Eq)]
struct EventGraphReplayMismatch {
    divergence: TriggerFiringDivergence,
}

fn trigger_firing_record(entry: &SchedulerEventLogEntry) -> Option<TriggerFiringRecord> {
    match entry.payload() {
        SchedulerEventLogPayload::TriggerFired(firing) => Some(TriggerFiringRecord {
            event: firing.event().clone(),
            at: firing.at(),
            action: firing.action().clone(),
        }),
        _ => None,
    }
}

fn trigger_trace_entry(entry: &SchedulerEventLogEntry) -> Option<TriggerTraceEntry> {
    match entry.payload() {
        SchedulerEventLogPayload::TriggerFired(firing) => Some(TriggerTraceEntry::Fired {
            event: firing.event().clone(),
            at: firing.at(),
            action: firing.action().clone(),
        }),
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            Some(TriggerTraceEntry::ActionApplied {
                event: application.event.clone(),
                at: application.at,
                path: application.path.clone(),
                action: application.action.clone(),
            })
        }
        _ => None,
    }
}

fn trigger_firing_records(entries: &[SchedulerEventLogEntry]) -> Vec<TriggerFiringRecord> {
    entries.iter().filter_map(trigger_firing_record).collect()
}

fn trigger_trace(entries: &[SchedulerEventLogEntry]) -> Vec<TriggerTraceEntry> {
    entries.iter().filter_map(trigger_trace_entry).collect()
}

fn replay_trigger_applications_from_event_log(
    entries: &[SchedulerEventLogEntry],
) -> Vec<TriggerActionApplication> {
    entries
        .iter()
        .inspect(|entry| {
            assert!(
                entry.has_valid_content_hash(),
                "trigger replay oracle must reject corrupt event-log entries"
            );
        })
        .filter_map(|entry| match entry.payload() {
            SchedulerEventLogPayload::TriggerActionApplied(application) => {
                Some(application.clone())
            }
            _ => None,
        })
        .collect()
}

fn first_trigger_firing_divergence(
    expected: &[TriggerFiringRecord],
    actual: &[TriggerFiringRecord],
) -> Option<TriggerFiringDivergence> {
    let max_len = expected.len().max(actual.len());
    (0..max_len).find_map(|index| {
        let expected = expected.get(index).cloned();
        let actual = actual.get(index).cloned();
        (expected != actual).then_some(TriggerFiringDivergence {
            index,
            expected,
            actual,
        })
    })
}

fn replay_event_graph_artifact(artifact: &EventGraphReplayArtifact) -> EventGraphRun {
    let scenario_form = artifact.reproduction.scenario_form();
    assert!(
        artifact.condition_script_matches_recorded_schedule(),
        "event-graph replay condition script must match the hash recorded in the schedule"
    );
    let reduction_replay = artifact
        .reproduction
        .replay()
        .expect("event-graph reproduction artifact should replay");
    assert_eq!(reduction_replay.scenario, scenario_form.id());
    assert_eq!(
        reduction_replay.schedule,
        artifact.reproduction.schedule().content_hash()
    );

    let graph = scenario_form.plan().event_graph().clone();
    let mut scheduler =
        SingleScheduler::new(scenario("event-graph-replay-oracle", scenario_form.world()))
            .expect("scheduler builds");
    assert_eq!(&scheduler.configuration().schedule, &Schedule::empty());
    let mut graph_state = EventGraphState::new();
    let mut segment_bytes = Vec::new();
    let mut trigger_log = Vec::<SchedulerEventLogEntry>::new();

    for step in &artifact.condition_script {
        match step {
            ReplayStep::Observations(events) => {
                let append = scheduler
                    .append_observable_events(events.clone())
                    .expect("artifact observations should append");
                segment_bytes.push(append.segment_bytes);
            }
            ReplayStep::QuantumBoundary(ticks) => {
                segment_bytes.push(append_boundary(&mut scheduler, *ticks));
            }
        }

        let firings = scheduler.evaluate_event_graph(&graph, &mut graph_state, NoGuestLeaves);
        if !firings.is_empty() {
            let append = scheduler
                .apply_trigger_firings(&firings)
                .expect("replayed trigger actions should apply");
            segment_bytes.push(append.segment_bytes);
            trigger_log.extend(append.entries);
        }
    }

    let trigger_firings = trigger_firing_records(&trigger_log);
    assert!(
        !trigger_log
            .iter()
            .any(|entry| entry.event_payload().kind() == "condition_evaluated"),
        "condition truth must be rederived rather than logged as condition_evaluated",
    );
    for entry in trigger_log
        .iter()
        .filter(|entry| entry.event_payload().kind() == "trigger_fired")
    {
        assert!(
            matches!(entry.payload(), SchedulerEventLogPayload::TriggerFired(_)),
            "trigger firing must not be recorded as a Decision",
        );
        assert!(
            entry.event_payload().string("condition").is_some(),
            "trigger firing must retain its canonical condition summary",
        );
    }
    assert_eq!(
        fired_event_names_from_records(&trigger_firings),
        vec![
            "wait-ready",
            "timer-observed",
            "pass-on-black-box-convergence",
        ]
    );

    let assertion_verdict = AssertionRunVerdict::passed();
    let verdict = scheduler
        .trigger_actions()
        .compose_run_verdict(assertion_verdict.clone());
    let offline_verdict =
        TriggerActionState::compose_run_verdict_from_event_log(&trigger_log, assertion_verdict)
            .expect("trigger verdict should replay from event log");
    let offline_applications = replay_trigger_applications_from_event_log(&trigger_log);

    assert_eq!(
        scheduler.trigger_actions().applications,
        offline_applications
    );
    assert_eq!(verdict, offline_verdict);

    EventGraphRun {
        artifact_id: artifact.reproduction.id(),
        condition_script_hash: artifact.condition_script_hash,
        reduction_replay,
        scenario_id: scenario_form.id(),
        scenario_seed: scenario_form.seed(),
        schedule: artifact.reproduction.schedule().clone(),
        online_applications: scheduler.trigger_actions().applications.clone(),
        offline_applications,
        trigger_firings,
        trigger_trace: trigger_trace(&trigger_log),
        verdict,
        offline_verdict,
        segment_bytes,
    }
}

fn fired_event_names_from_records(records: &[TriggerFiringRecord]) -> Vec<&str> {
    records
        .iter()
        .map(|record| record.event.name.as_str())
        .collect()
}

fn check_event_graph_replay_oracle(
    artifact: &EventGraphReplayArtifact,
    recorded_firings: &[TriggerFiringRecord],
) -> Result<EventGraphRun, Box<EventGraphReplayMismatch>> {
    let replay = replay_event_graph_artifact(artifact);
    if let Some(divergence) =
        first_trigger_firing_divergence(recorded_firings, &replay.trigger_firings)
    {
        return Err(Box::new(EventGraphReplayMismatch { divergence }));
    }
    Ok(replay)
}

#[test]
fn event_graph_replay_oracle_rederives_identical_firings_actions_and_verdict() {
    let artifact = EventGraphReplayArtifact::capture_converged();
    let online = replay_event_graph_artifact(&artifact);
    let offline = check_event_graph_replay_oracle(&artifact, &online.trigger_firings)
        .expect("offline replay should rederive the recorded trigger firings");

    assert_eq!(online.artifact_id, offline.artifact_id);
    assert_eq!(online.condition_script_hash, offline.condition_script_hash);
    assert_eq!(online.reduction_replay, offline.reduction_replay);
    assert_eq!(online.scenario_id, offline.scenario_id);
    assert_eq!(online.scenario_seed, offline.scenario_seed);
    assert_eq!(online.schedule, offline.schedule);
    assert_eq!(online.trigger_firings, offline.trigger_firings);
    assert_eq!(online.online_applications, offline.online_applications);
    assert_eq!(online.offline_applications, offline.offline_applications);
    assert_eq!(online.verdict, offline.verdict);
    assert_eq!(online.offline_verdict, offline.offline_verdict);
    assert_eq!(online.segment_bytes, offline.segment_bytes);
    assert_eq!(online.trigger_trace, offline.trigger_trace);
    assert!(
        first_trigger_firing_divergence(&online.trigger_firings, &offline.trigger_firings)
            .is_none()
    );
}

#[test]
fn event_graph_replay_oracle_rejects_condition_script_schedule_drift() {
    let mut artifact = EventGraphReplayArtifact::capture_converged();
    assert!(artifact.condition_script_matches_recorded_schedule());

    artifact.condition_script = vec![ReplayStep::Observations(readiness_observations())];

    assert!(!artifact.condition_script_matches_recorded_schedule());
    assert_ne!(
        condition_script_hash(&artifact.condition_script),
        artifact.condition_script_hash
    );
}

#[test]
fn event_graph_replay_oracle_localizes_first_differing_firing() {
    let artifact = EventGraphReplayArtifact::capture_converged();
    let online = replay_event_graph_artifact(&artifact);
    let mut corrupt_recorded_firings = online.trigger_firings.clone();
    corrupt_recorded_firings[2] = TriggerFiringRecord {
        event: event_id("fail-on-property-violation"),
        at: time(50),
        action: Action::fail("cluster-safe assertion violated"),
    };

    let mismatch = check_event_graph_replay_oracle(&artifact, &corrupt_recorded_firings)
        .expect_err("corrupt recorded trigger firing should diverge from replay");
    let divergence = mismatch.divergence;

    assert_eq!(divergence.index, 2);
    assert_eq!(
        divergence
            .expected
            .as_ref()
            .map(|firing| firing.event.clone()),
        Some(event_id("fail-on-property-violation"))
    );
    assert_eq!(
        divergence
            .actual
            .as_ref()
            .map(|firing| firing.event.clone()),
        Some(event_id("pass-on-black-box-convergence"))
    );
    assert_eq!(
        &corrupt_recorded_firings[..divergence.index],
        &online.trigger_firings[..divergence.index],
        "replay oracle must preserve the identical prefix before reporting divergence"
    );
}
