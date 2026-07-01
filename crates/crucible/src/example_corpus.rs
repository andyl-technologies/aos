//! Built-in worked-example scenario corpus.
//!
//! This module owns the shipped RFC-0010 example artifacts that double as
//! determinism fixtures. Each fixture is a regular content-addressed
//! [`ScenarioDefForm`](crate::model::ScenarioDefForm) plus a deterministic
//! double-backed run script that proves the scenario can pass and reproduce
//! without any guest-side Crucible component.

use std::error::Error;
use std::fmt;

use crate::model::{
    AssertionDef, AssertionId, ChoiceTag, ContentAddressedBlobRef, ContentHash, Decision,
    EngineError, FramePredicate, GuestWorkloadBinary, GuestWorkloadParameterKey,
    GuestWorkloadScalarParameter, LinkId, LinkLossProbability, NodeId, NodeLifecycle, NodeTemplate,
    OverrideDecision, Plan, Predicate, Properties, Property, ReadyPoint, ReproductionArtifact,
    ScenarioDefForm, Schedule, SchedulingPoint, Seed, SimDuration, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode,
};
use crate::scheduler::{
    EventLog, SchedulerError, SchedulerEvaluationBoundaryKind, SchedulerQuiescence,
};
use crate::trigger::{
    Action, BlackBoxHostOracle, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle,
    EventFirings, EventGraph, EventGraphState, HostAssertionEvaluator, HostAssertionReport,
    ObservableEvent, ObservableEventPayload,
};

/// Version label for the built-in worked-example corpus.
pub const BUILT_IN_EXAMPLE_CORPUS_VERSION: &str = "crucible.example-corpus.v1";

/// Stable corpus name for the RFC-0010 A.1 happy-path example.
pub const HAPPY_PATH_SCENARIO_NAME: &str = "happy-path.scn";

/// Whether the built-in example corpus requires a Crucible guest-side component.
pub const EXAMPLE_CORPUS_REQUIRES_GUEST_COMPONENTS: bool = false;

/// Whether the built-in example corpus requires the white-box guest-host channel.
pub const EXAMPLE_CORPUS_WHITE_BOX_REQUIRED: bool = false;

const HAPPY_PATH_RUNS: usize = 5;
const HAPPY_PATH_DEADLINE_TICKS: u64 = 60_000_000_000;
const HAPPY_PATH_TERMINAL_TICKS: u64 = 38;
const HAPPY_PATH_REPLAY_OBSERVATION_POINT_PREFIX: &str = "example-corpus/happy-path/observation/";
const HAPPY_PATH_REPLAY_BOUNDARY_POINT: &str = "example-corpus/happy-path/boundary";

/// A built-in scenario fixture shipped with Crucible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExampleScenarioFixture {
    /// Stable corpus entry name.
    pub name: String,
    /// RFC section that defines the worked example.
    pub rfc_section: String,
    /// Content-addressed scenario definition form.
    pub scenario: ScenarioDefForm,
    /// Whether the fixture is authored without guest-side Crucible components.
    pub zero_guest_components: bool,
    /// Whether the fixture requires white-box guest-host observations.
    pub requires_white_box: bool,
    observations: Vec<ObservableEvent>,
}

impl ExampleScenarioFixture {
    /// Returns the deterministic black-box observations used by the local run proof.
    #[must_use]
    pub fn observations(&self) -> &[ObservableEvent] {
        &self.observations
    }
}

/// The terminal outcome of a built-in example run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExampleScenarioRunOutcome {
    /// The scenario reached its pass event.
    Passed,
}

/// Deterministic result of running one built-in example fixture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExampleScenarioRunReport {
    /// Corpus entry name that was run.
    pub scenario_name: String,
    /// Terminal outcome for the run.
    pub outcome: ExampleScenarioRunOutcome,
    /// Canonical event-log bytes emitted by the run proof.
    pub canonical_event_log: Vec<u8>,
    /// Deterministic fingerprint stream derived from the scenario and log.
    pub fingerprint_stream: Vec<u8>,
    /// Final host-side assertion report produced from the checked log prefix.
    pub assertion_report: HostAssertionReport,
    /// Self-contained reproduction artifact for the run.
    pub reproduction: ReproductionArtifact,
    /// Canonical event-log bytes re-derived from the reproduction artifact.
    pub replayed_canonical_event_log: Vec<u8>,
    /// Fingerprint stream re-derived from the reproduction artifact.
    pub replayed_fingerprint_stream: Vec<u8>,
    /// Event graph firings observed at the passing boundary.
    pub firings: EventFirings,
}

/// Deterministic multi-run verification result for a built-in example fixture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExampleScenarioVerifyReport {
    /// Corpus entry name that was verified.
    pub scenario_name: String,
    /// Number of independent local double-backed runs compared.
    pub runs: usize,
    /// Reference canonical event-log bytes shared by every run.
    pub canonical_event_log: Vec<u8>,
    /// Reference fingerprint stream shared by every run.
    pub fingerprint_stream: Vec<u8>,
}

/// Error returned while building, running, or verifying a built-in example.
#[derive(Debug)]
pub enum ExampleCorpusError {
    /// The underlying scenario model rejected the fixture.
    Engine(EngineError),
    /// The scheduler event-log path rejected the fixture run proof.
    Scheduler(SchedulerError),
    /// A scenario expected to pass did not fire a pass action.
    DidNotPass {
        /// Corpus entry name that failed to pass.
        scenario: String,
    },
    /// A scenario expected to pass had failing host-side assertions.
    AssertionsFailed {
        /// Corpus entry name whose assertions failed.
        scenario: String,
        /// Number of failing assertion records.
        failures: usize,
    },
    /// The reproduction artifact did not re-derive the same checked run bytes.
    ReplayDiverged {
        /// Corpus entry name whose artifact replay diverged.
        scenario: String,
    },
    /// The reproduction artifact schedule did not carry a valid example replay script.
    ReplayScheduleInvalid {
        /// Corpus entry name whose artifact schedule was invalid.
        scenario: String,
        /// Stable explanation of the schedule problem.
        reason: String,
    },
    /// A verification request asked for zero independent runs.
    VerifyRunsZero {
        /// Corpus entry name being verified.
        scenario: String,
    },
    /// Repeated verification runs diverged.
    VerifyDiverged {
        /// Corpus entry name that diverged.
        scenario: String,
        /// Reference run index.
        reference_run: usize,
        /// Diverging run index.
        differing_run: usize,
    },
}

impl fmt::Display for ExampleCorpusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(error) => write!(formatter, "example scenario model error: {error}"),
            Self::Scheduler(error) => {
                write!(formatter, "example scenario scheduler error: {error}")
            }
            Self::DidNotPass { scenario } => {
                write!(formatter, "example scenario `{scenario}` did not pass")
            }
            Self::AssertionsFailed { scenario, failures } => write!(
                formatter,
                "example scenario `{scenario}` failed {failures} host-side assertions"
            ),
            Self::ReplayDiverged { scenario } => write!(
                formatter,
                "example scenario `{scenario}` reproduction artifact replay diverged"
            ),
            Self::ReplayScheduleInvalid { scenario, reason } => write!(
                formatter,
                "example scenario `{scenario}` replay schedule is invalid: {reason}"
            ),
            Self::VerifyRunsZero { scenario } => {
                write!(
                    formatter,
                    "example scenario `{scenario}` verify runs must be nonzero"
                )
            }
            Self::VerifyDiverged {
                scenario,
                reference_run,
                differing_run,
            } => write!(
                formatter,
                "example scenario `{scenario}` diverged between run {reference_run} and {differing_run}"
            ),
        }
    }
}

impl Error for ExampleCorpusError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            Self::Scheduler(error) => Some(error),
            Self::DidNotPass { .. }
            | Self::AssertionsFailed { .. }
            | Self::ReplayDiverged { .. }
            | Self::ReplayScheduleInvalid { .. }
            | Self::VerifyRunsZero { .. }
            | Self::VerifyDiverged { .. } => None,
        }
    }
}

impl From<EngineError> for ExampleCorpusError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

impl From<SchedulerError> for ExampleCorpusError {
    fn from(error: SchedulerError) -> Self {
        Self::Scheduler(error)
    }
}

/// Returns the built-in worked-example scenario corpus.
///
/// # Errors
///
/// Returns [`ExampleCorpusError::Engine`] if a shipped scenario fixture no
/// longer validates or serializes.
pub fn built_in_example_corpus() -> Result<Vec<ExampleScenarioFixture>, ExampleCorpusError> {
    Ok(vec![happy_path_scenario()?])
}

/// Builds the RFC-0010 A.1 happy-path client/server scenario fixture.
///
/// # Errors
///
/// Returns [`ExampleCorpusError::Engine`] if the scenario's world, event graph,
/// properties, or canonical form fail validation.
pub fn happy_path_scenario() -> Result<ExampleScenarioFixture, ExampleCorpusError> {
    let kernel = example_blob("happy-path-any-kernel");
    let server_root = example_blob("happy-path-unmodified-httpd-root-image");
    let client_root = example_blob("happy-path-unmodified-client-loop-root-image");
    let target =
        GuestWorkloadScalarParameter::new(GuestWorkloadParameterKey::Target, "server:8080")?;
    let count = GuestWorkloadScalarParameter::new(GuestWorkloadParameterKey::Count, "100")?;

    let server_cmdline =
        GuestWorkloadBinary::Httpd.selected_cmdline("console=ttyS0 quiet port=8080");
    let client_cmdline = count.selected_cmdline(&target.selected_cmdline(
        &GuestWorkloadBinary::ClientLoop.selected_cmdline("console=ttyS0 quiet"),
    ));

    let world = crate::model::World::from_nodes_and_links(
        vec![
            WorldNode {
                id: node("server"),
                arch: VmArchitecture::X86_64,
                memory_mib: 256,
                cmdline: server_cmdline,
                ready_point: ReadyPoint::ConsoleMarker {
                    marker: String::from("listening on 0.0.0.0:8080"),
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: 7,
                kernel: Some(kernel),
                root_image: Some(server_root),
                initrd: None,
            },
            WorldNode {
                id: node("client"),
                arch: VmArchitecture::X86_64,
                memory_mib: 256,
                cmdline: client_cmdline,
                ready_point: ReadyPoint::ConsoleMarker {
                    marker: String::from("client ready"),
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: 7,
                kernel: Some(kernel),
                root_image: Some(client_root),
                initrd: None,
            },
        ],
        vec![crate::model::LinkDef::with_transport(
            node("client"),
            node("server"),
            SimDuration { nanos: 5_000_000 },
            SimDuration { nanos: 1_000_000 },
            LinkLossProbability::ZERO,
            None,
        )?],
    )?;
    let properties = happy_path_properties(&world)?;
    let plan = happy_path_plan(&world, &properties)?;
    let scenario = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(42),
        10,
    )?;

    Ok(ExampleScenarioFixture {
        name: HAPPY_PATH_SCENARIO_NAME.to_owned(),
        rfc_section: String::from("33.A.1"),
        scenario,
        zero_guest_components: true,
        requires_white_box: false,
        observations: happy_path_observations(),
    })
}

/// Runs a built-in example fixture through the deterministic local proof path.
///
/// # Errors
///
/// Returns [`ExampleCorpusError::Scheduler`] if the checked event-log path
/// rejects the fixture observations, [`ExampleCorpusError::AssertionsFailed`]
/// if the fixture's host-side assertions fail,
/// [`ExampleCorpusError::ReplayDiverged`] if the captured reproduction artifact
/// does not re-derive the same checked bytes,
/// [`ExampleCorpusError::ReplayScheduleInvalid`] if the captured artifact does
/// not carry a valid replay schedule script, or
/// [`ExampleCorpusError::DidNotPass`] if the fixture's event graph does not fire
/// a pass action.
pub fn run_example_scenario(
    fixture: &ExampleScenarioFixture,
) -> Result<ExampleScenarioRunReport, ExampleCorpusError> {
    let primary = run_example_scenario_material(
        &fixture.name,
        &fixture.scenario,
        &fixture.observations,
        HAPPY_PATH_TERMINAL_TICKS,
    )?;
    let reproduction = ReproductionArtifact::capture(
        &fixture.scenario,
        &happy_path_schedule(&fixture.observations),
    )?;
    let replayed = replay_example_scenario_artifact(&fixture.name, &reproduction)?;
    if replayed.canonical_event_log != primary.canonical_event_log
        || replayed.fingerprint_stream != primary.fingerprint_stream
        || replayed.assertion_report != primary.assertion_report
        || replayed.firings != primary.firings
    {
        return Err(ExampleCorpusError::ReplayDiverged {
            scenario: fixture.name.clone(),
        });
    }

    Ok(ExampleScenarioRunReport {
        scenario_name: fixture.name.clone(),
        outcome: ExampleScenarioRunOutcome::Passed,
        canonical_event_log: primary.canonical_event_log,
        fingerprint_stream: primary.fingerprint_stream,
        assertion_report: primary.assertion_report,
        reproduction,
        replayed_canonical_event_log: replayed.canonical_event_log,
        replayed_fingerprint_stream: replayed.fingerprint_stream,
        firings: primary.firings,
    })
}

/// Verifies that `runs` independent local reductions are byte-identical.
///
/// # Errors
///
/// Returns [`ExampleCorpusError::VerifyRunsZero`] when `runs` is zero,
/// [`ExampleCorpusError::VerifyDiverged`] when any run differs from the first
/// run, or the errors returned by [`run_example_scenario`].
pub fn verify_example_scenario_runs(
    fixture: &ExampleScenarioFixture,
    runs: usize,
) -> Result<ExampleScenarioVerifyReport, ExampleCorpusError> {
    if runs == 0 {
        return Err(ExampleCorpusError::VerifyRunsZero {
            scenario: fixture.name.clone(),
        });
    }
    let reference = run_example_scenario(fixture)?;
    for run_index in 1..runs {
        let candidate = run_example_scenario(fixture)?;
        if candidate.canonical_event_log != reference.canonical_event_log
            || candidate.fingerprint_stream != reference.fingerprint_stream
            || candidate.assertion_report != reference.assertion_report
            || candidate.replayed_canonical_event_log != reference.replayed_canonical_event_log
            || candidate.replayed_fingerprint_stream != reference.replayed_fingerprint_stream
            || candidate.reproduction.scenario_form().id()
                != reference.reproduction.scenario_form().id()
        {
            return Err(ExampleCorpusError::VerifyDiverged {
                scenario: fixture.name.clone(),
                reference_run: 0,
                differing_run: run_index,
            });
        }
    }
    Ok(ExampleScenarioVerifyReport {
        scenario_name: fixture.name.clone(),
        runs,
        canonical_event_log: reference.canonical_event_log,
        fingerprint_stream: reference.fingerprint_stream,
    })
}

/// Verifies the happy-path example with the RFC sketch's default run count.
///
/// # Errors
///
/// Returns the errors documented by [`happy_path_scenario`] and
/// [`verify_example_scenario_runs`].
pub fn verify_happy_path_default_runs() -> Result<ExampleScenarioVerifyReport, ExampleCorpusError> {
    let fixture = happy_path_scenario()?;
    verify_example_scenario_runs(&fixture, HAPPY_PATH_RUNS)
}

fn happy_path_properties(world: &World) -> Result<Properties, EngineError> {
    Properties::from_assertions_for_world(
        world,
        vec![
            AssertionDef {
                id: AssertionId::from_name("no-crashes"),
                message: String::from("client and server must not crash"),
                property: Property::Always {
                    predicate: Predicate::not(Predicate::any_of(vec![
                        Predicate::node_state(node("client"), NodeLifecycle::Crashed),
                        Predicate::node_state(node("server"), NodeLifecycle::Crashed),
                    ])),
                },
            },
            AssertionDef {
                id: AssertionId::from_name("all-requests-succeed"),
                message: String::from("client observes 100 successful HTTP responses"),
                property: Property::Eventually {
                    trigger: Predicate::once(Predicate::network_match(
                        Some(LinkId::from_name("client--server")),
                        FramePredicate::contains(b"GET /".to_vec()),
                    )),
                    property: Predicate::all_of(vec![
                        Predicate::network_match(
                            Some(LinkId::from_name("client--server")),
                            FramePredicate::contains(b"http_200_count=100".to_vec()),
                        ),
                        Predicate::node_state(node("client"), NodeLifecycle::Exited),
                    ]),
                    deadline: VirtualTime {
                        ticks: HAPPY_PATH_DEADLINE_TICKS,
                    },
                },
            },
        ],
    )
}

fn happy_path_plan(world: &World, properties: &Properties) -> Result<Plan, EngineError> {
    let graph = EventGraph::builder()
        .event("pass-on-quiescence")
        .when(Predicate::all_of(vec![
            Predicate::node_state(node("client"), NodeLifecycle::Exited),
            Predicate::quiescent(),
        ]))
        .action(Action::pass())
        .build_with_assertions_for_world(
            properties
                .assertions()
                .iter()
                .map(|assertion| assertion.id.clone()),
            world,
        )
        .map_err(|source| EngineError::ScenarioSerialization {
            reason: source.to_string(),
        })?;
    Plan::from_event_graph_with_assertions_for_world(
        world,
        properties
            .assertions()
            .iter()
            .map(|assertion| assertion.id.clone()),
        graph,
    )
}

fn happy_path_observations() -> Vec<ObservableEvent> {
    vec![
        ObservableEvent::console_output(
            VirtualTime { ticks: 10 },
            node("server"),
            b"boot complete\nlistening on 0.0.0.0:8080\n".to_vec(),
        ),
        ObservableEvent::console_output(
            VirtualTime { ticks: 12 },
            node("client"),
            b"client ready\n".to_vec(),
        ),
        ObservableEvent::network_delivered(
            VirtualTime { ticks: 20 },
            Some(LinkId::from_name("client--server")),
            b"GET / HTTP/1.1\r\nHost: server\r\n".to_vec(),
        ),
        ObservableEvent::network_delivered(
            VirtualTime {
                ticks: HAPPY_PATH_TERMINAL_TICKS,
            },
            Some(LinkId::from_name("client--server")),
            b"HTTP/1.1 200 OK\r\nhttp_200_count=100\r\n".to_vec(),
        ),
        ObservableEvent::node_state(
            VirtualTime {
                ticks: HAPPY_PATH_TERMINAL_TICKS,
            },
            node("client"),
            NodeLifecycle::Exited,
        ),
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExampleScenarioRunCore {
    canonical_event_log: Vec<u8>,
    fingerprint_stream: Vec<u8>,
    assertion_report: HostAssertionReport,
    firings: EventFirings,
}

fn run_example_scenario_material(
    scenario_name: &str,
    scenario: &ScenarioDefForm,
    observations: &[ObservableEvent],
    boundary_ticks: u64,
) -> Result<ExampleScenarioRunCore, ExampleCorpusError> {
    let graph = scenario
        .plan()
        .event_graph()
        .ok_or_else(|| ExampleCorpusError::DidNotPass {
            scenario: scenario_name.to_owned(),
        })?;
    let mut log = EventLog::new();
    let mut canonical_event_log = Vec::new();
    let mut assertion_oracle = BlackBoxHostOracle;
    let mut assertion_evaluator = HostAssertionEvaluator::new(scenario.properties())
        .with_world_white_box_policies(scenario.world());

    for observation in observations {
        let observation_segment =
            log.append_observable_events(std::iter::once(observation.clone()))?;
        canonical_event_log.extend_from_slice(&observation_segment.segment_bytes);
        assertion_evaluator.observe_prefix(log.condition_prefix(), &mut assertion_oracle);
    }
    let boundary_segment = log.append_evaluation_boundary(
        VirtualTime {
            ticks: boundary_ticks,
        },
        SchedulerEvaluationBoundaryKind::Quantum,
    )?;
    canonical_event_log.extend_from_slice(&boundary_segment.segment_bytes);

    let assertion_report =
        assertion_evaluator.finalize_prefix(log.condition_prefix(), &mut assertion_oracle);
    if assertion_report.verdict().is_failed() {
        return Err(ExampleCorpusError::AssertionsFailed {
            scenario: scenario_name.to_owned(),
            failures: assertion_report.verdict().failures().len(),
        });
    }

    let mut pass =
        ConditionEvaluationPass::from_log_prefix(log.condition_prefix().clone(), NoNamedLeaves)
            .with_scheduler_quiescence(SchedulerQuiescence::default())
            .with_world_white_box_policies(scenario.world());
    let mut state = EventGraphState::new();
    let firings = pass.evaluate_event_graph(graph, &mut state);
    if !firings.iter().any(|firing| action_passes(firing.action())) {
        return Err(ExampleCorpusError::DidNotPass {
            scenario: scenario_name.to_owned(),
        });
    }

    let fingerprint_stream =
        example_fingerprint_stream(scenario_name, scenario, &canonical_event_log);
    Ok(ExampleScenarioRunCore {
        canonical_event_log,
        fingerprint_stream,
        assertion_report,
        firings,
    })
}

fn replay_example_scenario_artifact(
    scenario_name: &str,
    reproduction: &ReproductionArtifact,
) -> Result<ExampleScenarioRunCore, ExampleCorpusError> {
    let replay = reproduction.replay()?;
    if replay.scenario != reproduction.scenario_form().id() {
        return Err(ExampleCorpusError::ReplayDiverged {
            scenario: scenario_name.to_owned(),
        });
    }
    let replay_script = example_script_from_schedule(scenario_name, reproduction.schedule())?;
    run_example_scenario_material(
        scenario_name,
        reproduction.scenario_form(),
        &replay_script.observations,
        replay_script.boundary_ticks,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExampleReplayScript {
    observations: Vec<ObservableEvent>,
    boundary_ticks: u64,
}

fn happy_path_schedule(observations: &[ObservableEvent]) -> Schedule {
    let mut schedule = Schedule::empty();
    for (index, observation) in observations.iter().enumerate() {
        schedule = schedule.appended(Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: format!("{HAPPY_PATH_REPLAY_OBSERVATION_POINT_PREFIX}{index}"),
            },
            choice: ChoiceTag {
                name: encode_observation(observation),
            },
        }));
    }
    schedule.appended(Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: HAPPY_PATH_REPLAY_BOUNDARY_POINT.to_owned(),
        },
        choice: ChoiceTag {
            name: format!("quantum-boundary|{HAPPY_PATH_TERMINAL_TICKS}"),
        },
    }))
}

fn example_script_from_schedule(
    scenario_name: &str,
    schedule: &Schedule,
) -> Result<ExampleReplayScript, ExampleCorpusError> {
    let mut observations = Vec::new();
    let mut boundary_ticks = None;
    for decision in schedule.decisions() {
        let Decision::Override(override_decision) = decision else {
            return Err(invalid_replay_schedule(
                scenario_name,
                "schedule contains a non-override decision",
            ));
        };
        if let Some(index) = override_decision
            .point
            .key
            .strip_prefix(HAPPY_PATH_REPLAY_OBSERVATION_POINT_PREFIX)
        {
            let expected_index = observations.len().to_string();
            if index != expected_index {
                return Err(invalid_replay_schedule(
                    scenario_name,
                    format!("observation index `{index}` did not follow `{expected_index}`"),
                ));
            }
            observations.push(decode_observation(
                scenario_name,
                &override_decision.choice.name,
            )?);
        } else if override_decision.point.key == HAPPY_PATH_REPLAY_BOUNDARY_POINT {
            if boundary_ticks.is_some() {
                return Err(invalid_replay_schedule(
                    scenario_name,
                    "schedule contains multiple replay boundaries",
                ));
            }
            boundary_ticks = Some(decode_boundary_ticks(
                scenario_name,
                &override_decision.choice.name,
            )?);
        } else {
            return Err(invalid_replay_schedule(
                scenario_name,
                format!(
                    "unknown replay scheduling point `{}`",
                    override_decision.point.key
                ),
            ));
        }
    }
    let Some(boundary_ticks) = boundary_ticks else {
        return Err(invalid_replay_schedule(
            scenario_name,
            "schedule is missing the replay boundary",
        ));
    };
    Ok(ExampleReplayScript {
        observations,
        boundary_ticks,
    })
}

fn encode_observation(observation: &ObservableEvent) -> String {
    match observation.payload() {
        ObservableEventPayload::ConsoleOutput { node, bytes } => format!(
            "console-output|{}|{}|{}",
            observation.at().ticks,
            node.name,
            bytes_hex(bytes)
        ),
        ObservableEventPayload::NetworkDelivered { link, payload } => format!(
            "network-delivered|{}|{}|{}",
            observation.at().ticks,
            link.as_ref().map(|link| link.name.as_str()).unwrap_or("-"),
            bytes_hex(payload)
        ),
        ObservableEventPayload::NodeState { node, state } => format!(
            "node-state|{}|{}|{}",
            observation.at().ticks,
            node.name,
            encode_node_lifecycle(*state)
        ),
        ObservableEventPayload::CoverageBlock { .. }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::MemorySample { .. }
        | ObservableEventPayload::IoCompletion { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionProximity { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::GuestMarker { .. }
        | ObservableEventPayload::GuestAssertionMarker { .. } => {
            String::from("unsupported-observation")
        }
    }
}

fn decode_observation(
    scenario_name: &str,
    encoded: &str,
) -> Result<ObservableEvent, ExampleCorpusError> {
    let parts = encoded.split('|').collect::<Vec<_>>();
    match parts.as_slice() {
        ["console-output", ticks, node_name, bytes] => Ok(ObservableEvent::console_output(
            decode_ticks(scenario_name, ticks)?,
            node(node_name),
            bytes_from_hex(scenario_name, bytes)?,
        )),
        ["network-delivered", ticks, link_name, payload] => {
            let link = if *link_name == "-" {
                None
            } else {
                Some(LinkId::from_name(*link_name))
            };
            Ok(ObservableEvent::network_delivered(
                decode_ticks(scenario_name, ticks)?,
                link,
                bytes_from_hex(scenario_name, payload)?,
            ))
        }
        ["node-state", ticks, node_name, state] => Ok(ObservableEvent::node_state(
            decode_ticks(scenario_name, ticks)?,
            node(node_name),
            decode_node_lifecycle(scenario_name, state)?,
        )),
        _ => Err(invalid_replay_schedule(
            scenario_name,
            format!("invalid observation record `{encoded}`"),
        )),
    }
}

fn decode_boundary_ticks(scenario_name: &str, encoded: &str) -> Result<u64, ExampleCorpusError> {
    let parts = encoded.split('|').collect::<Vec<_>>();
    match parts.as_slice() {
        ["quantum-boundary", ticks] => decode_u64(scenario_name, ticks, "boundary ticks"),
        _ => Err(invalid_replay_schedule(
            scenario_name,
            format!("invalid boundary record `{encoded}`"),
        )),
    }
}

fn decode_ticks(scenario_name: &str, ticks: &str) -> Result<VirtualTime, ExampleCorpusError> {
    Ok(VirtualTime {
        ticks: decode_u64(scenario_name, ticks, "observation ticks")?,
    })
}

fn decode_u64(scenario_name: &str, value: &str, label: &str) -> Result<u64, ExampleCorpusError> {
    value.parse::<u64>().map_err(|_| {
        invalid_replay_schedule(
            scenario_name,
            format!("{label} `{value}` is not an unsigned integer"),
        )
    })
}

fn encode_node_lifecycle(state: NodeLifecycle) -> &'static str {
    match state {
        NodeLifecycle::Started => "started",
        NodeLifecycle::Crashed => "crashed",
        NodeLifecycle::Hung => "hung",
        NodeLifecycle::Exited => "exited",
    }
}

fn decode_node_lifecycle(
    scenario_name: &str,
    state: &str,
) -> Result<NodeLifecycle, ExampleCorpusError> {
    match state {
        "started" => Ok(NodeLifecycle::Started),
        "crashed" => Ok(NodeLifecycle::Crashed),
        "hung" => Ok(NodeLifecycle::Hung),
        "exited" => Ok(NodeLifecycle::Exited),
        _ => Err(invalid_replay_schedule(
            scenario_name,
            format!("unknown node lifecycle `{state}`"),
        )),
    }
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

fn bytes_from_hex(scenario_name: &str, hex: &str) -> Result<Vec<u8>, ExampleCorpusError> {
    if hex.len() % 2 != 0 {
        return Err(invalid_replay_schedule(
            scenario_name,
            "hex payload has an odd length",
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks(2) {
        let high = hex_nibble(scenario_name, pair[0])?;
        let low = hex_nibble(scenario_name, pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(scenario_name: &str, byte: u8) -> Result<u8, ExampleCorpusError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid_replay_schedule(
            scenario_name,
            "hex payload contains a non-lowercase-hex byte",
        )),
    }
}

fn invalid_replay_schedule(scenario_name: &str, reason: impl Into<String>) -> ExampleCorpusError {
    ExampleCorpusError::ReplayScheduleInvalid {
        scenario: scenario_name.to_owned(),
        reason: reason.into(),
    }
}

fn action_passes(action: &Action) -> bool {
    match action {
        Action::Pass => true,
        Action::Group(actions) => actions.iter().any(action_passes),
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Fail { .. }
        | Action::Log { .. } => false,
    }
}

fn example_fingerprint_stream(
    scenario_name: &str,
    scenario: &ScenarioDefForm,
    canonical_event_log: &[u8],
) -> Vec<u8> {
    let log_hash = ContentHash::from_bytes(canonical_event_log);
    let material = format!(
        "corpus_version={BUILT_IN_EXAMPLE_CORPUS_VERSION}\nscenario={}\nscenario_id={}\nlog={}\n",
        scenario_name,
        scenario.id().to_hex(),
        log_hash.to_hex()
    );
    ContentHash::from_canonical_material("crucible.example-corpus.fingerprint.v1", &material)
        .to_hex()
        .into_bytes()
}

fn example_blob(name: &str) -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
        "crucible.example-corpus.asset.v1",
        name,
    ))
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

#[derive(Clone, Copy, Debug)]
struct NoNamedLeaves;

impl ConditionLeafOracle for NoNamedLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}
