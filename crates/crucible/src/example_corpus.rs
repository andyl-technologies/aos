//! Built-in worked-example scenario corpus.
//!
//! This module owns the shipped RFC-0010 example artifacts that double as
//! determinism fixtures. Each fixture is a regular content-addressed
//! [`ScenarioDefForm`] plus a deterministic
//! double-backed run script that proves the scenario can pass and reproduce.
//! Guest-controlled application verdicts use structured guest assertions;
//! host-owned lifecycle, fault, timer, and quiescence facts remain host-side.

use std::error::Error;
use std::fmt;

use crucible_protocol::{
    WhiteboxAssertionMarkerBody, WhiteboxAssertionMarkerFlavor, WhiteboxDoorbellFrame,
    WhiteboxMarkerDetail, WhiteboxMarkerPayload, decode_whitebox_marker_payload,
    encode_whitebox_marker_frame,
};

use crate::model::{
    AssertionDef, AssertionId, AssertionPhase, Checkpoint, CheckpointKind, ChoiceTag, CodePoint,
    Configuration, ContentAddressedBlobRef, ContentHash, CoverageGuidedFuzzConfig,
    CoverageGuidedFuzzIteration, CoverageGuidedFuzzRun, Decision, EngineError, EventId,
    FamilySpace, FindingDiscoveryPath, FindingReproductionArtifact, GenesisCheckpoint,
    GuestWorkloadBinary, GuestWorkloadParameterKey, GuestWorkloadScalarParameter, Icount,
    IoEventKind, LinkLossProbability, MarkerId, MemoryDagStore, NodeCounter, NodeId, NodeLifecycle,
    NodeTemplate, OverrideDecision, Plan, Predicate, Properties, Property, ReadyPoint,
    RegexProgram, ReproductionArtifact, ScenarioDefForm, ScenarioFamily, Schedule, SchedulerNodeId,
    SchedulingNodeKind, SchedulingPoint, Seed, Shift, SimDuration, SimInstant, TemporalGraph,
    TemporalGraphFork, TemporalGraphRuntime, TemporalGraphSave, TemporalGraphStoreError, TimerId,
    TopologyShape, TopologySizeRange, UnifiedGraphOperationEvidence, UnifiedGraphOperationReport,
    VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode, bake, try_step,
};
use crate::scheduler::{
    EventLog, EventLogCoverageFeedback, EventLogCoverageFeedbackConsumer, ExactLocalEvent,
    NetworkLookahead, SchedulerError, SchedulerEvaluationBoundaryKind, SchedulerLivenessScenario,
    SchedulerLookaheadEdge, SchedulerNodeActivity, SchedulerScenarioNode,
    SchedulerTopologyChangeApplication, SingleScheduler, TriggerActionApplication,
};
use crate::trigger::{
    Action, AssertionViolationArtifactReplay, AssertionViolationReplayError,
    AssertionViolationReplayReport, BlackBoxHostOracle, ConditionEvaluationPass, ConditionLeaf,
    ConditionLeafOracle, EventFirings, EventGraph, EventGraphState, GuestAssertionDetail,
    GuestAssertionKind, GuestAssertionMarker, HostAssertionEvaluator, HostAssertionOutcome,
    HostAssertionOutcomeKind, HostAssertionReport, LogLevel, ObservableEvent,
    ObservableEventPayload, OfflineAssertionCheckError, RecordedAssertionLog,
    check_assertion_violation_reproduction, guest_assertion_marker_from_whitebox_body,
};

/// Version label for the built-in worked-example corpus.
pub const BUILT_IN_EXAMPLE_CORPUS_VERSION: &str = "crucible.example-corpus.v2";

/// Stable corpus name for the RFC-0010 A.1 happy-path example.
pub const HAPPY_PATH_SCENARIO_NAME: &str = "happy-path.scn";

/// Stable corpus name for the RFC-0010 A.2 partition-recovery example.
pub const PARTITION_RECOVERY_SCENARIO_NAME: &str = "partition-recovery.scn";

/// Stable corpus name for the RFC-0010 A.3 crash+restart example.
pub const CRASH_RESTART_SCENARIO_NAME: &str = "crash-restart.scn";

/// Stable built-in family name for the RFC-0010 A.4 fault-campaign example.
pub const FAULT_CAMPAIGN_FAMILY_NAME: &str = "fault-campaign.fam";

/// Whether the built-in example corpus requires a Crucible guest-side component.
pub const EXAMPLE_CORPUS_REQUIRES_GUEST_COMPONENTS: bool = true;

/// Whether the built-in example corpus requires the white-box guest-host channel.
pub const EXAMPLE_CORPUS_WHITE_BOX_REQUIRED: bool = true;

const HAPPY_PATH_RUNS: usize = 5;
const HAPPY_PATH_DEADLINE_TICKS: u64 = 60_000_000_000;
const HAPPY_PATH_TERMINAL_TICKS: u64 = 38;
const PARTITION_HEAL_DELAY_TICKS: u64 = 10_000_000_000;
const PARTITION_CONVERGENCE_DEADLINE_TICKS: u64 = 30_000_000_000;
const CRASH_RESTART_DELAY_TICKS: u64 = 5_000_000_000;
const CRASH_RESTART_DEADLINE_TICKS: u64 = 40_000_000_000;
const CRASH_RESTART_COMMIT_TICKS: u64 = 30;
const FAULT_CAMPAIGN_DEFAULT_RUNS: u64 = 4;
const EXAMPLE_REPLAY_STEP_POINT_PREFIX: &str = "example-corpus/replay-step/";
const FAULT_CAMPAIGN_VIOLATION_POINT: &str = "example-corpus/fault-campaign/violation";

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
    steps: Vec<ExampleReplayStep>,
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
    /// Scheduler topology-change applications produced by the run proof.
    pub scheduler_topology_change_applications: Vec<SchedulerTopologyChangeApplication>,
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

/// Deterministic proof report for the RFC-0010 A.4 fault-campaign example.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultCampaignExampleReport {
    /// Stable built-in family name used by the CLI and corpus checks.
    pub family_name: String,
    /// Coverage-guided fuzzing configuration used by the proof.
    pub config: CoverageGuidedFuzzConfig,
    /// Deterministic coverage feedback fingerprints consumed by fuzzing.
    pub coverage_fingerprints: Vec<ContentHash>,
    /// Complete coverage-guided fuzzing run over the built-in family.
    pub fuzz_run: CoverageGuidedFuzzRun,
    /// Iteration selected by the planted discoverable failure oracle.
    pub discovered_iteration: CoverageGuidedFuzzIteration,
    /// Black-box observations that trigger the planted no-split-brain violation.
    pub violation_observations: Vec<ObservableEvent>,
    /// Unified event-log bytes that carry the planted violation observations.
    pub violation_event_log: Vec<u8>,
    /// Host-side assertion report proving the planted violation was evaluated.
    pub violation_report: HostAssertionReport,
    /// Assertion-violation replay report proving the finding reproduces the violation.
    pub violation_replay: AssertionViolationReplayReport,
    /// Self-contained reduced finding artifact for the discovered failure.
    pub finding: FindingReproductionArtifact,
    /// Unified-graph validation report for the fuzzing iteration.
    pub fuzz_report: UnifiedGraphOperationReport,
    /// Unified-graph validation report for the finding artifact replay.
    pub reproduction_report: UnifiedGraphOperationReport,
    /// Save operation for the pre-failure neighborhood checkpoint.
    pub save: TemporalGraphSave,
    /// Unified-graph validation report for the save operation.
    pub save_report: UnifiedGraphOperationReport,
    /// Resume operation from the saved pre-failure neighborhood checkpoint.
    pub resume: TemporalGraphRuntime,
    /// Unified-graph validation report for the resume operation.
    pub resume_report: UnifiedGraphOperationReport,
    /// Fork operation that walks an alternate schedule from the same prefix.
    pub fork: TemporalGraphFork,
    /// Unified-graph validation report for the fork operation.
    pub fork_report: UnifiedGraphOperationReport,
}

/// Error returned while building, running, or verifying a built-in example.
#[derive(Debug)]
pub enum ExampleCorpusError {
    /// The underlying scenario model rejected the fixture.
    Engine(Box<EngineError>),
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
    /// A fault-campaign proof was requested with no fuzz iterations.
    FaultCampaignNoIterations,
    /// The fault-campaign proof did not produce the planted no-split-brain violation.
    FaultCampaignViolationMissing,
    /// The fault-campaign retained assertion log could not be folded.
    FaultCampaignViolationLog(OfflineAssertionCheckError),
    /// The fault-campaign assertion violation did not replay bit-identically.
    FaultCampaignViolationReplay(Box<AssertionViolationReplayError>),
    /// The temporal graph could not persist the savepoint closure.
    TemporalGraphStore(Box<TemporalGraphStoreError>),
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
            Self::FaultCampaignNoIterations => write!(
                formatter,
                "fault-campaign example requires at least one fuzz iteration"
            ),
            Self::FaultCampaignViolationMissing => write!(
                formatter,
                "fault-campaign example did not evaluate the planted no-split-brain violation"
            ),
            Self::FaultCampaignViolationLog(error) => write!(
                formatter,
                "fault-campaign assertion violation log error: {error}"
            ),
            Self::FaultCampaignViolationReplay(error) => write!(
                formatter,
                "fault-campaign assertion violation replay error: {error}"
            ),
            Self::TemporalGraphStore(error) => {
                write!(
                    formatter,
                    "fault-campaign temporal graph store error: {error}"
                )
            }
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
            | Self::VerifyDiverged { .. }
            | Self::FaultCampaignNoIterations
            | Self::FaultCampaignViolationMissing => None,
            Self::FaultCampaignViolationLog(error) => Some(error),
            Self::FaultCampaignViolationReplay(error) => Some(error),
            Self::TemporalGraphStore(error) => Some(error),
        }
    }
}

impl From<EngineError> for ExampleCorpusError {
    fn from(error: EngineError) -> Self {
        Self::Engine(Box::new(error))
    }
}

impl From<SchedulerError> for ExampleCorpusError {
    fn from(error: SchedulerError) -> Self {
        Self::Scheduler(error)
    }
}

impl From<TemporalGraphStoreError> for ExampleCorpusError {
    fn from(error: TemporalGraphStoreError) -> Self {
        Self::TemporalGraphStore(Box::new(error))
    }
}

/// Returns the built-in worked-example scenario corpus.
///
/// # Errors
///
/// Returns [`ExampleCorpusError::Engine`] if a shipped scenario fixture no
/// longer validates or serializes.
pub fn built_in_example_corpus() -> Result<Vec<ExampleScenarioFixture>, ExampleCorpusError> {
    Ok(vec![
        happy_path_scenario()?,
        partition_recovery_scenario()?,
        crash_restart_scenario()?,
    ])
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

    let observations = happy_path_observations();
    let steps = happy_path_replay_steps(&observations);
    Ok(ExampleScenarioFixture {
        name: HAPPY_PATH_SCENARIO_NAME.to_owned(),
        rfc_section: String::from("33.A.1"),
        scenario,
        zero_guest_components: true,
        requires_white_box: false,
        observations,
        steps,
    })
}

/// Builds the RFC-0010 A.2 three-node partition-recovery scenario fixture.
///
/// # Errors
///
/// Returns [`ExampleCorpusError::Engine`] if the scenario's world, event graph,
/// properties, or canonical form fail validation.
pub fn partition_recovery_scenario() -> Result<ExampleScenarioFixture, ExampleCorpusError> {
    let kernel = example_blob("partition-recovery-any-kernel");
    let root = example_blob("partition-recovery-unmodified-store-root-image");
    let world = World::from_nodes_and_links(
        vec![
            partition_node("db-0", kernel, root),
            partition_node("db-1", kernel, root),
            partition_node("db-2", kernel, root),
        ],
        vec![
            partition_link("db-0", "db-1")?,
            partition_link("db-1", "db-2")?,
            partition_link("db-0", "db-2")?,
        ],
    )?;
    let properties = partition_recovery_properties(&world)?;
    let plan = partition_recovery_plan(&world, &properties)?;
    let scenario = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(99),
        10,
    )?;
    let steps = partition_recovery_replay_steps();

    Ok(ExampleScenarioFixture {
        name: PARTITION_RECOVERY_SCENARIO_NAME.to_owned(),
        rfc_section: String::from("33.A.2"),
        scenario,
        zero_guest_components: false,
        requires_white_box: true,
        observations: flatten_observations(&steps),
        steps,
    })
}

/// Builds the RFC-0010 A.3 node crash+restart scenario fixture.
///
/// # Errors
///
/// Returns [`ExampleCorpusError::Engine`] if the scenario's world, event graph,
/// properties, or canonical form fail validation.
pub fn crash_restart_scenario() -> Result<ExampleScenarioFixture, ExampleCorpusError> {
    let kernel = example_blob("crash-restart-any-kernel");
    let root = example_blob("crash-restart-unmodified-store-root-image");
    let world = World::from_nodes_and_links(
        vec![
            crash_restart_node("db-0", kernel, root),
            crash_restart_node("db-1", kernel, root),
            crash_restart_node("db-2", kernel, root),
        ],
        vec![
            partition_link("db-0", "db-1")?,
            partition_link("db-1", "db-2")?,
            partition_link("db-0", "db-2")?,
        ],
    )?;
    let properties = crash_restart_properties(&world)?;
    let plan = crash_restart_plan(&world, &properties)?;
    let scenario = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(7),
        10,
    )?;
    let steps = crash_restart_replay_steps();

    Ok(ExampleScenarioFixture {
        name: CRASH_RESTART_SCENARIO_NAME.to_owned(),
        rfc_section: String::from("33.A.3"),
        scenario,
        zero_guest_components: false,
        requires_white_box: true,
        observations: flatten_observations(&steps),
        steps,
    })
}

/// Builds the RFC-0010 A.4 fault-campaign scenario family.
///
/// # Errors
///
/// Returns [`ExampleCorpusError::Engine`] if the family space or shared
/// black-box property is invalid.
pub fn fault_campaign_family() -> Result<ScenarioFamily, ExampleCorpusError> {
    let space = FamilySpace::new(
        crate::model::SeedSpace::generated(Seed::from_u64(0x33_a4), 8)?,
        TopologySizeRange::new(3, 5)?,
        vec![TopologyShape::Ring, TopologyShape::Mesh],
    )?;
    let template = NodeTemplate::fixed_icount(Icount { retired: 100 })
        .white_box(WhiteBoxPolicy::Enabled)
        .cmdline("console=ttyS0 quiet store.role=replica cluster=crucible-a4");
    Ok(
        ScenarioFamily::new(space, template).property(AssertionDef::guest_unreachable(
            AssertionId::from_name("no-split-brain"),
            "the store must not publish split-brain evidence",
        )),
    )
}

/// Runs the RFC-0010 A.4 fault-campaign proof with the default fuzz budget.
///
/// # Errors
///
/// Returns the errors documented by [`run_fault_campaign_example`].
pub fn run_fault_campaign_example_default() -> Result<FaultCampaignExampleReport, ExampleCorpusError>
{
    run_fault_campaign_example(CoverageGuidedFuzzConfig::new(
        Seed::from_u64(0x33a4_f00d),
        FAULT_CAMPAIGN_DEFAULT_RUNS,
    ))
}

/// Runs the RFC-0010 A.4 fault-campaign proof.
///
/// # Errors
///
/// Returns [`ExampleCorpusError::Engine`] if family sampling, reproduction,
/// replay, resume, fork, or unified-graph validation fails;
/// [`ExampleCorpusError::Scheduler`] if the coverage feedback event log cannot
/// be built; [`ExampleCorpusError::TemporalGraphStore`] if the savepoint closure
/// cannot be persisted; or [`ExampleCorpusError::FaultCampaignNoIterations`] if
/// `config` requests no fuzz iterations.
pub fn run_fault_campaign_example(
    config: CoverageGuidedFuzzConfig,
) -> Result<FaultCampaignExampleReport, ExampleCorpusError> {
    let family = fault_campaign_family()?;
    let coverage_feedback = fault_campaign_coverage_feedback()?;
    let coverage_fingerprints = coverage_feedback
        .iter()
        .map(|feedback| {
            feedback.fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing)
        })
        .collect::<Vec<_>>();
    let fuzz_run = family.fuzz_coverage_guided(config, &coverage_feedback)?;
    let discovered_iteration = fuzz_run
        .iterations
        .iter()
        .find(|iteration| iteration.new_coverage)
        .or_else(|| fuzz_run.iterations.first())
        .cloned()
        .ok_or(ExampleCorpusError::FaultCampaignNoIterations)?;
    let violation = fault_campaign_violation_evidence(discovered_iteration.scenario.form())?;
    let finding_fingerprint =
        fault_campaign_finding_fingerprint(&discovered_iteration, &violation.report);
    let violation_configuration = try_step(
        &discovered_iteration.configuration,
        fault_campaign_violation_decision(&violation.observations)?,
    )?;
    let finding = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::CoverageGuidedFuzzing,
        finding_fingerprint,
        discovered_iteration.scenario.form(),
        &violation_configuration,
    )?;
    let reproduced_log = fault_campaign_replayed_violation_log_from_artifact(&finding.artifact)?;
    let replayed_violation =
        AssertionViolationArtifactReplay::from_artifact(&finding.artifact, reproduced_log)?;
    let violation_replay = check_assertion_violation_reproduction(
        &finding.artifact,
        &violation.recorded_log,
        &replayed_violation,
    )
    .map_err(|error| ExampleCorpusError::FaultCampaignViolationReplay(Box::new(error)))?;

    let pre_failure = discovered_iteration
        .scenario
        .genesis_configuration()
        .configuration()
        .clone();
    let mut graph = TemporalGraph::new(ContentHash::from_canonical_material(
        "crucible.example-corpus.fault-campaign.graph.v1",
        &format!(
            "family={FAULT_CAMPAIGN_FAMILY_NAME}\nconfig={:?}\nfinding={}",
            config,
            finding_fingerprint.to_hex()
        ),
    ))
    .with_baked_genesis(
        &discovered_iteration.configuration.def,
        baked_genesis_for_scenario(discovered_iteration.scenario.form())?,
    )?;

    let fuzz_report = graph.validate_unified_operation(
        &UnifiedGraphOperationEvidence::CoverageGuidedFuzzing {
            family: family.clone(),
            run: fuzz_run.clone(),
            feedback_fingerprints: coverage_fingerprints.clone(),
            iteration: discovered_iteration.clone(),
        },
    )?;
    let reproduction_report = graph.validate_unified_operation(
        &UnifiedGraphOperationEvidence::ReproductionArtifact(finding.clone()),
    )?;

    let store = MemoryDagStore::new();
    let save = graph.save(&store, &pre_failure)?;
    let save_report = graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Save {
        configuration: pre_failure.clone(),
        save: save.clone(),
    })?;
    let resume = graph.resume_checkpoint(save.checkpoint)?;
    let resume_report =
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Resume {
            configuration: pre_failure.clone(),
            runtime: resume.clone(),
        })?;
    let fork = graph.fork(
        &pre_failure,
        vec![fault_campaign_alternate_decision(config)],
    )?;
    let fork_report =
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Fork(fork.clone()))?;

    Ok(FaultCampaignExampleReport {
        family_name: FAULT_CAMPAIGN_FAMILY_NAME.to_owned(),
        config,
        coverage_fingerprints,
        fuzz_run,
        discovered_iteration,
        violation_observations: violation.observations,
        violation_event_log: violation.event_log,
        violation_report: violation_replay.reproduced.clone(),
        violation_replay,
        finding,
        fuzz_report,
        reproduction_report,
        save,
        save_report,
        resume,
        resume_report,
        fork,
        fork_report,
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
    let primary = run_example_scenario_material(&fixture.name, &fixture.scenario, &fixture.steps)?;
    let schedule = if fixture.name == HAPPY_PATH_SCENARIO_NAME {
        happy_path_schedule(&fixture.observations)?
    } else {
        example_schedule(&fixture.name, &fixture.steps)?
    };
    let reproduction = ReproductionArtifact::capture(&fixture.scenario, &schedule)?;
    let replayed = replay_example_scenario_artifact(&fixture.name, &reproduction)?;
    if replayed.canonical_event_log != primary.canonical_event_log
        || replayed.fingerprint_stream != primary.fingerprint_stream
        || replayed.assertion_report != primary.assertion_report
        || replayed.firings != primary.firings
        || replayed.scheduler_topology_change_applications
            != primary.scheduler_topology_change_applications
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
        scheduler_topology_change_applications: primary.scheduler_topology_change_applications,
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

/// Verifies the partition-recovery example with the RFC sketch's default count.
///
/// # Errors
///
/// Returns the errors documented by [`partition_recovery_scenario`] and
/// [`verify_example_scenario_runs`].
pub fn verify_partition_recovery_default_runs()
-> Result<ExampleScenarioVerifyReport, ExampleCorpusError> {
    let fixture = partition_recovery_scenario()?;
    verify_example_scenario_runs(&fixture, HAPPY_PATH_RUNS)
}

/// Verifies the crash+restart example with the RFC sketch's default count.
///
/// # Errors
///
/// Returns the errors documented by [`crash_restart_scenario`] and
/// [`verify_example_scenario_runs`].
pub fn verify_crash_restart_default_runs() -> Result<ExampleScenarioVerifyReport, ExampleCorpusError>
{
    let fixture = crash_restart_scenario()?;
    verify_example_scenario_runs(&fixture, HAPPY_PATH_RUNS)
}

fn partition_node(
    name: &str,
    kernel: ContentAddressedBlobRef,
    root_image: ContentAddressedBlobRef,
) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: 512,
        cmdline: String::from("console=ttyS0 quiet store.role=replica cluster=crucible-a2"),
        ready_point: ReadyPoint::ConsoleMarker {
            marker: String::from("ready to accept connections"),
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: 7,
        kernel: Some(kernel),
        root_image: Some(root_image),
        initrd: None,
    }
}

fn crash_restart_node(
    name: &str,
    kernel: ContentAddressedBlobRef,
    root_image: ContentAddressedBlobRef,
) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: 512,
        cmdline: String::from("console=ttyS0 quiet store.role=replica cluster=crucible-a3"),
        ready_point: ReadyPoint::ConsoleMarker {
            marker: String::from("ready to accept connections"),
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: 7,
        kernel: Some(kernel),
        root_image: Some(root_image),
        initrd: None,
    }
}

fn partition_link(from: &str, to: &str) -> Result<crate::model::LinkDef, EngineError> {
    crate::model::LinkDef::with_transport(
        node(from),
        node(to),
        SimDuration { nanos: 5_000_000 },
        SimDuration { nanos: 1_000_000 },
        LinkLossProbability::ZERO,
        None,
    )
}

fn crash_restart_properties(world: &World) -> Result<Properties, EngineError> {
    let crash_trigger = Predicate::node_state(node("db-1"), NodeLifecycle::Crashed);
    Properties::from_assertions_for_world(
        world,
        vec![
            AssertionDef::guest_unreachable(
                AssertionId::from_name("data-not-lost"),
                "the committed write must survive db-1 crash and restart",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("committed-write-survived"),
                "a replica confirms that the committed write survived",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("replicas-reconciled"),
                "replicas report matching logs after db-1 restarts",
            ),
            AssertionDef {
                id: AssertionId::from_name("reconverges"),
                message: String::from("replicas must reconcile after db-1 restarts"),
                property: Property::Eventually {
                    trigger: crash_trigger,
                    property: Predicate::assertion_state(
                        AssertionId::from_name("replicas-reconciled"),
                        AssertionPhase::Satisfied,
                    ),
                    deadline: VirtualTime {
                        ticks: CRASH_RESTART_DEADLINE_TICKS,
                    },
                },
            },
        ],
    )
}

fn crash_restart_plan(world: &World, properties: &Properties) -> Result<Plan, EngineError> {
    let graph = EventGraph::builder()
        .event("crash-after-commit")
        .when(Predicate::all_of(vec![
            Predicate::node_state(node("db-1"), NodeLifecycle::Started),
            Predicate::once(Predicate::io_pattern(node("db-1"), IoEventKind::BlockWrite)),
        ]))
        .action(Action::stop_node(node("db-1")))
        .event("restart")
        .when(Predicate::after(
            SimDuration {
                nanos: CRASH_RESTART_DELAY_TICKS,
            },
            EventId::from_name("crash-after-commit"),
        ))
        .action(Action::start_node(node("db-1")))
        .event("pass-on-reconverge")
        .when(Predicate::all_of(vec![
            Predicate::once(Predicate::node_state(node("db-1"), NodeLifecycle::Started)),
            Predicate::once(Predicate::assertion_state(
                AssertionId::from_name("committed-write-survived"),
                AssertionPhase::Satisfied,
            )),
            Predicate::once(Predicate::assertion_state(
                AssertionId::from_name("replicas-reconciled"),
                AssertionPhase::Satisfied,
            )),
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

fn partition_recovery_properties(world: &World) -> Result<Properties, EngineError> {
    Properties::from_assertions_for_world(
        world,
        vec![
            AssertionDef::guest_unreachable(
                AssertionId::from_name("no-split-brain"),
                "the store must not publish split-brain evidence",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("replicas-reconciled"),
                "replicas report matching logs after the partition heals",
            ),
            AssertionDef {
                id: AssertionId::from_name("converges-after-heal"),
                message: String::from("replicas must reconcile after the healed partition"),
                property: Property::Eventually {
                    trigger: Predicate::node_state(node("db-0"), NodeLifecycle::Started),
                    property: Predicate::assertion_state(
                        AssertionId::from_name("replicas-reconciled"),
                        AssertionPhase::Satisfied,
                    ),
                    deadline: VirtualTime {
                        ticks: PARTITION_CONVERGENCE_DEADLINE_TICKS,
                    },
                },
            },
        ],
    )
}

fn partition_recovery_plan(world: &World, properties: &Properties) -> Result<Plan, EngineError> {
    let heal_timer = partition_heal_timer();
    let graph = EventGraph::builder()
        .event("wait-ready")
        .when(Predicate::all_of(vec![
            Predicate::console_match(
                node("db-0"),
                RegexProgram::from_pattern("ready to accept connections"),
            ),
            Predicate::console_match(
                node("db-1"),
                RegexProgram::from_pattern("ready to accept connections"),
            ),
            Predicate::console_match(
                node("db-2"),
                RegexProgram::from_pattern("ready to accept connections"),
            ),
            Predicate::once(Predicate::coverage_point(
                node("db-0"),
                CodePoint::guest_address(0x4010),
            )),
        ]))
        .action(Action::arm_timer(
            heal_timer.clone(),
            SimDuration {
                nanos: PARTITION_HEAL_DELAY_TICKS,
            },
        ))
        .event("heal")
        .when(Predicate::timer(heal_timer))
        .action(Action::log(
            LogLevel::Info,
            "partition recovery interval ended",
        ))
        .event("pass-on-converge")
        .when(Predicate::all_of(vec![
            Predicate::once(Predicate::assertion_state(
                AssertionId::from_name("replicas-reconciled"),
                AssertionPhase::Satisfied,
            )),
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
                    trigger: Predicate::once(Predicate::console_match(
                        node("client"),
                        RegexProgram::from_pattern("(^|\\n)CLIENT_STARTED(\\r?\\n|$)"),
                    )),
                    property: Predicate::all_of(vec![
                        Predicate::console_match(
                            node("client"),
                            RegexProgram::from_pattern(
                                "(^|\\n)CLIENT_RESULT requests=100 successful=100 failed=0(\\r?\\n|$)",
                            ),
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
            Predicate::once(Predicate::assertion_state(
                AssertionId::from_name("all-requests-succeed"),
                AssertionPhase::Satisfied,
            )),
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
            b"client ready\nCLIENT_STARTED\n".to_vec(),
        ),
        ObservableEvent::console_output(
            VirtualTime {
                ticks: HAPPY_PATH_TERMINAL_TICKS,
            },
            node("client"),
            b"CLIENT_RESULT requests=100 successful=100 failed=0\n".to_vec(),
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

fn happy_path_replay_steps(observations: &[ObservableEvent]) -> Vec<ExampleReplayStep> {
    observations
        .iter()
        .cloned()
        .map(|observation| ExampleReplayStep::Observations(vec![observation]))
        .chain(std::iter::once(ExampleReplayStep::QuantumBoundary(
            HAPPY_PATH_TERMINAL_TICKS,
        )))
        .collect()
}

fn partition_recovery_replay_steps() -> Vec<ExampleReplayStep> {
    vec![
        ExampleReplayStep::Observations(vec![
            ObservableEvent::console_output(
                VirtualTime { ticks: 10 },
                node("db-0"),
                b"db-0 ready to accept connections\n".to_vec(),
            ),
            ObservableEvent::console_output(
                VirtualTime { ticks: 10 },
                node("db-1"),
                b"db-1 ready to accept connections\n".to_vec(),
            ),
            ObservableEvent::console_output(
                VirtualTime { ticks: 10 },
                node("db-2"),
                b"db-2 ready to accept connections\n".to_vec(),
            ),
            ObservableEvent::coverage_block(Icount { retired: 10 }, node("db-0"), 0x4000, 0x20),
        ]),
        ExampleReplayStep::QuantumBoundary(10 + PARTITION_HEAL_DELAY_TICKS),
        ExampleReplayStep::Observations(vec![guest_assertion_observation(
            20 + PARTITION_HEAL_DELAY_TICKS,
            "db-0",
            "replicas-reconciled",
            "replicas report matching logs after the partition heals",
            GuestAssertionKind::Sometimes,
            true,
            true,
        )]),
    ]
}

fn crash_restart_replay_steps() -> Vec<ExampleReplayStep> {
    let restart_ticks = CRASH_RESTART_COMMIT_TICKS + CRASH_RESTART_DELAY_TICKS;
    vec![
        ExampleReplayStep::Observations(vec![
            ObservableEvent::node_state(
                VirtualTime {
                    ticks: CRASH_RESTART_COMMIT_TICKS,
                },
                node("db-1"),
                NodeLifecycle::Started,
            ),
            ObservableEvent::io_completion(
                VirtualTime {
                    ticks: CRASH_RESTART_COMMIT_TICKS,
                },
                node("db-1"),
                IoEventKind::BlockWrite,
                b"region=wal commit_index=42 durable=true".to_vec(),
            ),
        ]),
        ExampleReplayStep::QuantumBoundary(restart_ticks),
        ExampleReplayStep::Observations(vec![
            guest_assertion_observation(
                restart_ticks + 10,
                "db-0",
                "committed-write-survived",
                "a replica confirms that the committed write survived",
                GuestAssertionKind::Sometimes,
                true,
                true,
            ),
            guest_assertion_observation(
                restart_ticks + 10,
                "db-0",
                "replicas-reconciled",
                "replicas report matching logs after db-1 restarts",
                GuestAssertionKind::Sometimes,
                true,
                true,
            ),
        ]),
    ]
}

fn fault_campaign_coverage_feedback() -> Result<Vec<EventLogCoverageFeedback>, SchedulerError> {
    let mut first = EventLog::new();
    let first_append = first.append_observable_events(vec![
        ObservableEvent::coverage_block(Icount { retired: 10 }, node("node-0"), 0x4010, 0x20),
        ObservableEvent::coverage_marker(
            Icount { retired: 11 },
            node("node-1"),
            MarkerId::from_name("a4-election-window"),
        ),
    ])?;
    let mut second = EventLog::new();
    let second_append = second.append_observable_events(vec![
        ObservableEvent::coverage_block(Icount { retired: 12 }, node("node-2"), 0x5020, 0x20),
        ObservableEvent::coverage_marker(
            Icount { retired: 13 },
            node("node-0"),
            MarkerId::from_name("a4-split-brain-probe"),
        ),
    ])?;
    Ok(vec![
        EventLogCoverageFeedback::from_event_log(&first_append.entries),
        EventLogCoverageFeedback::from_event_log(&second_append.entries),
    ])
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultCampaignViolationEvidence {
    observations: Vec<ObservableEvent>,
    event_log: Vec<u8>,
    recorded_log: RecordedAssertionLog,
    report: HostAssertionReport,
}

fn fault_campaign_violation_evidence(
    scenario: &ScenarioDefForm,
) -> Result<FaultCampaignViolationEvidence, ExampleCorpusError> {
    let observations = vec![guest_assertion_observation(
        30,
        "node-0",
        "no-split-brain",
        "the store must not publish split-brain evidence",
        GuestAssertionKind::Unreachable,
        true,
        false,
    )];
    let mut event_log = EventLog::new();
    let append = event_log.append_observable_events(observations.clone())?;
    let recorded_log = RecordedAssertionLog::from_segments(vec![append.entries.clone()])
        .map_err(ExampleCorpusError::FaultCampaignViolationLog)?;
    let mut oracle = BlackBoxHostOracle;
    let mut evaluator = HostAssertionEvaluator::new(scenario.properties())
        .with_world_white_box_policies(scenario.world());
    let report = evaluator.finalize_prefix(event_log.condition_prefix(), &mut oracle);
    let no_split_brain_violated = report.outcomes().iter().any(|outcome| {
        outcome.assertion.name == "no-split-brain"
            && outcome.kind == HostAssertionOutcomeKind::Violated
    });
    if !report.verdict().is_failed() || !no_split_brain_violated {
        return Err(ExampleCorpusError::FaultCampaignViolationMissing);
    }
    Ok(FaultCampaignViolationEvidence {
        observations,
        event_log: append.segment_bytes,
        recorded_log,
        report,
    })
}

fn fault_campaign_violation_decision(
    observations: &[ObservableEvent],
) -> Result<Decision, ExampleCorpusError> {
    Ok(Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: String::from(FAULT_CAMPAIGN_VIOLATION_POINT),
        },
        choice: ChoiceTag {
            name: encode_replay_step(
                FAULT_CAMPAIGN_FAMILY_NAME,
                &ExampleReplayStep::Observations(observations.to_vec()),
            )?,
        },
    }))
}

fn fault_campaign_replayed_violation_log_from_artifact(
    artifact: &ReproductionArtifact,
) -> Result<RecordedAssertionLog, ExampleCorpusError> {
    artifact.replay()?;
    let observations = fault_campaign_violation_observations_from_artifact(artifact)?;
    let mut event_log = EventLog::new();
    let append = event_log.append_observable_events(observations)?;
    RecordedAssertionLog::from_segments(vec![append.entries])
        .map_err(ExampleCorpusError::FaultCampaignViolationLog)
}

fn fault_campaign_violation_observations_from_artifact(
    artifact: &ReproductionArtifact,
) -> Result<Vec<ObservableEvent>, ExampleCorpusError> {
    let mut decoded = None;
    for decision in artifact.schedule().decisions() {
        let Decision::Override(override_decision) = decision else {
            continue;
        };
        if override_decision.point.key != FAULT_CAMPAIGN_VIOLATION_POINT {
            continue;
        }
        if decoded.is_some() {
            return Err(invalid_replay_schedule(
                FAULT_CAMPAIGN_FAMILY_NAME,
                "fault-campaign artifact contains multiple violation observations",
            ));
        }
        let ExampleReplayStep::Observations(observations) =
            decode_replay_step(FAULT_CAMPAIGN_FAMILY_NAME, &override_decision.choice.name)?
        else {
            return Err(invalid_replay_schedule(
                FAULT_CAMPAIGN_FAMILY_NAME,
                "fault-campaign artifact violation entry must encode observations",
            ));
        };
        decoded = Some(observations);
    }
    decoded.ok_or_else(|| {
        invalid_replay_schedule(
            FAULT_CAMPAIGN_FAMILY_NAME,
            "fault-campaign artifact is missing the violation observation",
        )
    })
}

fn fault_campaign_finding_fingerprint(
    iteration: &CoverageGuidedFuzzIteration,
    violation_report: &HostAssertionReport,
) -> ContentHash {
    let params = iteration.params;
    let violation_material = violation_report
        .violations()
        .iter()
        .map(|violation| {
            format!(
                "assertion={} kind={:?} at={} detail={}",
                violation.assertion.name,
                violation.quantifier,
                violation.at_virtual_time.ticks,
                violation.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ContentHash::from_canonical_material(
        "crucible.example-corpus.fault-campaign.finding.v1",
        &format!(
            "property=no-split-brain\nsequence={}\nsample_index={}\nseed={}\ntopology_size={}\ntopology_shape={:?}\nconfiguration={}\nviolation_count={}\n{}",
            iteration.sequence,
            iteration.sample_index,
            params.seed.to_hex(),
            params.topology_size,
            params.topology_shape,
            iteration.configuration_id().to_hex(),
            violation_report.violations().len(),
            violation_material
        ),
    )
}

fn fault_campaign_alternate_decision(config: CoverageGuidedFuzzConfig) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: format!("fault-campaign-neighborhood/{}", config.meta_seed.to_hex()),
        },
        choice: ChoiceTag {
            name: String::from("deliver-delayed-vote-first"),
        },
    })
}

fn baked_genesis_for_scenario(
    scenario: &ScenarioDefForm,
) -> Result<GenesisCheckpoint, EngineError> {
    let baked = bake(scenario.world())?;
    let genesis = Configuration::genesis(scenario.scenario_def());
    let checkpoint = Checkpoint::from_recorded_configuration(
        &genesis,
        None,
        VirtualTime::default(),
        baked.checkpoint.node_icounts,
        CheckpointKind::Fat,
        baked.checkpoint.node_blobs,
    )?;
    Ok(GenesisCheckpoint { checkpoint })
}

fn flatten_observations(steps: &[ExampleReplayStep]) -> Vec<ObservableEvent> {
    steps
        .iter()
        .flat_map(|step| match step {
            ExampleReplayStep::Observations(observations) => observations.clone(),
            ExampleReplayStep::QuantumBoundary(_) => Vec::new(),
        })
        .collect()
}

fn guest_assertion_observation(
    retired: u64,
    node_name: &str,
    assertion: &str,
    message: &str,
    kind: GuestAssertionKind,
    condition: bool,
    must_hit: bool,
) -> ObservableEvent {
    ObservableEvent::guest_assertion_marker(
        Icount { retired },
        node(node_name),
        GuestAssertionMarker::new(
            AssertionId::from_name(assertion),
            message,
            kind,
            condition,
            must_hit,
            vec![GuestAssertionDetail::new("scenario", assertion)],
            format!("example-corpus/{assertion}"),
        ),
    )
}

fn partition_heal_timer() -> TimerId {
    TimerId {
        name: String::from("heal-after"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExampleScenarioRunCore {
    canonical_event_log: Vec<u8>,
    fingerprint_stream: Vec<u8>,
    assertion_report: HostAssertionReport,
    firings: EventFirings,
    scheduler_topology_change_applications: Vec<SchedulerTopologyChangeApplication>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExampleReplayStep {
    Observations(Vec<ObservableEvent>),
    QuantumBoundary(u64),
}

fn run_example_scenario_material(
    scenario_name: &str,
    scenario: &ScenarioDefForm,
    steps: &[ExampleReplayStep],
) -> Result<ExampleScenarioRunCore, ExampleCorpusError> {
    let graph = scenario.plan().event_graph();
    let scheduler_nodes = example_scheduler_nodes(scenario.world());
    let scheduler_edges = example_scheduler_edges(scenario.world());
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            scenario_name,
            Shift { bits: 0 },
            16,
            SimInstant {
                nanos: scenario_run_time_limit(steps),
            },
            scheduler_nodes,
            Vec::new(),
        )
        .with_trigger_world(scenario.world())
        .with_effective_topology_edges(scheduler_edges),
    )?;
    let mut canonical_event_log = Vec::new();
    let mut assertion_oracle = BlackBoxHostOracle;
    let mut assertion_evaluator = HostAssertionEvaluator::new(scenario.properties())
        .with_world_white_box_policies(scenario.world());
    let mut state = EventGraphState::new();
    let mut observed_trigger_actions = 0;
    let mut pass_firings = None;

    for step in steps {
        let append = match step {
            ExampleReplayStep::Observations(observations) => {
                scheduler.append_observable_events(observations.clone())?
            }
            ExampleReplayStep::QuantumBoundary(ticks) => scheduler.append_evaluation_boundary(
                VirtualTime { ticks: *ticks },
                SchedulerEvaluationBoundaryKind::Quantum,
            )?,
        };
        canonical_event_log.extend_from_slice(&append.segment_bytes);
        if let Some(firings) = settle_example_step(
            &mut scheduler,
            graph,
            &mut state,
            scenario.world(),
            &mut assertion_evaluator,
            &mut assertion_oracle,
            &mut canonical_event_log,
            &mut observed_trigger_actions,
        )? {
            pass_firings = Some(firings);
        }
    }

    let Some(firings) = pass_firings else {
        return Err(ExampleCorpusError::DidNotPass {
            scenario: scenario_name.to_owned(),
        });
    };
    let assertion_report = assertion_evaluator.finalize_prefix(
        scheduler.condition_event_log_prefix(),
        &mut assertion_oracle,
    );
    if assertion_report.verdict().is_failed() {
        return Err(ExampleCorpusError::AssertionsFailed {
            scenario: scenario_name.to_owned(),
            failures: assertion_report.verdict().failures().len(),
        });
    }

    let fingerprint_stream =
        example_fingerprint_stream(scenario_name, scenario, &canonical_event_log);
    Ok(ExampleScenarioRunCore {
        canonical_event_log,
        fingerprint_stream,
        assertion_report,
        firings,
        scheduler_topology_change_applications: scheduler.topology_change_applications().to_vec(),
    })
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn settle_example_step(
    scheduler: &mut SingleScheduler,
    graph: &EventGraph,
    state: &mut EventGraphState,
    world: &World,
    assertion_evaluator: &mut HostAssertionEvaluator,
    assertion_oracle: &mut BlackBoxHostOracle,
    canonical_event_log: &mut Vec<u8>,
    observed_trigger_actions: &mut usize,
) -> Result<Option<EventFirings>, ExampleCorpusError> {
    let mut pass_firings = None;
    loop {
        observe_assertions_and_append_state_events(
            scheduler,
            canonical_event_log,
            assertion_evaluator,
            assertion_oracle,
        )?;
        let firings = evaluate_example_graph(scheduler, graph, state, world)?;
        if firings.is_empty() {
            break;
        }
        if firings.iter().any(|firing| action_passes(firing.action())) {
            pass_firings = Some(firings.clone());
        }
        let action_append = scheduler.apply_trigger_firings(&firings)?;
        canonical_event_log.extend_from_slice(&action_append.segment_bytes);
        scheduler.apply_queued_topology_changes_at_boundary()?;
        append_trigger_lifecycle_events(scheduler, canonical_event_log, observed_trigger_actions)?;
    }
    Ok(pass_firings)
}

fn append_trigger_lifecycle_events(
    scheduler: &mut SingleScheduler,
    canonical_event_log: &mut Vec<u8>,
    observed_trigger_actions: &mut usize,
) -> Result<(), ExampleCorpusError> {
    let applications = scheduler.trigger_actions().applications.clone();
    let events = applications
        .iter()
        .skip(*observed_trigger_actions)
        .filter_map(trigger_lifecycle_event)
        .collect::<Vec<_>>();
    *observed_trigger_actions = applications.len();
    if events.is_empty() {
        return Ok(());
    }
    let append = scheduler.append_observable_events(events)?;
    canonical_event_log.extend_from_slice(&append.segment_bytes);
    Ok(())
}

fn trigger_lifecycle_event(application: &TriggerActionApplication) -> Option<ObservableEvent> {
    match &application.action {
        Action::StopNode { node } => Some(ObservableEvent::node_state(
            application.at,
            node.clone(),
            NodeLifecycle::Crashed,
        )),
        Action::StartNode { node } => Some(ObservableEvent::node_state(
            application.at,
            node.clone(),
            NodeLifecycle::Started,
        )),
        Action::Group(_)
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => None,
    }
}

fn observe_assertions_and_append_state_events(
    scheduler: &mut SingleScheduler,
    canonical_event_log: &mut Vec<u8>,
    assertion_evaluator: &mut HostAssertionEvaluator,
    assertion_oracle: &mut BlackBoxHostOracle,
) -> Result<(), ExampleCorpusError> {
    let outcomes = assertion_evaluator
        .observe_prefix(scheduler.condition_event_log_prefix(), assertion_oracle);
    let events = outcomes
        .iter()
        .filter_map(assertion_state_event_from_outcome)
        .collect::<Vec<_>>();
    if events.is_empty() {
        return Ok(());
    }
    let append = scheduler.append_observable_events(events)?;
    canonical_event_log.extend_from_slice(&append.segment_bytes);
    assertion_evaluator.observe_prefix(scheduler.condition_event_log_prefix(), assertion_oracle);
    Ok(())
}

fn assertion_state_event_from_outcome(outcome: &HostAssertionOutcome) -> Option<ObservableEvent> {
    let state = match outcome.kind {
        HostAssertionOutcomeKind::Satisfied => AssertionPhase::Satisfied,
        HostAssertionOutcomeKind::Violated => AssertionPhase::Violated,
        HostAssertionOutcomeKind::Passed
        | HostAssertionOutcomeKind::Warning
        | HostAssertionOutcomeKind::NeverEvaluated
        | HostAssertionOutcomeKind::NeverTriggered
        | HostAssertionOutcomeKind::NeverReachedWarn
        | HostAssertionOutcomeKind::NeverReachedFail => return None,
    };
    Some(ObservableEvent::assertion_state_changed(
        outcome.at,
        outcome.assertion.clone(),
        state,
    ))
}

fn evaluate_example_graph(
    scheduler: &SingleScheduler,
    graph: &EventGraph,
    state: &mut EventGraphState,
    world: &World,
) -> Result<EventFirings, ExampleCorpusError> {
    let mut pass = ConditionEvaluationPass::from_log_prefix(
        scheduler.condition_event_log_prefix().clone(),
        NoNamedLeaves,
    )
    .with_timer_fires(scheduler.trigger_actions().armed_timers.clone())
    .with_scheduler_quiescence(scheduler.quiescence()?)
    .with_world_white_box_policies(world);
    Ok(pass.evaluate_event_graph(graph, state))
}

fn scenario_run_time_limit(steps: &[ExampleReplayStep]) -> u64 {
    steps
        .iter()
        .map(|step| match step {
            ExampleReplayStep::Observations(observations) => observations
                .iter()
                .map(|observation| observation.at().ticks)
                .max()
                .unwrap_or(0),
            ExampleReplayStep::QuantumBoundary(ticks) => *ticks,
        })
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn example_scheduler_nodes(world: &World) -> Vec<SchedulerScenarioNode> {
    world
        .vm_nodes()
        .iter()
        .map(|node| SchedulerScenarioNode {
            id: example_scheduler_node(&node.id),
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Idle,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        })
        .collect()
}

fn example_scheduler_edges(world: &World) -> Vec<SchedulerLookaheadEdge> {
    world
        .links()
        .iter()
        .flat_map(|link| {
            let (left, right) = link.endpoints();
            let left = example_scheduler_node(left);
            let right = example_scheduler_node(right);
            [
                SchedulerLookaheadEdge::new(left.clone(), right.clone(), link.latency()),
                SchedulerLookaheadEdge::new(right, left, link.latency()),
            ]
        })
        .collect()
}

fn example_scheduler_node(node: &NodeId) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node.clone(),
        kind: SchedulingNodeKind::Vm,
    }
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
    let replay_steps = example_script_from_schedule(scenario_name, reproduction.schedule())?;
    run_example_scenario_material(scenario_name, reproduction.scenario_form(), &replay_steps)
}

fn happy_path_schedule(observations: &[ObservableEvent]) -> Result<Schedule, ExampleCorpusError> {
    example_schedule(
        HAPPY_PATH_SCENARIO_NAME,
        &happy_path_replay_steps(observations),
    )
}

fn example_schedule(
    scenario_name: &str,
    steps: &[ExampleReplayStep],
) -> Result<Schedule, ExampleCorpusError> {
    let mut schedule = Schedule::empty();
    for (index, step) in steps.iter().enumerate() {
        schedule = schedule.appended(Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: example_replay_step_point(scenario_name, index),
            },
            choice: ChoiceTag {
                name: encode_replay_step(scenario_name, step)?,
            },
        }));
    }
    Ok(schedule)
}

fn example_script_from_schedule(
    scenario_name: &str,
    schedule: &Schedule,
) -> Result<Vec<ExampleReplayStep>, ExampleCorpusError> {
    let mut steps = Vec::new();
    let expected_prefix = format!("{EXAMPLE_REPLAY_STEP_POINT_PREFIX}{scenario_name}/");
    for decision in schedule.decisions() {
        let Decision::Override(override_decision) = decision else {
            return Err(invalid_replay_schedule(
                scenario_name,
                "schedule contains a non-override decision",
            ));
        };
        let Some(index) = override_decision.point.key.strip_prefix(&expected_prefix) else {
            return Err(invalid_replay_schedule(
                scenario_name,
                format!(
                    "unknown replay scheduling point `{}`",
                    override_decision.point.key
                ),
            ));
        };
        let expected_index = steps.len().to_string();
        if index != expected_index {
            return Err(invalid_replay_schedule(
                scenario_name,
                format!("step index `{index}` did not follow `{expected_index}`"),
            ));
        }
        steps.push(decode_replay_step(
            scenario_name,
            &override_decision.choice.name,
        )?);
    }
    if steps.is_empty() {
        return Err(invalid_replay_schedule(
            scenario_name,
            "schedule is missing replay steps",
        ));
    }
    Ok(steps)
}

fn example_replay_step_point(scenario_name: &str, index: usize) -> String {
    format!("{EXAMPLE_REPLAY_STEP_POINT_PREFIX}{scenario_name}/{index}")
}

fn encode_replay_step(
    scenario_name: &str,
    step: &ExampleReplayStep,
) -> Result<String, ExampleCorpusError> {
    match step {
        ExampleReplayStep::Observations(observations) => {
            let mut encoded = Vec::with_capacity(observations.len());
            for observation in observations {
                encoded.push(encode_observation(scenario_name, observation)?);
            }
            Ok(format!("observations|{}", encoded.join(";")))
        }
        ExampleReplayStep::QuantumBoundary(ticks) => Ok(format!("quantum-boundary|{ticks}")),
    }
}

fn decode_replay_step(
    scenario_name: &str,
    encoded: &str,
) -> Result<ExampleReplayStep, ExampleCorpusError> {
    if let Some(observations) = encoded.strip_prefix("observations|") {
        let observations = if observations.is_empty() {
            Vec::new()
        } else {
            observations
                .split(';')
                .map(|observation| decode_observation(scenario_name, observation))
                .collect::<Result<Vec<_>, _>>()?
        };
        return Ok(ExampleReplayStep::Observations(observations));
    }
    Ok(ExampleReplayStep::QuantumBoundary(decode_boundary_ticks(
        scenario_name,
        encoded,
    )?))
}

fn encode_observation(
    scenario_name: &str,
    observation: &ObservableEvent,
) -> Result<String, ExampleCorpusError> {
    match observation.payload() {
        ObservableEventPayload::ConsoleOutput { node, bytes } => Ok(format!(
            "console-output|{}|{}|{}",
            observation.at().ticks,
            node.name,
            bytes_hex(bytes)
        )),
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            guest_pc,
            block_len,
        } => Ok(format!(
            "coverage-block|{}|{}|{}|{}",
            execution_icount.retired, node.name, guest_pc, block_len
        )),
        ObservableEventPayload::IoCompletion {
            node,
            kind,
            payload,
        } => Ok(format!(
            "io-completion|{}|{}|{}|{}",
            observation.at().ticks,
            node.name,
            encode_io_event_kind(*kind),
            bytes_hex(payload)
        )),
        ObservableEventPayload::NodeState { node, state } => Ok(format!(
            "node-state|{}|{}|{}",
            observation.at().ticks,
            node.name,
            encode_node_lifecycle(*state)
        )),
        ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } => Ok(format!(
            "guest-assertion-marker|{}|{}|{}",
            retired_icount.retired,
            node.name,
            encode_guest_assertion_marker(scenario_name, marker)?,
        )),
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::MemorySample { .. }
        | ObservableEventPayload::AssertionProximity { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::GuestMarker { .. } => Err(invalid_replay_schedule(
            scenario_name,
            "unsupported observation kind in example replay script",
        )),
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
        ["node-state", ticks, node_name, state] => Ok(ObservableEvent::node_state(
            decode_ticks(scenario_name, ticks)?,
            node(node_name),
            decode_node_lifecycle(scenario_name, state)?,
        )),
        ["coverage-block", retired, node_name, guest_pc, block_len] => {
            Ok(ObservableEvent::coverage_block(
                Icount {
                    retired: decode_u64(scenario_name, retired, "coverage icount")?,
                },
                node(node_name),
                decode_u64(scenario_name, guest_pc, "coverage guest pc")?,
                decode_u32(scenario_name, block_len, "coverage block length")?,
            ))
        }
        ["io-completion", ticks, node_name, kind, payload] => Ok(ObservableEvent::io_completion(
            decode_ticks(scenario_name, ticks)?,
            node(node_name),
            decode_io_event_kind(scenario_name, kind)?,
            bytes_from_hex(scenario_name, payload)?,
        )),
        ["guest-assertion-marker", retired, node_name, marker] => {
            Ok(ObservableEvent::guest_assertion_marker(
                Icount {
                    retired: decode_u64(scenario_name, retired, "guest assertion icount")?,
                },
                node(node_name),
                decode_guest_assertion_marker(scenario_name, marker)?,
            ))
        }
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

fn decode_u32(scenario_name: &str, value: &str, label: &str) -> Result<u32, ExampleCorpusError> {
    value.parse::<u32>().map_err(|_| {
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

fn encode_io_event_kind(kind: IoEventKind) -> &'static str {
    match kind {
        IoEventKind::Any => "any",
        IoEventKind::BlockRead => "block-read",
        IoEventKind::BlockWrite => "block-write",
        IoEventKind::Fsync => "fsync",
        IoEventKind::NineP => "ninep",
        IoEventKind::Network => "network",
    }
}

fn decode_io_event_kind(
    scenario_name: &str,
    kind: &str,
) -> Result<IoEventKind, ExampleCorpusError> {
    match kind {
        "any" => Ok(IoEventKind::Any),
        "block-read" => Ok(IoEventKind::BlockRead),
        "block-write" => Ok(IoEventKind::BlockWrite),
        "fsync" => Ok(IoEventKind::Fsync),
        "ninep" => Ok(IoEventKind::NineP),
        "network" => Ok(IoEventKind::Network),
        _ => Err(invalid_replay_schedule(
            scenario_name,
            format!("unknown I/O event kind `{kind}`"),
        )),
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

fn encode_guest_assertion_marker(
    scenario_name: &str,
    marker: &GuestAssertionMarker,
) -> Result<String, ExampleCorpusError> {
    let payload = WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
        flavor: guest_assertion_flavor(marker.kind),
        condition: marker.condition,
        must_hit: marker.must_hit,
        id: marker.id.name.clone(),
        message: marker.message.clone(),
        location: marker.location.clone(),
        details: marker
            .details
            .iter()
            .map(|detail| WhiteboxMarkerDetail::new(&detail.key, &detail.value))
            .collect(),
    });
    encode_whitebox_marker_frame(&payload)
        .map(|frame| bytes_hex(&frame))
        .map_err(|error| invalid_replay_schedule(scenario_name, error.to_string()))
}

fn decode_guest_assertion_marker(
    scenario_name: &str,
    marker: &str,
) -> Result<GuestAssertionMarker, ExampleCorpusError> {
    let frame = WhiteboxDoorbellFrame::decode(&bytes_from_hex(scenario_name, marker)?)
        .map_err(|error| invalid_replay_schedule(scenario_name, error.to_string()))?;
    let WhiteboxMarkerPayload::Assertion(body) = decode_whitebox_marker_payload(&frame)
        .map_err(|error| invalid_replay_schedule(scenario_name, error.to_string()))?
    else {
        return Err(invalid_replay_schedule(
            scenario_name,
            "guest assertion record carries a non-assertion doorbell frame",
        ));
    };
    Ok(guest_assertion_marker_from_whitebox_body(&body))
}

fn guest_assertion_flavor(kind: GuestAssertionKind) -> WhiteboxAssertionMarkerFlavor {
    match kind {
        GuestAssertionKind::Always => WhiteboxAssertionMarkerFlavor::Always,
        GuestAssertionKind::Sometimes => WhiteboxAssertionMarkerFlavor::Sometimes,
        GuestAssertionKind::Reachable => WhiteboxAssertionMarkerFlavor::Reachable,
        GuestAssertionKind::Unreachable => WhiteboxAssertionMarkerFlavor::Unreachable,
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
    if !hex.len().is_multiple_of(2) {
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
        Action::ArmTimer { .. }
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
