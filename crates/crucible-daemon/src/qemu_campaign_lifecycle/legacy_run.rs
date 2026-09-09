//! Shared ownership for one guarded, scenario-default campaign run.
//!
//! This compatibility owner translates a single legacy run request into the
//! same authenticated repository, planner, executor, and observation flow used
//! by long-lived campaigns. The caller supplies explicit immutable inputs and
//! guarded host capabilities; the returned record contains only bounded,
//! accepted campaign results and scheduler-authored evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

// crucible-lint: allow host-nondeterminism-state -- decoded configurations are authenticated repository artifacts returned after campaign acceptance.
use crucible::{Checkpoint, CheckpointKind, Configuration};
use crucible::{ScenarioDefForm, Schedule, Seed, VirtualTime};
// crucible-lint: allow host-nondeterminism-state -- the caller supplies a validated production lifecycle capability; host observations cannot alter modeled choices.
use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{
    ApplyCampaignCommandRequest, Attempt, AttemptResourceLimits, AttemptStart,
    AuthorizedPlannerService, AuthorizedPlannerServiceError, BranchBudget, BranchRequest,
    BranchRequestCause, BudgetGrant, CampaignAuthorizationError, CampaignClient,
    CampaignClientError, CampaignCodecError, CampaignCommandId, CampaignControlAction,
    CampaignExecutorDriver, CampaignExecutorDriverConfigError, CampaignExecutorStepOutcome,
    CampaignExecutorStore, CampaignFact, CampaignFactId, CampaignHash, CampaignLineage,
    CampaignMode, CampaignName, CampaignPlannerDriver, CampaignPlannerDriverConfigError,
    CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignRepository, CampaignRepositoryError,
    CampaignSeed, CampaignServiceOperation, CampaignSnapshotId, CampaignState, CampaignSupervisor,
    CampaignSupervisorConfigError, CampaignSupervisorError, CampaignSupervisorStepOutcome,
    CandidateSource, CreateCampaignRequest, DaemonEpoch, DebuggerAuthorityKey, DiscoveryRequest,
    ExactCheckpointId, ExecutionRetentionIntent, ExecutorCompatibilityProfile, ExplorerPolicy,
    FairnessPolicy, Observation, ObservationId, PlannerAuthorityKey, PlannerClient, PlanningBudget,
    RepositoryCampaignService, RetentionPolicy, SavepointCaptureOutcome, SavepointCaptureRequest,
    SavepointContinuationSelection, StopCondition, StopOutcome, SubmitCampaignBranchRequest,
    SubmitCampaignDiscoveryRequest,
};
use crucible_cas::content_store::{
    ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend, MutableRefBackend,
};
use thiserror::Error;

use super::{
    QemuAttemptExecutionEvidence, QemuAttemptExecutionEvidenceSnapshot,
    QemuAttemptProductionVmLifecycleError, QemuAttemptProductionVmLifecycleFactory,
    QemuFreshExecutionRunner, QemuFreshExecutionRunnerError, QemuFreshScenarioResourceError,
    QemuObservedFreshAttemptLifecycleFactory, QemuObservedFreshAttemptLifecycleFactoryError,
    validate_fresh_qemu_scenario_resources,
};
use crate::{
    ComposedQemuAttemptResourceGuardFactory, CrucibleArtifactError, CrucibleCampaignArtifactStore,
    CrucibleExecutionModel, CrucibleExecutionModelError, CrucibleExecutionRunner,
    ExactCheckpointStore, ExactCheckpointStoreError, ExecutorCapacityError,
    LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostResourceFactory, QemuFreshModeledDriver,
    QemuFreshModeledDriverError, RepositoryAttemptAdmission,
    decode_crucible_configuration_artifact_with_selections,
};

mod executor;
use executor::{
    LocalPlannerMeter, LocalPlannerMeterError, SynchronousCampaignExecutor,
    SynchronousCampaignExecutorError,
};

mod replay_closure;
pub use replay_closure::{GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError};

mod resume;
pub use resume::GuardedDefaultCampaignResumeProof;
use resume::{
    DefaultRunResumeProgress, DefaultRunResumeProof, GuardedDefaultCampaignResumeSource,
    materialize_resume_proof, validate_resume_source,
};

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

const DEFAULT_RUN_MAX_CHOICES: u64 = 65_536;
const DEFAULT_RUN_REPOSITORY_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_RUN_EXECUTOR_SCAN: usize = 1_024;
const DEFAULT_RUN_PLANNER_SCAN: u32 = 1_024;
const DEFAULT_RUN_MAX_SUPERVISOR_STEPS: usize = 1_000_000;
const DEFAULT_RUN_RECONCILIATION_STEPS: usize = 64;

type DefaultPlannerService =
    AuthorizedPlannerService<crucible_campaign::CanonicalBeamPlanner, LocalPlannerMeter>;
type DefaultPlannerServiceError =
    AuthorizedPlannerServiceError<CampaignCodecError, LocalPlannerMeterError>;
type DefaultExecutorService<R> = SynchronousCampaignExecutor<CrucibleExecutionModel<R>>;
type DefaultExecutorServiceError<E> =
    SynchronousCampaignExecutorError<CrucibleExecutionModelError<E>>;
type DefaultSupervisorError<E> =
    CampaignSupervisorError<DefaultPlannerServiceError, DefaultExecutorServiceError<E>>;

/// Concrete production-runner failure used by the guarded CLI campaign owner.
pub type GuardedDefaultCampaignProductionRunnerError = QemuFreshExecutionRunnerError<
    QemuObservedFreshAttemptLifecycleFactoryError<QemuAttemptProductionVmLifecycleError>,
    QemuFreshModeledDriverError,
>;

/// Typed shared-owner failure while advancing one guarded campaign.
#[derive(Debug)]
pub struct GuardedDefaultCampaignSupervisorError<E = GuardedDefaultCampaignProductionRunnerError>(
    Box<DefaultSupervisorError<E>>,
);

impl<E> fmt::Display for GuardedDefaultCampaignSupervisorError<E>
where
    E: Error + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<E> Error for GuardedDefaultCampaignSupervisorError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Immutable inputs and resource authority for one guarded default campaign.
pub struct GuardedDefaultCampaignRunRequest {
    scenario: ScenarioDefForm,
    seed: Seed,
    engine_build_id: String,
    qemu_build_id: String,
    lifecycle: ProductionVmLifecycleConfig,
    host: LinuxQemuAttemptHostConfig,
    resources: AttemptResourceLimits,
    initial_schedule: Schedule,
    initial_replay_closure: Option<GuardedCampaignReplayClosure>,
    discovery_stop: StopCondition,
    collect_watch_frames: bool,
    capture_reached_stop: Option<Arc<ExactCheckpointStore>>,
    resume_source: Option<GuardedDefaultCampaignResumeSource>,
}

impl GuardedDefaultCampaignRunRequest {
    /// Creates one request from explicit modeled identity and guarded host inputs.
    #[must_use]
    pub fn new(
        scenario: ScenarioDefForm,
        seed: Seed,
        engine_build_id: impl Into<String>,
        qemu_build_id: impl Into<String>,
        lifecycle: ProductionVmLifecycleConfig,
        host: LinuxQemuAttemptHostConfig,
        resources: AttemptResourceLimits,
    ) -> Self {
        Self {
            scenario,
            seed,
            engine_build_id: engine_build_id.into(),
            qemu_build_id: qemu_build_id.into(),
            lifecycle,
            host,
            resources,
            initial_schedule: Schedule::empty(),
            initial_replay_closure: None,
            discovery_stop: StopCondition::NextChoice,
            collect_watch_frames: false,
            capture_reached_stop: None,
            resume_source: None,
        }
    }

    /// Starts discovery from an authenticated recorded schedule and choice closure.
    ///
    /// This is the campaign replay adapter: the executor re-materializes the
    /// supplied configuration before publishing any observation. The schedule
    /// remains modeled input and does not weaken host resource ownership.
    #[must_use]
    pub fn with_initial_replay(
        mut self,
        schedule: Schedule,
        closure: GuardedCampaignReplayClosure,
    ) -> Self {
        self.initial_schedule = schedule;
        self.initial_replay_closure = Some(closure);
        self
    }

    /// Uses an explicit semantic stop for the initial campaign discovery.
    ///
    /// The request is admitted through [`crucible_campaign::CampaignService`]
    /// after the campaign is funded and running, before its supervisor can
    /// perform automatic discovery.
    #[must_use]
    pub fn with_discovery_stop(mut self, stop: StopCondition) -> Self {
        self.discovery_stop = stop;
        self
    }

    /// Retains bounded authenticated campaign progress frames for CLI watch output.
    #[must_use]
    pub const fn with_watch_frames(mut self) -> Self {
        self.collect_watch_frames = true;
        self
    }

    /// Captures the initial discovery attempt after it reaches its declared stop.
    ///
    /// The exact store receives a physical checkpoint closure before the
    /// campaign is completed. A terminal outcome reached before the requested
    /// stop fails closed without reporting a savepoint. The caller owns the
    /// store's lifetime and retention policy; the returned checkpoint ID does
    /// not retain this ephemeral campaign repository or its physical closure.
    #[must_use]
    pub fn with_reached_stop_savepoint_capture(
        mut self,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Self {
        self.capture_reached_stop = Some(checkpoints);
        self
    }

    /// Resumes an authenticated selection-free legacy checkpoint through one campaign.
    ///
    /// The source schedule is first replayed to the exact logical checkpoint
    /// frontier. Only after the accepted configuration and scheduler frontier
    /// equal `checkpoint` does the owner capture an exact physical savepoint and
    /// admit an [`AttemptStart::AfterAttempt`] continuation to `final_stop`.
    /// Historical schedules that require typed selection records are rejected;
    /// their existing session-owned resume path must retain the producer's
    /// complete choice closure.
    #[must_use]
    pub fn with_selection_free_resume_source(
        mut self,
        // crucible-lint: allow host-nondeterminism-state -- the caller-supplied replay schedule is forwarded unchanged into exact source authentication.
        schedule: Schedule,
        closure: GuardedCampaignReplayClosure,
        checkpoint: Checkpoint,
        final_stop: StopCondition,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Self {
        self.initial_schedule = schedule;
        self.initial_replay_closure = Some(closure);
        self.discovery_stop = StopCondition::VirtualTimeNanoseconds(checkpoint.virtual_time.ticks);
        self.resume_source = Some(GuardedDefaultCampaignResumeSource {
            checkpoint,
            final_stop,
            checkpoints,
        });
        self
    }
}

/// One authenticated observation and bounded child metadata used by the CLI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedDefaultCampaignObservation {
    id: ObservationId,
    observation: Observation,
    virtual_time_ticks: u64,
}

impl GuardedDefaultCampaignObservation {
    /// Returns the content identity of the accepted observation.
    #[must_use]
    pub const fn id(&self) -> ObservationId {
        self.id
    }

    /// Returns the authenticated modeled observation.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }

    /// Returns the child schedule's recorded virtual-time frontier in ticks.
    #[must_use]
    pub const fn virtual_time_ticks(&self) -> u64 {
        self.virtual_time_ticks
    }
}

/// One authenticated campaign head paired with its exact execution boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedDefaultCampaignWatchFrame {
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    state: CampaignState,
    frontier: crucible::VirtualTime,
    quanta: u64,
    observation: Option<ObservationId>,
}

impl GuardedDefaultCampaignWatchFrame {
    /// Returns the campaign whose authenticated head produced this frame.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact authenticated campaign snapshot observed by the owner.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the lifecycle state projected from the exact snapshot.
    #[must_use]
    pub const fn state(&self) -> CampaignState {
        self.state
    }

    /// Returns the scheduler frontier recorded when the frame was captured.
    #[must_use]
    pub const fn frontier(&self) -> crucible::VirtualTime {
        self.frontier
    }

    /// Returns the absolute scheduler-quantum coordinate at that frontier.
    #[must_use]
    pub const fn quanta(&self) -> u64 {
        self.quanta
    }

    /// Returns the incorporated observation that advanced execution, if any.
    #[must_use]
    pub const fn observation(&self) -> Option<ObservationId> {
        self.observation
    }
}

/// Bounded immutable result of one completed guarded default campaign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedDefaultCampaignRun {
    campaign: CampaignName,
    final_snapshot: CampaignSnapshotId,
    observations: Vec<GuardedDefaultCampaignObservation>,
    terminal: GuardedDefaultCampaignObservation,
    terminal_configuration: Configuration,
    branch_request_count: usize,
    state_updates: Vec<CampaignState>,
    watch_frames: Vec<GuardedDefaultCampaignWatchFrame>,
    evidence: QemuAttemptExecutionEvidenceSnapshot,
    replay_closure: GuardedCampaignReplayClosure,
    savepoint: Option<GuardedDefaultCampaignSavepoint>,
    resume: Option<GuardedDefaultCampaignResumeProof>,
}

/// Authenticated physical savepoint captured for the terminal observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedDefaultCampaignSavepoint {
    request: CampaignFactId,
    attempt: crucible_campaign::AttemptId,
    checkpoint: ExactCheckpointId,
    configuration: crucible_campaign::ConfigurationId,
    stop: StopCondition,
    evidence: QemuAttemptExecutionEvidenceSnapshot,
}

impl GuardedDefaultCampaignSavepoint {
    /// Returns the immutable campaign fact that owns the capture scope.
    #[must_use]
    pub const fn request(&self) -> CampaignFactId {
        self.request
    }

    /// Returns the semantic attempt replayed for exact capture.
    #[must_use]
    pub const fn attempt(&self) -> crucible_campaign::AttemptId {
        self.attempt
    }

    /// Returns the authenticated physical checkpoint root.
    #[must_use]
    pub const fn checkpoint(&self) -> ExactCheckpointId {
        self.checkpoint
    }

    /// Returns the modeled configuration materialized by the checkpoint.
    #[must_use]
    pub const fn configuration(&self) -> crucible_campaign::ConfigurationId {
        self.configuration
    }

    /// Returns the exact stop condition replayed for capture.
    #[must_use]
    pub const fn stop(&self) -> &StopCondition {
        &self.stop
    }

    /// Returns the scheduler evidence recorded by the exact-capture replay.
    #[must_use]
    pub const fn evidence(&self) -> &QemuAttemptExecutionEvidenceSnapshot {
        &self.evidence
    }
}

impl GuardedDefaultCampaignRun {
    /// Returns the ephemeral campaign name used for authenticated operations.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the final completed campaign snapshot.
    #[must_use]
    pub const fn final_snapshot(&self) -> CampaignSnapshotId {
        self.final_snapshot
    }

    /// Returns every incorporated observation in acceptance order.
    #[must_use]
    pub fn observations(&self) -> &[GuardedDefaultCampaignObservation] {
        &self.observations
    }

    /// Returns the terminal incorporated observation.
    #[must_use]
    pub const fn terminal(&self) -> &GuardedDefaultCampaignObservation {
        &self.terminal
    }

    /// Returns the decoded configuration bound by the terminal observation.
    #[must_use]
    // crucible-lint: allow host-nondeterminism-state -- the returned configuration is decoded from the terminal observation's authenticated child artifact.
    pub const fn terminal_configuration(&self) -> &Configuration {
        &self.terminal_configuration
    }

    /// Returns the number of scenario-default branch requests accepted.
    #[must_use]
    pub const fn branch_request_count(&self) -> usize {
        self.branch_request_count
    }

    /// Returns authenticated campaign lifecycle states in observation order.
    #[must_use]
    pub fn state_updates(&self) -> &[CampaignState] {
        &self.state_updates
    }

    /// Returns authenticated campaign heads and their captured execution boundaries.
    #[must_use]
    pub fn watch_frames(&self) -> &[GuardedDefaultCampaignWatchFrame] {
        &self.watch_frames
    }

    /// Returns the bounded scheduler-authored evidence from the terminal attempt.
    #[must_use]
    pub const fn evidence(&self) -> &QemuAttemptExecutionEvidenceSnapshot {
        &self.evidence
    }

    /// Returns the exact choice-record closure needed to replay the terminal schedule.
    #[must_use]
    pub const fn replay_closure(&self) -> &GuardedCampaignReplayClosure {
        &self.replay_closure
    }

    /// Returns the authenticated physical savepoint when capture was requested.
    #[must_use]
    pub const fn savepoint(&self) -> Option<&GuardedDefaultCampaignSavepoint> {
        self.savepoint.as_ref()
    }

    /// Returns the authenticated legacy-resume admission, when requested.
    #[must_use]
    pub const fn resume(&self) -> Option<&GuardedDefaultCampaignResumeProof> {
        self.resume.as_ref()
    }
}

/// Failure while owning one guarded default campaign run.
#[derive(Debug, Error)]
pub enum GuardedDefaultCampaignRunError<E = GuardedDefaultCampaignProductionRunnerError>
where
    E: Error + 'static,
{
    /// A canonical campaign request or artifact record was invalid.
    #[error("guarded default campaign record is invalid: {0}")]
    Codec(#[source] CampaignCodecError),
    /// Crucible artifact encoding or decoding failed authentication.
    #[error("guarded default campaign artifact failed: {0}")]
    Artifact(#[source] CrucibleArtifactError),
    /// The campaign repository rejected a durable operation.
    #[error("guarded default campaign repository failed: {0}")]
    Repository(#[source] CampaignRepositoryError),
    /// Objective evidence replay or publication failed.
    #[error("guarded default campaign objective evaluation failed: {0}")]
    Objective(#[source] crate::ObjectiveEvaluationDriverError),
    /// Reserving bounded result storage failed.
    #[error("guarded default campaign result allocation failed: {0}")]
    Allocation(#[source] std::collections::TryReserveError),
    /// The checked campaign client rejected a service exchange.
    #[error("guarded default campaign service failed: {0}")]
    Service(#[source] CampaignClientError),
    /// Opening the configured cgroup or project-quota owner failed.
    #[error("guarded default campaign host resources failed: {0}")]
    Host(#[source] crucible_qemu::QemuVmRealizationError),
    /// The requested scenario cannot fit the admitted process/storage limits.
    #[error("guarded default campaign resource admission failed: {0}")]
    Resource(#[source] QemuFreshScenarioResourceError),
    /// Static planner-driver configuration was invalid.
    #[error("guarded default campaign planner configuration failed: {0}")]
    PlannerConfiguration(#[source] CampaignPlannerDriverConfigError),
    /// Static executor-driver configuration was invalid.
    #[error("guarded default campaign executor configuration failed: {0}")]
    ExecutorConfiguration(#[source] CampaignExecutorDriverConfigError),
    /// Local exact-capture capacity was invalid.
    #[error("guarded default campaign capture capacity failed: {0}")]
    ExecutorCapacity(#[source] ExecutorCapacityError),
    /// Static supervisor composition was invalid.
    #[error("guarded default campaign supervisor configuration failed: {0}")]
    SupervisorConfiguration(#[source] CampaignSupervisorConfigError),
    /// The shared campaign planner or executor supervisor failed.
    #[error("guarded default campaign supervisor failed: {0}")]
    Supervisor(#[source] GuardedDefaultCampaignSupervisorError<E>),
    /// Reading the bounded terminal-attempt evidence failed.
    #[error("guarded default campaign evidence failed: {0}")]
    Evidence(#[source] crucible::SchedulerError),
    /// A selected replay schedule did not have an exact authenticated choice closure.
    #[error("guarded default campaign replay closure failed: {0}")]
    ReplayClosure(#[source] GuardedCampaignReplayClosureError),
    /// A published physical checkpoint closure failed authentication.
    #[error("guarded default campaign exact checkpoint failed: {0}")]
    ExactCheckpoint(#[source] ExactCheckpointStoreError),
    /// A legacy logical resume checkpoint could not be reconstructed exactly.
    #[error("guarded default campaign resume checkpoint failed: {0}")]
    ResumeCheckpoint(#[source] crucible::EngineError),
    /// A fixed default-run invariant was violated.
    #[error("guarded default campaign invariant failed: {0}")]
    Invariant(#[source] GuardedDefaultCampaignInvariantError),
}

/// Invalid state reached by the bounded scenario-default compatibility owner.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum GuardedDefaultCampaignInvariantError {
    /// The campaign exceeded its fixed supervisor reconciliation bound.
    #[error("supervisor step count exceeded its fixed bound")]
    SupervisorStepLimit,
    /// More reached choices were accepted than the fixed compatibility bound.
    #[error("scenario-default choice count exceeded its fixed bound")]
    ChoiceLimit,
    /// A nonterminal observation contained no choice to continue.
    #[error("a nonterminal observation contained no authenticated choice")]
    MissingChoice,
    /// The completed campaign did not retain a terminal observation.
    #[error("the completed campaign retained no terminal observation")]
    MissingTerminalObservation,
    /// A bounded control-command ordinal overflowed.
    #[error("the campaign control-command ordinal overflowed")]
    CommandOrdinalOverflow,
    /// A requested savepoint stop was not reached exactly.
    #[error("the savepoint attempt ended before reaching its requested stop")]
    SavepointStopNotReached,
    /// A savepoint capture was requested more than once for one run.
    #[error("the default run attempted to request more than one savepoint capture")]
    DuplicateSavepointCapture,
    /// The executor resolved a different or unsuccessful capture.
    #[error("the executor resolved an incompatible savepoint capture")]
    SavepointCaptureMismatch,
    /// The completed campaign lost its authenticated capture facts.
    #[error("the completed campaign did not retain its savepoint capture proof")]
    MissingSavepointCapture,
    /// The physical checkpoint names a different scenario or configuration.
    #[error("the physical checkpoint differs from the captured semantic boundary")]
    SavepointCheckpointMismatch,
    /// The capture replay produced different scheduler evidence at the same boundary.
    #[error("the savepoint replay evidence differs from the accepted semantic attempt")]
    SavepointEvidenceMismatch,
    /// Save and resume capture modes were requested together.
    #[error("savepoint capture and legacy resume cannot share one default run")]
    ConflictingCheckpointModes,
    /// The legacy resume requested a stop outside its supported compatibility surface.
    #[error("the legacy resume final stop is not supported by the default campaign owner")]
    UnsupportedResumeStop,
    /// The logical source checkpoint did not equal its reconstructed v3 record.
    #[error("the legacy resume source checkpoint failed exact reconstruction")]
    ResumeSourceCheckpointMismatch,
    /// The source replay produced another configuration or campaign artifact.
    #[error("the legacy resume source observation differs from its checkpoint configuration")]
    ResumeSourceObservationMismatch,
    /// The source replay stopped at a different scheduler frontier.
    #[error("the legacy resume source replay differs from its checkpoint frontier")]
    ResumeSourceBoundaryMismatch,
    /// The source attempt ended at an unrelated nonterminal boundary.
    #[error("the legacy resume source attempt ended before its checkpoint boundary")]
    ResumeSourceStopNotReached,
    /// The selected continuation did not retain the exact capture provenance.
    #[error("the legacy resume continuation differs from its authenticated source capture")]
    ResumeContinuationMismatch,
    /// The completed run lost its authenticated legacy-resume proof.
    #[error("the completed campaign did not retain its legacy-resume proof")]
    MissingResumeProof,
}

/// Executes one guarded scenario-default path through shared campaign ownership.
///
/// # Errors
///
/// Returns [`GuardedDefaultCampaignRunError`] when resource admission, artifact
/// authentication, campaign service coordination, QEMU execution, publication,
/// or bounded evidence capture fails.
pub fn run_guarded_default_campaign(
    request: GuardedDefaultCampaignRunRequest,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError> {
    validate_initial_replay(&request)?;
    validate_resume_source(&request)?;
    validate_fresh_qemu_scenario_resources(&request.scenario, request.resources)
        .map_err(GuardedDefaultCampaignRunError::Resource)?;

    let host = LinuxQemuAttemptHostResourceFactory::open(request.host.clone())
        .map_err(GuardedDefaultCampaignRunError::Host)?;
    let guarded_factory = QemuAttemptProductionVmLifecycleFactory::new(
        request.lifecycle.clone(),
        ComposedQemuAttemptResourceGuardFactory::new(host),
    );
    let (lifecycle_factory, execution_evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(guarded_factory);
    let runner = QemuFreshExecutionRunner::new(lifecycle_factory, QemuFreshModeledDriver);

    run_guarded_default_campaign_with_validated_runner(request, runner, execution_evidence)
}

#[cfg(any(test, feature = "test-support"))]
fn run_guarded_default_campaign_with_runner<R>(
    request: GuardedDefaultCampaignRunRequest,
    runner: R,
    execution_evidence: QemuAttemptExecutionEvidence,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError<R::Error>>
where
    R: CrucibleExecutionRunner,
    R::Error: Error + Send + Sync + 'static,
{
    validate_initial_replay(&request)?;
    validate_resume_source(&request)?;

    run_guarded_default_campaign_with_validated_runner(request, runner, execution_evidence)
}

fn run_guarded_default_campaign_with_validated_runner<R>(
    request: GuardedDefaultCampaignRunRequest,
    runner: R,
    execution_evidence: QemuAttemptExecutionEvidence,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError<R::Error>>
where
    R: CrucibleExecutionRunner,
    R::Error: Error + Send + Sync + 'static,
{
    run_guarded_default_campaign_with_store(
        request,
        runner,
        execution_evidence,
        Arc::new(MemoryBlobBackend::new(
            "legacy-run-campaign",
            DEFAULT_RUN_REPOSITORY_BYTES,
        )),
        Arc::new(MemoryRefBackend::new()),
    )
}

fn run_guarded_default_campaign_with_store<R>(
    request: GuardedDefaultCampaignRunRequest,
    runner: R,
    execution_evidence: QemuAttemptExecutionEvidence,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError<R::Error>>
where
    R: CrucibleExecutionRunner,
    R::Error: Error + Send + Sync + 'static,
{
    let (repository, planner_authority) = default_run_repository(blobs, refs)?;
    let repository = Arc::new(repository);
    if let Some(closure) = &request.initial_replay_closure {
        closure
            .publish(&repository, &request.scenario, &request.initial_schedule)
            .map_err(GuardedDefaultCampaignRunError::ReplayClosure)?;
    }
    let artifacts = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    let initial_schedule = request.initial_schedule.clone();
    let scenario_content = artifacts
        .import_scenario(&request.scenario)
        .map_err(GuardedDefaultCampaignRunError::Artifact)?;
    let genesis_content = if request.initial_replay_closure.is_some() {
        artifacts.import_configuration_with_selections(&request.scenario, &initial_schedule)
    } else {
        artifacts.import_configuration(&request.scenario, &initial_schedule)
    }
    .map_err(GuardedDefaultCampaignRunError::Artifact)?;
    let lineage = default_run_lineage(&request, scenario_content, genesis_content)?;
    let policy = default_run_policy(&lineage, request.seed, &request.discovery_stop)?;
    let campaign = CampaignName::new(format!(
        "legacy-run-{:016x}",
        request.seed.decision_rng_root_seed()
    ))
    .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let principal = CampaignPrincipal::new("local:legacy-run")
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let client = CampaignClient::new(RepositoryCampaignService::new(
        repository.as_ref(),
        LocalRunAuthorizer {
            principal: principal.clone(),
            campaign: campaign.clone(),
        },
    ));
    let created = client
        .create_campaign(
            &CreateCampaignRequest::new(
                principal.clone(),
                campaign.clone(),
                lineage.clone(),
                policy.clone(),
            )
            .map_err(GuardedDefaultCampaignRunError::Codec)?,
        )
        .map_err(GuardedDefaultCampaignRunError::Service)?;
    let created_state = repository
        .state(campaign.as_str())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let funded = apply_campaign_control(
        &client,
        &principal,
        &campaign,
        created.snapshot(),
        0,
        CampaignControlAction::GrantBudget(
            BudgetGrant::new(
                DEFAULT_RUN_MAX_CHOICES,
                DEFAULT_RUN_MAX_CHOICES
                    + if request.resume_source.is_some() {
                        2
                    } else {
                        1
                    },
            )
            .map_err(GuardedDefaultCampaignRunError::Codec)?,
        ),
    )?;
    let running = apply_campaign_control(
        &client,
        &principal,
        &campaign,
        funded,
        1,
        CampaignControlAction::Resume,
    )?;
    let running_state = repository
        .state(campaign.as_str())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;

    // Admit the caller's exact starting configuration and stop before the
    // supervisor can manufacture its automatic NextChoice discovery.
    let discovery = DiscoveryRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.daemon.legacy-run-discovery.v1",
            &[],
        )),
        running,
        genesis_content,
        request.discovery_stop.clone(),
    )
    .map_err(GuardedDefaultCampaignRunError::Codec)?;
    client
        .submit_discovery_request(
            &SubmitCampaignDiscoveryRequest::new(principal.clone(), campaign.clone(), discovery)
                .map_err(GuardedDefaultCampaignRunError::Codec)?,
        )
        .map_err(GuardedDefaultCampaignRunError::Service)?;

    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let model = CrucibleExecutionModel::new(store.clone(), runner);
    let executor_profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let daemon_epoch =
        DaemonEpoch::from_bytes([0x59; 16]).map_err(GuardedDefaultCampaignRunError::Codec)?;
    let executor_service = SynchronousCampaignExecutor::new(
        store,
        model,
        RepositoryAttemptAdmission::new(Arc::clone(&repository), executor_profile),
        daemon_epoch,
        request.resources,
    );
    let capture_checkpoints = request.capture_reached_stop.as_ref().or_else(|| {
        request
            .resume_source
            .as_ref()
            .map(|source| &source.checkpoints)
    });
    let executor_service = match capture_checkpoints {
        Some(checkpoints) => executor_service
            .with_checkpoint_capture(Arc::clone(checkpoints))
            .map_err(GuardedDefaultCampaignRunError::ExecutorCapacity)?,
        None => executor_service,
    };
    let planner_basis = repository
        .publish_canonical_beam_planner_basis()
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let planner_service = AuthorizedPlannerService::new(
        crucible_campaign::CanonicalBeamPlanner,
        LocalPlannerMeter,
        planner_authority.clone(),
    );
    let planning_budget = PlanningBudget::new(1, 1, 64, 1024 * 1024, 4096)
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let planner = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        PlannerClient::new(planner_service, planner_authority),
        planner_basis.engine().clone(),
        planner_basis.artifact().clone(),
        planner_basis.initial_state().clone(),
        DEFAULT_RUN_PLANNER_SCAN,
        planning_budget,
    )
    .map_err(GuardedDefaultCampaignRunError::PlannerConfiguration)?
    .require_beam_policy();
    let executor = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        crucible_campaign::ExecutorClient::new(executor_service),
        daemon_epoch,
        1,
        request.resources,
        ExecutionRetentionIntent::Discard,
        DEFAULT_RUN_EXECUTOR_SCAN,
    )
    .map_err(GuardedDefaultCampaignRunError::ExecutorConfiguration)?;
    let mut supervisor = CampaignSupervisor::new(
        Arc::clone(&repository),
        campaign.clone(),
        planner,
        executor,
        1,
    )
    .map_err(GuardedDefaultCampaignRunError::SupervisorConfiguration)?;

    let mut watch_frames = Vec::new();
    if request.collect_watch_frames {
        let initial_evidence = execution_evidence
            .snapshot()
            .map_err(GuardedDefaultCampaignRunError::Evidence)?;
        watch_frames.push(campaign_watch_frame(
            &repository,
            &campaign,
            created.snapshot(),
            &initial_evidence,
            None,
        )?);
        watch_frames.push(campaign_watch_frame(
            &repository,
            &campaign,
            running,
            &initial_evidence,
            None,
        )?);
    }
    let execution = drive_default_campaign(
        DefaultRunContext {
            repository: &repository,
            client: &client,
            execution_evidence: &execution_evidence,
            principal: &principal,
            campaign: &campaign,
            policy: policy.id().map_err(GuardedDefaultCampaignRunError::Codec)?,
            discovery_stop: &request.discovery_stop,
            initial_configuration_content: genesis_content,
        },
        vec![created_state, running_state],
        watch_frames,
        request.collect_watch_frames,
        request.capture_reached_stop.is_some(),
        request.resume_source.as_ref(),
        &mut supervisor,
    )?;
    materialize_result(
        &repository,
        campaign,
        execution,
        request.capture_reached_stop.as_deref(),
        request.resume_source.as_ref(),
    )
}

fn default_run_repository<E>(
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
) -> Result<(CampaignRepository, PlannerAuthorityKey), GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let planner_authority = PlannerAuthorityKey::from_bytes([0x31; 32])
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let debugger_authority = DebuggerAuthorityKey::from_bytes([0x47; 32])
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let repository = CampaignRepository::with_component_authorities(
        blobs,
        refs,
        planner_authority.clone(),
        debugger_authority,
    )
    .map_err(GuardedDefaultCampaignRunError::Repository)?;
    Ok((repository, planner_authority))
}

fn default_run_lineage<E>(
    request: &GuardedDefaultCampaignRunRequest,
    scenario_content: crucible_campaign::ScenarioArtifactId,
    genesis_content: crucible_campaign::ConfigurationArtifactId,
) -> Result<CampaignLineage, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let encoded = crate::encode_crucible_scenario_artifact(&request.scenario)
        .map_err(GuardedDefaultCampaignRunError::Artifact)?;
    let scenario = encoded.scenario();
    // crucible-lint: allow host-nondeterminism-state -- lineage binds the deterministic initial configuration derived solely from authenticated replay input.
    let genesis = Configuration {
        def: request.scenario.scenario_def(),
        schedule: request.initial_schedule.clone(),
    }
    .id();
    CampaignLineage::new(
        scenario,
        scenario_content,
        crucible_campaign::ConfigurationId::from_hash(CampaignHash::from_bytes(genesis.bytes)),
        genesis_content,
        request.engine_build_id.clone(),
        request.qemu_build_id.clone(),
        BTreeMap::from([
            (
                String::from("control"),
                // crucible-lint: allow host-nondeterminism-state -- lineage records the compile-time protocol compatibility constant, not a host observation.
                crucible_api::CONTROL_PROTOCOL_VERSION,
            ),
            (String::from("shared-memory"), crucible::SHMEM_ABI_VERSION),
        ]),
        encoded.payload_schema(),
        crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
    )
    .map_err(GuardedDefaultCampaignRunError::Codec)
}

fn validate_initial_replay<E>(
    request: &GuardedDefaultCampaignRunRequest,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    match &request.initial_replay_closure {
        Some(closure) => closure
            .validate_for_schedule(&request.scenario, &request.initial_schedule)
            .map_err(GuardedDefaultCampaignRunError::ReplayClosure),
        None if request.initial_schedule.is_empty() => Ok(()),
        None => Err(GuardedDefaultCampaignRunError::ReplayClosure(
            GuardedCampaignReplayClosureError::Invalid {
                reason: "a nonempty initial schedule requires its authenticated choice closure",
            },
        )),
    }
}

fn default_run_policy<E>(
    lineage: &CampaignLineage,
    seed: Seed,
    discovery_stop: &StopCondition,
) -> Result<crucible_campaign::CampaignPolicy, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let stop_conditions = match discovery_stop {
        StopCondition::NamedBoundary(name) => BTreeSet::from([name.clone()]),
        StopCondition::NextChoice
        | StopCondition::VirtualTimeNanoseconds(_)
        | StopCondition::EventCount(_)
        | StopCondition::Terminal
        | StopCondition::ExecutionQuanta(_)
        | StopCondition::VirtualTimeOrExecutionQuanta { .. } => BTreeSet::new(),
    };
    crucible_campaign::CampaignPolicy::new(
        lineage.scenario(),
        CampaignSeed::from_bytes(seed.bytes()),
        CampaignMode::Strict,
        ExplorerPolicy::Beam {
            width: 1,
            novelty_reserve: 0,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        stop_conditions,
        FairnessPolicy::new(0, 0).map_err(GuardedDefaultCampaignRunError::Codec)?,
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .and_then(|policy| {
        // The caller-owned root discovery is the standalone cohort that opens
        // the scenario-default path, so this pinned policy admits its guidance.
        policy.with_intervention_learning_policy(
            crucible_campaign::InterventionLearningPolicy::IncludeInGuidance,
        )
    })
    .map_err(GuardedDefaultCampaignRunError::Codec)
}

fn apply_campaign_control<S, E>(
    client: &CampaignClient<S>,
    principal: &CampaignPrincipal,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    ordinal: u64,
    action: CampaignControlAction,
) -> Result<CampaignSnapshotId, GuardedDefaultCampaignRunError<E>>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
    E: Error + 'static,
{
    let command = CampaignCommandId::from_hash(CampaignHash::derive(
        "crucible.daemon.legacy-run-control.v1",
        &ordinal.to_be_bytes(),
    ));
    let request = ApplyCampaignCommandRequest::new(
        principal.clone(),
        campaign.clone(),
        crucible_campaign::ControlRequest {
            command,
            expected_snapshot: snapshot,
            action,
        },
    )
    .map_err(GuardedDefaultCampaignRunError::Codec)?;
    client
        .apply_campaign_command(&request)
        .map(|response| response.new_snapshot())
        .map_err(GuardedDefaultCampaignRunError::Service)
}

struct DefaultRunExecution {
    observations: Vec<DefaultRunAcceptedObservation>,
    branch_request_count: usize,
    final_snapshot: CampaignSnapshotId,
    state_updates: Vec<CampaignState>,
    watch_frames: Vec<GuardedDefaultCampaignWatchFrame>,
    savepoint: Option<DefaultRunSavepointCapture>,
    resume: Option<DefaultRunResumeProof>,
}

struct DefaultRunAcceptedObservation {
    id: ObservationId,
    virtual_time_ticks: u64,
    evidence: QemuAttemptExecutionEvidenceSnapshot,
}

struct DefaultRunPendingSavepointCapture {
    request: CampaignFactId,
    description: SavepointCaptureRequest,
    reached: crucible_campaign::ConfigurationId,
    reached_content: crucible_campaign::ConfigurationArtifactId,
    expected_evidence: QemuAttemptExecutionEvidenceSnapshot,
    resume_source_observation: Option<ObservationId>,
}

#[derive(Clone)]
struct DefaultRunSavepointCapture {
    request: CampaignFactId,
    description: SavepointCaptureRequest,
    checkpoint: ExactCheckpointId,
    reached: crucible_campaign::ConfigurationId,
    evidence: QemuAttemptExecutionEvidenceSnapshot,
}

struct DefaultRunContext<'a, S> {
    repository: &'a CampaignRepository,
    client: &'a CampaignClient<S>,
    execution_evidence: &'a QemuAttemptExecutionEvidence,
    principal: &'a CampaignPrincipal,
    campaign: &'a CampaignName,
    policy: crucible_campaign::CampaignPolicyId,
    discovery_stop: &'a StopCondition,
    initial_configuration_content: crucible_campaign::ConfigurationArtifactId,
}

fn drive_default_campaign<R, S>(
    context: DefaultRunContext<'_, S>,
    mut state_updates: Vec<CampaignState>,
    mut watch_frames: Vec<GuardedDefaultCampaignWatchFrame>,
    collect_watch_frames: bool,
    capture_reached_stop: bool,
    resume_source: Option<&GuardedDefaultCampaignResumeSource>,
    supervisor: &mut CampaignSupervisor<DefaultPlannerService, DefaultExecutorService<R>>,
) -> Result<DefaultRunExecution, GuardedDefaultCampaignRunError<R::Error>>
where
    R: CrucibleExecutionRunner,
    R::Error: Error + Send + Sync + 'static,
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let mut observations = Vec::new();
    let mut branch_request_count = 0usize;
    let mut pending_capture: Option<DefaultRunPendingSavepointCapture> = None;
    let mut resume_progress = resume_source.map(|_| DefaultRunResumeProgress::AwaitingSource);
    let mut objective_evaluation_cursor = None;
    for supervisor_iteration in 0..DEFAULT_RUN_MAX_SUPERVISOR_STEPS {
        if crate::publish_next_objective_evaluation(
            context.repository,
            context.campaign.as_str(),
            &mut objective_evaluation_cursor,
        )
        .map_err(GuardedDefaultCampaignRunError::Objective)?
        {
            continue;
        }
        // crucible-lint: allow host-nondeterminism-state -- the shared supervisor advances only authenticated campaign planner and executor operations.
        let supervisor_result = supervisor.step();
        let outcome = supervisor_result
            .map_err(|error| GuardedDefaultCampaignSupervisorError(Box::new(error)))
            .map_err(GuardedDefaultCampaignRunError::Supervisor)?;
        let CampaignSupervisorStepOutcome::Executor { outcome, .. } = outcome else {
            continue;
        };

        if let CampaignExecutorStepOutcome::CaptureResolved {
            result,
            attempt,
            checkpoint,
            ..
        } = outcome
        {
            let pending = pending_capture
                .take()
                .ok_or(GuardedDefaultCampaignInvariantError::SavepointCaptureMismatch)?;
            let evidence = context
                .execution_evidence
                .snapshot()
                .map_err(GuardedDefaultCampaignRunError::Evidence)?;
            if result.request != pending.request
                || result.outcome != SavepointCaptureOutcome::Ready
                || attempt != pending.description.attempt
                || evidence != pending.expected_evidence
            {
                return Err(GuardedDefaultCampaignInvariantError::SavepointEvidenceMismatch.into());
            }
            let checkpoint =
                checkpoint.ok_or(GuardedDefaultCampaignInvariantError::SavepointCaptureMismatch)?;
            let resume_source_observation = pending.resume_source_observation;
            let reached_content = pending.reached_content;
            let savepoint = DefaultRunSavepointCapture {
                request: pending.request,
                description: pending.description,
                checkpoint,
                reached: pending.reached,
                evidence: evidence.clone(),
            };
            if let Some(source_observation) = resume_source_observation {
                if !matches!(resume_progress, Some(DefaultRunResumeProgress::Capturing)) {
                    return Err(
                        GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into(),
                    );
                }
                let source = resume_source
                    .ok_or(GuardedDefaultCampaignInvariantError::MissingResumeProof)?;
                let ready = context
                    .repository
                    .savepoint_capture_resolution_at(result.new_snapshot, savepoint.request)
                    .map_err(GuardedDefaultCampaignRunError::Repository)?
                    .ok_or(GuardedDefaultCampaignInvariantError::SavepointCaptureMismatch)?;
                if ready.request != savepoint.request
                    || ready.outcome != SavepointCaptureOutcome::Ready
                {
                    return Err(
                        GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into(),
                    );
                }
                let ready_id = CampaignFact::SavepointCaptureResolved(ready)
                    .id()
                    .map_err(GuardedDefaultCampaignRunError::Codec)?;
                let origin = context
                    .repository
                    .load_attempt(savepoint.description.attempt)
                    .map_err(GuardedDefaultCampaignRunError::Repository)?;
                let continuation = Attempt::new(
                    AttemptStart::AfterAttempt {
                        origin: savepoint.description.attempt,
                        reached: reached_content,
                    },
                    origin.path(),
                    source.final_stop.clone(),
                )
                .map_err(GuardedDefaultCampaignRunError::Codec)?;
                let continuation_id = continuation
                    .id()
                    .map_err(GuardedDefaultCampaignRunError::Codec)?;
                let source_content = source_observation.content_id().encode();
                let selection = SavepointContinuationSelection {
                    command: CampaignCommandId::from_hash(CampaignHash::derive(
                        "crucible.daemon.legacy-resume-continuation.v1",
                        source_content.as_bytes(),
                    )),
                    expected_snapshot: result.new_snapshot,
                    request: savepoint.request,
                    ready: ready_id,
                    continuation: continuation_id,
                };
                let selected = context
                    .repository
                    .select_savepoint_continuation(
                        context.campaign.as_str(),
                        &selection,
                        &continuation,
                    )
                    .map_err(GuardedDefaultCampaignRunError::Repository)?;
                if selected.continuation != continuation_id
                    || selected.prior_snapshot != result.new_snapshot
                    || selected.source != selected.selection
                {
                    return Err(
                        GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into(),
                    );
                }
                if collect_watch_frames {
                    watch_frames.push(campaign_watch_frame(
                        context.repository,
                        context.campaign,
                        selected.new_snapshot,
                        &evidence,
                        None,
                    )?);
                }
                resume_progress = Some(DefaultRunResumeProgress::Continuing(Box::new(
                    DefaultRunResumeProof {
                        source_checkpoint: source.checkpoint.id,
                        source_configuration: savepoint.reached,
                        source_frontier: source.checkpoint.virtual_time,
                        source_observation,
                        source_evidence: evidence.clone(),
                        source_capture: Some(savepoint),
                        ready_snapshot: Some(result.new_snapshot),
                        ready: Some(ready_id),
                        selection: Some(selected.selection),
                        continuation: Some(continuation_id),
                    },
                )));
                continue;
            }

            let final_snapshot = complete_default_campaign(
                &context,
                result.new_snapshot,
                supervisor_iteration,
                &mut state_updates,
            )?;
            if collect_watch_frames {
                watch_frames.push(campaign_watch_frame(
                    context.repository,
                    context.campaign,
                    final_snapshot,
                    &evidence,
                    None,
                )?);
            }
            return Ok(DefaultRunExecution {
                observations,
                branch_request_count,
                final_snapshot,
                state_updates,
                watch_frames,
                savepoint: Some(savepoint),
                resume: None,
            });
        }

        if pending_capture.is_some()
            && matches!(
                outcome,
                CampaignExecutorStepOutcome::CaptureAlreadyResolved { .. }
                    | CampaignExecutorStepOutcome::CaptureBlocked { .. }
                    | CampaignExecutorStepOutcome::CaptureUnexpectedCompletion { .. }
            )
        {
            return Err(GuardedDefaultCampaignInvariantError::SavepointCaptureMismatch.into());
        }

        let CampaignExecutorStepOutcome::Incorporated(result) = outcome else {
            continue;
        };
        let snapshot = result.new_snapshot;
        let observation_id = result.observation;
        let execution_boundary = context
            .execution_evidence
            .snapshot()
            .map_err(GuardedDefaultCampaignRunError::Evidence)?;
        let virtual_time_ticks = execution_boundary.frontier().ticks;
        let observation = context
            .repository
            .load_observation(observation_id)
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        observations.push(DefaultRunAcceptedObservation {
            id: observation_id,
            virtual_time_ticks,
            evidence: execution_boundary.clone(),
        });
        if collect_watch_frames {
            watch_frames.push(campaign_watch_frame(
                context.repository,
                context.campaign,
                snapshot,
                &execution_boundary,
                Some(observation_id),
            )?);
        }

        if matches!(
            resume_progress,
            Some(DefaultRunResumeProgress::AwaitingSource)
        ) {
            let source =
                resume_source.ok_or(GuardedDefaultCampaignInvariantError::MissingResumeProof)?;
            let expected_configuration = crucible_campaign::ConfigurationId::from_hash(
                CampaignHash::from_bytes(source.checkpoint.configuration.bytes),
            );
            if observation.child() != expected_configuration
                || observation.child_content() != context.initial_configuration_content
            {
                return Err(
                    GuardedDefaultCampaignInvariantError::ResumeSourceObservationMismatch.into(),
                );
            }
            if execution_boundary.frontier() != source.checkpoint.virtual_time {
                return Err(
                    GuardedDefaultCampaignInvariantError::ResumeSourceBoundaryMismatch.into(),
                );
            }

            if observation.stop() == &StopOutcome::Reached(context.discovery_stop.clone()) {
                pending_capture = Some(request_default_savepoint_capture(
                    &context,
                    snapshot,
                    observation_id,
                    &observation,
                    context.discovery_stop,
                    "legacy resume source",
                    execution_boundary,
                    Some(observation_id),
                )?);
                resume_progress = Some(DefaultRunResumeProgress::Capturing);
                continue;
            }
            if matches!(observation.stop(), StopOutcome::Reached(_)) {
                return Err(
                    GuardedDefaultCampaignInvariantError::ResumeSourceStopNotReached.into(),
                );
            }

            let proof = DefaultRunResumeProof {
                source_checkpoint: source.checkpoint.id,
                source_configuration: expected_configuration,
                source_frontier: source.checkpoint.virtual_time,
                source_observation: observation_id,
                source_evidence: execution_boundary.clone(),
                source_capture: None,
                ready_snapshot: None,
                ready: None,
                selection: None,
                continuation: None,
            };
            let final_snapshot = complete_default_campaign(
                &context,
                snapshot,
                supervisor_iteration,
                &mut state_updates,
            )?;
            if collect_watch_frames {
                watch_frames.push(campaign_watch_frame(
                    context.repository,
                    context.campaign,
                    final_snapshot,
                    &execution_boundary,
                    None,
                )?);
            }
            return Ok(DefaultRunExecution {
                observations,
                branch_request_count,
                final_snapshot,
                state_updates,
                watch_frames,
                savepoint: None,
                resume: Some(proof),
            });
        }

        let resume_final_stop_reached =
            resume_source
                .zip(resume_progress.as_ref())
                .is_some_and(|(source, progress)| {
                    matches!(progress, DefaultRunResumeProgress::Continuing(_))
                        && observation.stop() == &StopOutcome::Reached(source.final_stop.clone())
                });
        if observation.stop() == &StopOutcome::Reached(StopCondition::NextChoice)
            && !resume_final_stop_reached
        {
            let opportunity_id = observation
                .discovered_choices()
                .iter()
                .next()
                .copied()
                .ok_or(GuardedDefaultCampaignInvariantError::MissingChoice)?;
            if branch_request_count >= DEFAULT_RUN_MAX_CHOICES as usize {
                return Err(GuardedDefaultCampaignInvariantError::ChoiceLimit.into());
            }
            let opportunity = context
                .repository
                .load_choice_opportunity(opportunity_id)
                .map_err(GuardedDefaultCampaignRunError::Repository)?;
            let continuation_stop = resume_source
                .filter(|_| {
                    matches!(
                        resume_progress,
                        Some(DefaultRunResumeProgress::Continuing(_))
                    )
                })
                .map(|source| source.final_stop.clone())
                .unwrap_or_else(|| {
                    default_choice_continuation_stop(capture_reached_stop, context.discovery_stop)
                });
            let branch = BranchRequest::new(
                opportunity.branch_point_id(observation.child()),
                observation.child_content(),
                opportunity_id,
                opportunity.domain(),
                CandidateSource::finite(BTreeSet::from([opportunity.default().clone()]))
                    .map_err(GuardedDefaultCampaignRunError::Codec)?,
                BranchRequestCause::ScenarioDefault(context.policy),
                BranchBudget::new(1, 1).map_err(GuardedDefaultCampaignRunError::Codec)?,
                continuation_stop,
            )
            .map_err(GuardedDefaultCampaignRunError::Codec)?;
            let submission = SubmitCampaignBranchRequest::new(
                context.principal.clone(),
                context.campaign.clone(),
                snapshot,
                branch,
            )
            .map_err(GuardedDefaultCampaignRunError::Codec)?;
            context
                .client
                .submit_branch_request(&submission)
                .map_err(GuardedDefaultCampaignRunError::Service)?;
            branch_request_count += 1;
            continue;
        }

        if capture_reached_stop {
            if observation.stop() != &StopOutcome::Reached(context.discovery_stop.clone()) {
                return Err(GuardedDefaultCampaignInvariantError::SavepointStopNotReached.into());
            }
            if pending_capture.is_some() {
                return Err(GuardedDefaultCampaignInvariantError::DuplicateSavepointCapture.into());
            }

            pending_capture = Some(request_default_savepoint_capture(
                &context,
                snapshot,
                observation_id,
                &observation,
                context.discovery_stop,
                "legacy virtual-time save",
                execution_boundary,
                None,
            )?);
            continue;
        }

        let final_snapshot = complete_default_campaign(
            &context,
            snapshot,
            supervisor_iteration,
            &mut state_updates,
        )?;
        if collect_watch_frames {
            watch_frames.push(campaign_watch_frame(
                context.repository,
                context.campaign,
                final_snapshot,
                &execution_boundary,
                None,
            )?);
        }
        let resume = match resume_progress.take() {
            Some(DefaultRunResumeProgress::Continuing(proof)) => Some(*proof),
            Some(
                DefaultRunResumeProgress::AwaitingSource | DefaultRunResumeProgress::Capturing,
            ) => {
                return Err(GuardedDefaultCampaignInvariantError::MissingResumeProof.into());
            }
            None => None,
        };
        return Ok(DefaultRunExecution {
            observations,
            branch_request_count,
            final_snapshot,
            state_updates,
            watch_frames,
            savepoint: None,
            resume,
        });
    }
    Err(GuardedDefaultCampaignInvariantError::SupervisorStepLimit.into())
}

fn default_choice_continuation_stop(
    capture_reached_stop: bool,
    discovery_stop: &StopCondition,
) -> StopCondition {
    if capture_reached_stop {
        discovery_stop.clone()
    } else {
        StopCondition::NextChoice
    }
}

#[allow(clippy::too_many_arguments)]
fn request_default_savepoint_capture<S, E>(
    context: &DefaultRunContext<'_, S>,
    snapshot: CampaignSnapshotId,
    observation_id: ObservationId,
    observation: &Observation,
    stop: &StopCondition,
    reason: &str,
    expected_evidence: QemuAttemptExecutionEvidenceSnapshot,
    resume_source_observation: Option<ObservationId>,
) -> Result<DefaultRunPendingSavepointCapture, GuardedDefaultCampaignRunError<E>>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
    E: Error + 'static,
{
    let attempt = context
        .repository
        .load_attempt(observation.attempt())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    if attempt.stop() != stop {
        return Err(GuardedDefaultCampaignInvariantError::SavepointCaptureMismatch.into());
    }
    let starting_configuration = match attempt.start() {
        AttemptStart::Discover { configuration } => configuration,
        AttemptStart::Branch { parent, .. } => parent,
        AttemptStart::AfterAttempt { reached, .. } => reached,
    };
    let starting_artifact = context
        .repository
        .load_configuration_artifact(starting_configuration)
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let observation_content = observation_id.content_id().encode();
    let command = CampaignCommandId::from_hash(CampaignHash::derive(
        "crucible.daemon.legacy-run-savepoint-capture.v1",
        observation_content.as_bytes(),
    ));
    let description = SavepointCaptureRequest::new(
        command,
        snapshot,
        observation.attempt(),
        starting_configuration,
        starting_artifact.configuration(),
        stop.clone(),
        reason,
    )
    .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let requested = context
        .repository
        .request_savepoint_capture(context.campaign.as_str(), &description)
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    Ok(DefaultRunPendingSavepointCapture {
        request: requested.request,
        description,
        reached: observation.child(),
        reached_content: observation.child_content(),
        expected_evidence,
        resume_source_observation,
    })
}

fn complete_default_campaign<S, E>(
    context: &DefaultRunContext<'_, S>,
    snapshot: CampaignSnapshotId,
    supervisor_iteration: usize,
    state_updates: &mut Vec<CampaignState>,
) -> Result<CampaignSnapshotId, GuardedDefaultCampaignRunError<E>>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
    E: Error + 'static,
{
    let command_ordinal = 2_u64
        .checked_add(
            u64::try_from(supervisor_iteration)
                .map_err(|_| GuardedDefaultCampaignInvariantError::CommandOrdinalOverflow)?,
        )
        .ok_or(GuardedDefaultCampaignInvariantError::CommandOrdinalOverflow)?;
    let final_snapshot = apply_campaign_control(
        context.client,
        context.principal,
        context.campaign,
        snapshot,
        command_ordinal,
        CampaignControlAction::Complete,
    )?;
    state_updates.push(
        context
            .repository
            .state(context.campaign.as_str())
            .map_err(GuardedDefaultCampaignRunError::Repository)?,
    );
    Ok(final_snapshot)
}

fn campaign_watch_frame<E>(
    repository: &CampaignRepository,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    evidence: &QemuAttemptExecutionEvidenceSnapshot,
    observation: Option<ObservationId>,
) -> Result<GuardedDefaultCampaignWatchFrame, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let state = repository
        .state_at_snapshot(snapshot)
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    Ok(GuardedDefaultCampaignWatchFrame {
        campaign: campaign.clone(),
        snapshot,
        state,
        frontier: evidence.frontier(),
        quanta: evidence.quanta(),
        observation,
    })
}

fn materialize_result<E>(
    repository: &Arc<CampaignRepository>,
    campaign: CampaignName,
    execution: DefaultRunExecution,
    checkpoints: Option<&ExactCheckpointStore>,
    resume_source: Option<&GuardedDefaultCampaignResumeSource>,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let head = repository
        .head(campaign.as_str())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let lineage = repository
        .load_lineage(head.snapshot().lineage())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let scenario_artifact = repository
        .load_scenario_artifact(lineage.scenario_content())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let scenario = crate::decode_crucible_scenario_artifact(&scenario_artifact)
        .map_err(GuardedDefaultCampaignRunError::Artifact)?;
    let store = CampaignExecutorStore::new(Arc::clone(repository));
    let mut observations = Vec::new();
    observations
        .try_reserve(execution.observations.len())
        .map_err(GuardedDefaultCampaignRunError::Allocation)?;
    let observation_count = execution.observations.len();
    let terminal_execution_evidence = execution
        .observations
        .last()
        .map(|accepted| accepted.evidence.clone())
        .ok_or(GuardedDefaultCampaignInvariantError::MissingTerminalObservation)?;
    let mut terminal_configuration = None;
    for (index, accepted) in execution.observations.into_iter().enumerate() {
        let observation = repository
            .load_observation(accepted.id)
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        if index + 1 == observation_count {
            let child = repository
                .load_configuration_artifact(observation.child_content())
                .map_err(GuardedDefaultCampaignRunError::Repository)?;
            terminal_configuration = Some(
                decode_crucible_configuration_artifact_with_selections(
                    &scenario,
                    &scenario_artifact,
                    &child,
                    &store,
                )
                .map_err(GuardedDefaultCampaignRunError::Artifact)?,
            );
        }
        observations.push(GuardedDefaultCampaignObservation {
            id: accepted.id,
            observation,
            virtual_time_ticks: accepted.virtual_time_ticks,
        });
    }
    let terminal = observations
        .last()
        .cloned()
        .ok_or(GuardedDefaultCampaignInvariantError::MissingTerminalObservation)?;
    let terminal_configuration = terminal_configuration
        .ok_or(GuardedDefaultCampaignInvariantError::MissingTerminalObservation)?;
    let (savepoint, evidence) = match execution.savepoint {
        Some(capture) => {
            let checkpoints =
                checkpoints.ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
            let request = repository
                .savepoint_capture_request_at(execution.final_snapshot, capture.request)
                .map_err(GuardedDefaultCampaignRunError::Repository)?
                .ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
            let resolution = repository
                .savepoint_capture_resolution_at(execution.final_snapshot, capture.request)
                .map_err(GuardedDefaultCampaignRunError::Repository)?
                .ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
            let attempt = repository
                .load_attempt(capture.description.attempt)
                .map_err(GuardedDefaultCampaignRunError::Repository)?;
            if request != capture.description
                || resolution.request != capture.request
                || resolution.outcome != SavepointCaptureOutcome::Ready
                || attempt.stop() != &capture.description.stop
                || capture.description.attempt != terminal.observation.attempt()
                || capture.reached != terminal.observation.child()
                || capture.evidence != terminal_execution_evidence
            {
                return Err(GuardedDefaultCampaignInvariantError::SavepointCaptureMismatch.into());
            }

            let checkpoint = checkpoints
                .load_attempt_checkpoint(capture.checkpoint)
                .map_err(GuardedDefaultCampaignRunError::ExactCheckpoint)?;
            if checkpoint.root() != capture.checkpoint
                || checkpoint.scenario().bytes != lineage.scenario().as_hash().as_bytes()
                || checkpoint.configuration().bytes
                    != terminal.observation.child().as_hash().as_bytes()
                || !capture_evidence_reaches_stop(&capture.evidence, &capture.description.stop)
            {
                return Err(
                    GuardedDefaultCampaignInvariantError::SavepointCheckpointMismatch.into(),
                );
            }

            let evidence = capture.evidence.clone();
            let savepoint = GuardedDefaultCampaignSavepoint {
                request: capture.request,
                attempt: capture.description.attempt,
                checkpoint: capture.checkpoint,
                configuration: capture.reached,
                stop: capture.description.stop,
                evidence: capture.evidence,
            };
            (Some(savepoint), evidence)
        }
        None => {
            if checkpoints.is_some() && resume_source.is_none() {
                return Err(GuardedDefaultCampaignInvariantError::MissingSavepointCapture.into());
            }
            (None, terminal_execution_evidence)
        }
    };
    let resume = materialize_resume_proof(
        repository,
        execution.final_snapshot,
        &lineage,
        &observations,
        &terminal,
        &evidence,
        execution.resume,
        resume_source,
    )?;
    let replay_closure =
        GuardedCampaignReplayClosure::collect(&store, &scenario, &terminal_configuration.schedule)
            .map_err(GuardedDefaultCampaignRunError::ReplayClosure)?;
    Ok(GuardedDefaultCampaignRun {
        campaign,
        final_snapshot: execution.final_snapshot,
        observations,
        terminal,
        terminal_configuration,
        branch_request_count: execution.branch_request_count,
        state_updates: execution.state_updates,
        watch_frames: execution.watch_frames,
        evidence,
        replay_closure,
        savepoint,
        resume,
    })
}

fn capture_evidence_reaches_stop(
    evidence: &QemuAttemptExecutionEvidenceSnapshot,
    stop: &StopCondition,
) -> bool {
    match stop {
        StopCondition::VirtualTimeNanoseconds(deadline) => evidence.frontier().ticks >= *deadline,
        StopCondition::ExecutionQuanta(bound) => evidence.quanta() >= *bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds,
            execution_quanta,
        } => {
            evidence.frontier().ticks >= *virtual_time_nanoseconds
                || evidence.quanta() >= *execution_quanta
        }
        StopCondition::NextChoice
        | StopCondition::NamedBoundary(_)
        | StopCondition::EventCount(_)
        | StopCondition::Terminal => true,
    }
}

impl<E> From<GuardedDefaultCampaignInvariantError> for GuardedDefaultCampaignRunError<E>
where
    E: Error + 'static,
{
    fn from(error: GuardedDefaultCampaignInvariantError) -> Self {
        Self::Invariant(error)
    }
}

#[derive(Clone)]
struct LocalRunAuthorizer {
    principal: CampaignPrincipal,
    campaign: CampaignName,
}

impl CampaignPrincipalAuthorizer for LocalRunAuthorizer {
    fn authorize(
        &self,
        principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        if principal == &self.principal && campaign == &self.campaign {
            Ok(())
        } else {
            Err(CampaignAuthorizationError::Unauthorized)
        }
    }
}
