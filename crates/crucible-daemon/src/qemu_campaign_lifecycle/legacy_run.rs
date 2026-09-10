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
    ApplyCampaignCommandRequest, Attempt, AttemptResourceLimits, AttemptStart, BranchBudget,
    BranchRequest, BranchRequestCause, BudgetGrant, CampaignAuthorizationError, CampaignClient,
    CampaignClientError, CampaignCodecError, CampaignCommandId, CampaignControlAction,
    CampaignExecutorDriver, CampaignExecutorDriverConfigError, CampaignExecutorStepOutcome,
    CampaignExecutorStore, CampaignFact, CampaignFactId, CampaignHash, CampaignLineage,
    CampaignName, CampaignPlannerDriverConfigError, CampaignPlannerStepOutcome, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignRepository, CampaignRepositoryError,
    CampaignServiceOperation, CampaignSnapshotId, CampaignState, CampaignSupervisor,
    CampaignSupervisorConfigError, CampaignSupervisorError, CampaignSupervisorStepOutcome,
    CandidateSource, CreateCampaignRequest, DaemonEpoch, DebuggerAuthorityKey, DiscoveryRequest,
    ExactCheckpointId, ExecutionRetentionIntent, ExecutorCompatibilityProfile, Observation,
    ObservationId, ObservationStopProof, PlannerAuthorityKey, PlannerDisposition, PropertyVerdict,
    RepositoryCampaignService, SavepointCaptureOutcome, SavepointCaptureRequest,
    SavepointContinuationSelection, ScenarioDefId, StopCondition, StopOutcome,
    SubmitCampaignBranchRequest, SubmitCampaignDiscoveryRequest,
};
use crucible_cas::content_store::{
    ContentId, ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend, MutableRefBackend,
    ObjectKind,
};
use thiserror::Error;

use super::{
    QemuAttemptExecutionEvidence, QemuAttemptExecutionEvidenceSnapshot,
    QemuAttemptProductionVmLifecycleError, QemuAttemptProductionVmLifecycleFactory,
    QemuFreshExecutionRunner, QemuFreshExecutionRunnerError, QemuFreshScenarioResourceError,
    QemuObservedFreshAttemptLifecycleFactory, QemuObservedFreshAttemptLifecycleFactoryError,
    validate_fresh_qemu_scenario_resources,
};
use crate::qemu_campaign_driver::QemuFreshSupplementalModeledDriver;
use crate::{
    AutomaticFindingExecutionRunner, AutomaticFindingExecutionRunnerError,
    ComposedQemuAttemptResourceGuardFactory, CrucibleArtifactError, CrucibleCampaignArtifactStore,
    CrucibleExecutionModel, CrucibleExecutionModelError, CrucibleExecutionRunner,
    CrucibleMeasurementError, CrucibleMeasurementReplayEvidence, ExactCheckpointStore,
    ExactCheckpointStoreError, ExecutionCancellation, ExecutorCapacityError,
    LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostResourceFactory,
    MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES, QemuAttemptHostResourceFactory,
    QemuFreshModeledDriverError, RepositoryAttemptAdmission, SharedQemuAttemptHostResourceFactory,
    decode_crucible_configuration_artifact_with_selections,
};

mod executor;
use executor::{SynchronousCampaignExecutor, SynchronousCampaignExecutorError};

mod exploration;
use exploration::{
    ExplorationBranchDecision, LocalCampaignPlannerService, LocalCampaignPlannerServiceError,
    exploration_branch_request, local_campaign_planner, local_campaign_policy,
    observation_has_finding, publish_all_candidates_generator,
};
pub use exploration::{
    GuardedCampaignBranchAcceptance, GuardedCampaignExploration,
    GuardedCampaignExplorationCompletion, GuardedCampaignExplorationStrategy,
};

mod finding_export;
use finding_export::capture_final_finding_export;
pub use finding_export::{
    GuardedCampaignFindingExport, GuardedCampaignFindingObjectProof,
    GuardedCampaignFindingOccurrenceObjectProof, GuardedCampaignFindingOccurrenceProof,
    GuardedCampaignFindingProof, GuardedCampaignFindingQueryProof,
};

mod replay_closure;
pub use replay_closure::{
    GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError,
    validate_remote_resume_replay_closure,
};

mod resume;
use resume::{
    DefaultRunResumeProgress, DefaultRunResumeProof, GuardedDefaultCampaignResumeSource,
    continuation_lifecycle_config, materialize_resume_proof, validate_resume_source,
};
pub use resume::{
    GuardedCampaignContinuationControl, GuardedCampaignContinuationControlError,
    GuardedDefaultCampaignResumeProof,
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

type DefaultPlannerService = LocalCampaignPlannerService;
type DefaultPlannerServiceError = LocalCampaignPlannerServiceError;
type DefaultExecutorService<R> = SynchronousCampaignExecutor<CrucibleExecutionModel<R>>;
type DefaultExecutorServiceError<E> =
    SynchronousCampaignExecutorError<CrucibleExecutionModelError<E>>;
type DefaultSupervisorError<E> =
    CampaignSupervisorError<DefaultPlannerServiceError, DefaultExecutorServiceError<E>>;

type GuardedDefaultCampaignMainRunnerError = QemuFreshExecutionRunnerError<
    QemuObservedFreshAttemptLifecycleFactoryError<QemuAttemptProductionVmLifecycleError>,
    QemuFreshModeledDriverError,
>;
type GuardedDefaultCampaignReplayRunnerError = QemuFreshExecutionRunnerError<
    QemuAttemptProductionVmLifecycleError,
    QemuFreshModeledDriverError,
>;

/// Concrete production-runner failure used by the guarded CLI campaign owner.
pub type GuardedDefaultCampaignProductionRunnerError = AutomaticFindingExecutionRunnerError<
    GuardedDefaultCampaignMainRunnerError,
    GuardedDefaultCampaignReplayRunnerError,
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

/// Groups a portable observation proof with its retained raw source evidence.
///
/// The pair remains a caller-supplied claim until campaign execution validates
/// its internal bindings and independently reproduces both records from
/// scenario genesis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedDefaultCampaignObservationSource {
    proof: ObservationStopProof,
    evidence: CrucibleMeasurementReplayEvidence,
}

impl GuardedDefaultCampaignObservationSource {
    /// Creates a pending source claim for campaign-owned replay authentication.
    #[must_use]
    pub const fn new(
        proof: ObservationStopProof,
        evidence: CrucibleMeasurementReplayEvidence,
    ) -> Self {
        Self { proof, evidence }
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
    cancellation: ExecutionCancellation,
    initial_schedule: Schedule,
    initial_replay_closure: Option<GuardedCampaignReplayClosure>,
    discovery_stop: StopCondition,
    verify_determinism_findings: bool,
    collect_watch_frames: bool,
    capture_reached_stop: Option<Arc<ExactCheckpointStore>>,
    resume_source: Option<GuardedDefaultCampaignResumeSource>,
    exploration: Option<GuardedCampaignExploration>,
    supplemental_finding_oracle: Option<Arc<dyn GuardedCampaignFindingOracle>>,
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
            cancellation: ExecutionCancellation::default(),
            initial_schedule: Schedule::empty(),
            initial_replay_closure: None,
            discovery_stop: StopCondition::NextChoice,
            verify_determinism_findings: false,
            collect_watch_frames: false,
            capture_reached_stop: None,
            resume_source: None,
            exploration: None,
            supplemental_finding_oracle: None,
        }
    }

    /// Uses one caller-owned cancellation signal for every campaign attempt.
    #[must_use]
    pub fn with_execution_cancellation(mut self, cancellation: ExecutionCancellation) -> Self {
        self.cancellation = cancellation;
        self
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

    /// Enables bounded paired replay when an ordinary attempt has no finding.
    #[must_use]
    pub const fn with_determinism_finding_verification(mut self) -> Self {
        self.verify_determinism_findings = true;
        self
    }

    /// Uses one caller-owned cancellation signal for execution and final export.
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: ExecutionCancellation) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Returns whether ordinary attempts receive bounded paired replay.
    #[must_use]
    pub const fn verifies_determinism_findings(&self) -> bool {
        self.verify_determinism_findings
    }

    /// Retains bounded authenticated campaign progress frames for CLI watch output.
    #[must_use]
    pub const fn with_watch_frames(mut self) -> Self {
        self.collect_watch_frames = true;
        self
    }

    /// Explores typed choices through the shared campaign planner and executor.
    ///
    /// Exploration starts with `NextChoice` discovery and retains every
    /// accepted observation and branch-request identity. It cannot be combined
    /// with the single-run savepoint or resume adapters.
    #[must_use]
    pub fn with_exploration(mut self, exploration: GuardedCampaignExploration) -> Self {
        self.discovery_stop = exploration.attempt_stop();
        self.exploration = Some(exploration);
        self
    }

    /// Evaluates an immutable supplemental search oracle inside owner progression.
    ///
    /// The oracle source identity is bound into the authenticated campaign
    /// policy. Every accepted observation is evaluated before the owner admits
    /// another branch, so `stop_on_finding` retains its exact meaning.
    #[must_use]
    pub fn with_supplemental_finding_oracle(
        mut self,
        oracle: Box<dyn GuardedCampaignFindingOracle>,
    ) -> Self {
        self.supplemental_finding_oracle = Some(Arc::from(oracle));
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

    /// Resumes an authenticated legacy checkpoint through one campaign.
    ///
    /// The source schedule is first replayed to the exact logical checkpoint
    /// frontier. Only after the accepted configuration and scheduler frontier
    /// equal `checkpoint` does the owner capture an exact physical savepoint and
    /// admit an [`AttemptStart::AfterAttempt`] continuation to `final_stop`.
    /// `closure` must authenticate every typed selection in `schedule` and is
    /// published into the campaign repository before source replay begins.
    #[must_use]
    pub fn with_resume_source(
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
            continuation_control: None,
            source_observation_proof: None,
            source_observation_evidence: None,
            capture_only: false,
        });
        self
    }

    /// Continues from an authenticated checkpoint under modeled branch control.
    ///
    /// The control is committed into the continuation [`Attempt`] identity
    /// before execution admission. The campaign owner derives the production
    /// lifecycle branch configuration from that same record.
    #[must_use]
    pub fn with_controlled_resume_source(
        mut self,
        // crucible-lint: allow host-nondeterminism-state -- the caller-supplied replay schedule is forwarded unchanged into exact source authentication.
        schedule: Schedule,
        closure: GuardedCampaignReplayClosure,
        checkpoint: Checkpoint,
        final_stop: StopCondition,
        checkpoints: Arc<ExactCheckpointStore>,
        continuation_control: GuardedCampaignContinuationControl,
    ) -> Self {
        self.initial_schedule = schedule;
        self.initial_replay_closure = Some(closure);
        self.discovery_stop = StopCondition::VirtualTimeNanoseconds(checkpoint.virtual_time.ticks);
        self.resume_source = Some(GuardedDefaultCampaignResumeSource {
            checkpoint,
            final_stop,
            checkpoints,
            continuation_control: Some(continuation_control),
            source_observation_proof: None,
            source_observation_evidence: None,
            capture_only: false,
        });
        self
    }

    /// Resumes a portable observation savepoint through an exact source replay.
    ///
    /// The source attempt uses the proof's observation condition instead of a
    /// coordinate stop. Campaign ingestion authenticates the newly produced
    /// proof from retained scheduler evidence, and the owner requires it to
    /// equal the source claim before capturing the physical continuation point.
    #[must_use]
    pub fn with_observation_resume_source(
        mut self,
        // crucible-lint: allow host-nondeterminism-state -- the caller-supplied replay schedule is forwarded unchanged into exact source authentication.
        schedule: Schedule,
        closure: GuardedCampaignReplayClosure,
        checkpoint: Checkpoint,
        source_observation: GuardedDefaultCampaignObservationSource,
        final_stop: StopCondition,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Self {
        self.initial_schedule = schedule;
        self.initial_replay_closure = Some(closure);
        self.discovery_stop =
            StopCondition::Observation(source_observation.proof.condition().clone());
        self.resume_source = Some(GuardedDefaultCampaignResumeSource {
            checkpoint,
            final_stop,
            checkpoints,
            continuation_control: None,
            source_observation_proof: Some(source_observation.proof),
            source_observation_evidence: Some(source_observation.evidence),
            capture_only: false,
        });
        self
    }

    /// Forks a portable observation savepoint under modeled branch control.
    ///
    /// Source replay authenticates the observation proof and retained scheduler
    /// evidence before the campaign admits the controlled continuation.
    #[must_use]
    pub fn with_controlled_observation_resume_source(
        mut self,
        // crucible-lint: allow host-nondeterminism-state -- the caller-supplied replay schedule is forwarded unchanged into exact source authentication.
        schedule: Schedule,
        closure: GuardedCampaignReplayClosure,
        checkpoint: Checkpoint,
        source_observation: GuardedDefaultCampaignObservationSource,
        final_stop: StopCondition,
        checkpoints: Arc<ExactCheckpointStore>,
        continuation_control: GuardedCampaignContinuationControl,
    ) -> Self {
        self.initial_schedule = schedule;
        self.initial_replay_closure = Some(closure);
        self.discovery_stop =
            StopCondition::Observation(source_observation.proof.condition().clone());
        self.resume_source = Some(GuardedDefaultCampaignResumeSource {
            checkpoint,
            final_stop,
            checkpoints,
            continuation_control: Some(continuation_control),
            source_observation_proof: Some(source_observation.proof),
            source_observation_evidence: Some(source_observation.evidence),
            capture_only: false,
        });
        self
    }

    /// Authenticates and captures a portable observation source without continuing it.
    ///
    /// The campaign stops after exact source replay and physical checkpoint
    /// publication. This mode is used by remote session construction so the
    /// returned ordinary session owns every later control and quantum.
    #[must_use]
    pub fn with_observation_resume_source_capture_only(
        mut self,
        // crucible-lint: allow host-nondeterminism-state -- the caller-supplied replay schedule is forwarded unchanged into exact source authentication.
        schedule: Schedule,
        closure: GuardedCampaignReplayClosure,
        checkpoint: Checkpoint,
        source_observation: GuardedDefaultCampaignObservationSource,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Self {
        self.initial_schedule = schedule;
        self.initial_replay_closure = Some(closure);
        self.discovery_stop =
            StopCondition::Observation(source_observation.proof.condition().clone());
        self.resume_source = Some(GuardedDefaultCampaignResumeSource {
            checkpoint,
            final_stop: self.discovery_stop.clone(),
            checkpoints,
            continuation_control: None,
            source_observation_proof: Some(source_observation.proof),
            source_observation_evidence: Some(source_observation.evidence),
            capture_only: true,
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
    configuration: Configuration,
    properties: crucible_campaign::PropertyVerdictSet,
    coverage: crucible_campaign::CoverageProjection,
    evidence: QemuAttemptExecutionEvidenceSnapshot,
    observation_evidence: Option<CrucibleMeasurementReplayEvidence>,
    replay_closure: GuardedCampaignReplayClosure,
    supplemental_finding: Option<GuardedCampaignSupplementalFinding>,
    timeout: Option<GuardedCampaignTimeoutEvidence>,
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

    /// Returns the decoded child configuration authenticated by the observation.
    #[must_use]
    // crucible-lint: allow host-nondeterminism-state -- the configuration is decoded from the accepted campaign artifact and its complete selection closure.
    pub const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the authenticated property verdict set for this observation.
    #[must_use]
    pub const fn properties(&self) -> &crucible_campaign::PropertyVerdictSet {
        &self.properties
    }

    /// Returns the authenticated coverage projection for this observation.
    #[must_use]
    pub const fn coverage(&self) -> &crucible_campaign::CoverageProjection {
        &self.coverage
    }

    /// Returns bounded scheduler evidence captured for this exact attempt.
    #[must_use]
    pub const fn evidence(&self) -> &QemuAttemptExecutionEvidenceSnapshot {
        &self.evidence
    }

    /// Returns the raw replay evidence for an authenticated observation stop.
    #[must_use]
    pub const fn observation_evidence(&self) -> Option<&CrucibleMeasurementReplayEvidence> {
        self.observation_evidence.as_ref()
    }

    /// Returns the exact choice-record closure for this accepted configuration.
    #[must_use]
    pub const fn replay_closure(&self) -> &GuardedCampaignReplayClosure {
        &self.replay_closure
    }

    /// Returns the owner-evaluated supplemental finding, when present.
    #[must_use]
    pub const fn supplemental_finding(&self) -> Option<&GuardedCampaignSupplementalFinding> {
        self.supplemental_finding.as_ref()
    }

    /// Returns the timeout bound and reached scheduler coordinate, when present.
    #[must_use]
    pub const fn timeout(&self) -> Option<GuardedCampaignTimeoutEvidence> {
        self.timeout
    }
}

/// Authenticated modeled-timeout evidence reconstructed from an accepted attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardedCampaignTimeoutEvidence {
    observation: ObservationId,
    execution_quanta_limit: u64,
    observed_execution_quanta: u64,
    frontier: crucible::VirtualTime,
}

impl GuardedCampaignTimeoutEvidence {
    /// Returns the observation that durably owns the modeled timeout.
    #[must_use]
    pub const fn observation(self) -> ObservationId {
        self.observation
    }

    /// Returns the absolute scheduler-quantum timeout from the accepted attempt.
    #[must_use]
    pub const fn execution_quanta_limit(self) -> u64 {
        self.execution_quanta_limit
    }

    /// Returns the scheduler quanta observed when the attempt stopped.
    #[must_use]
    pub const fn observed_execution_quanta(self) -> u64 {
        self.observed_execution_quanta
    }

    /// Returns the modeled virtual-time frontier at the timeout boundary.
    #[must_use]
    pub const fn frontier(self) -> crucible::VirtualTime {
        self.frontier
    }
}

/// Immutable identity of one supplemental finding accepted by the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignSupplementalFinding {
    source: CampaignHash,
    fingerprint: CampaignHash,
    property: String,
}

const SUPPLEMENTAL_FINDING_SOURCE_MAGIC: &[u8; 8] = b"GCSO\0\0\0\x01";
const SUPPLEMENTAL_FINDING_SOURCE_SCHEMA: u32 = 1;
const MAX_SUPPLEMENTAL_FINDING_SOURCE_MEDIA_TYPE_BYTES: usize = 1_024;
const MAX_SUPPLEMENTAL_FINDING_SOURCE_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// Versioned immutable input used to reconstruct a supplemental finding oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingOracleSource {
    scenario: ScenarioDefId,
    media_type: String,
    payload: Vec<u8>,
}

impl GuardedCampaignFindingOracleSource {
    /// Builds one bounded oracle source bound to an exact scenario definition.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignFindingOracleError`] when the media type is
    /// empty, non-ASCII, or too long, or when the payload exceeds 32 MiB.
    pub fn new(
        scenario: ScenarioDefId,
        media_type: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<Self, GuardedCampaignFindingOracleError> {
        let media_type = media_type.into();
        if media_type.is_empty()
            || media_type.len() > MAX_SUPPLEMENTAL_FINDING_SOURCE_MEDIA_TYPE_BYTES
            || !media_type
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
        {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source media type is invalid",
            ));
        }
        if payload.len() > MAX_SUPPLEMENTAL_FINDING_SOURCE_PAYLOAD_BYTES {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source payload exceeds 32 MiB",
            ));
        }
        Ok(Self {
            scenario,
            media_type,
            payload,
        })
    }

    /// Returns the scenario whose configurations the source can evaluate.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the registered payload media type.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Returns the exact source payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes the portable source record.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            SUPPLEMENTAL_FINDING_SOURCE_MAGIC.len()
                + 32
                + std::mem::size_of::<u32>()
                + std::mem::size_of::<u64>()
                + self.media_type.len()
                + self.payload.len(),
        );
        bytes.extend_from_slice(SUPPLEMENTAL_FINDING_SOURCE_MAGIC);
        bytes.extend_from_slice(&self.scenario.as_hash().as_bytes());
        bytes.extend_from_slice(&(self.media_type.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(self.media_type.as_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Decodes and validates a portable source record.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignFindingOracleError`] for malformed,
    /// noncanonical, oversized, or unsupported bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, GuardedCampaignFindingOracleError> {
        const HEADER_BYTES: usize = 8 + 32 + 4 + 8;
        if bytes.len() < HEADER_BYTES
            || bytes.get(..8) != Some(SUPPLEMENTAL_FINDING_SOURCE_MAGIC.as_slice())
        {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source header is invalid",
            ));
        }
        let scenario_bytes: [u8; 32] = bytes[8..40].try_into().map_err(|_| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source scenario is truncated",
            )
        })?;
        let media_length = u32::from_le_bytes(bytes[40..44].try_into().map_err(|_| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source media length is truncated",
            )
        })?) as usize;
        let payload_length = u64::from_le_bytes(bytes[44..52].try_into().map_err(|_| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source payload length is truncated",
            )
        })?);
        let payload_length = usize::try_from(payload_length).map_err(|_| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source payload length is not representable",
            )
        })?;
        let media_end = HEADER_BYTES.checked_add(media_length).ok_or_else(|| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source media length overflows",
            )
        })?;
        let payload_end = media_end.checked_add(payload_length).ok_or_else(|| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source payload length overflows",
            )
        })?;
        if payload_end != bytes.len() {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source lengths disagree with its bytes",
            ));
        }
        let media_type = std::str::from_utf8(&bytes[HEADER_BYTES..media_end])
            .map_err(|_| {
                GuardedCampaignFindingOracleError::new(
                    "supplemental finding source media type is not UTF-8",
                )
            })?
            .to_owned();
        let source = Self::new(
            ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario_bytes)),
            media_type,
            bytes[media_end..].to_vec(),
        )?;
        if source.canonical_bytes() != bytes {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source is not canonically encoded",
            ));
        }
        Ok(source)
    }

    /// Returns the exact retained trace-leaf identity.
    #[must_use]
    pub fn content_id(&self) -> ContentId {
        ContentId::for_bytes(
            ObjectKind::Trace,
            SUPPLEMENTAL_FINDING_SOURCE_SCHEMA,
            &self.canonical_bytes(),
        )
    }

    /// Returns the source identity bound into campaign policy and findings.
    #[must_use]
    pub fn identity(&self) -> CampaignHash {
        CampaignHash::from_bytes(self.content_id().digest())
    }

    /// Reopens and decodes one exact retained source leaf.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignFindingOracleSourceLoadError`] when the leaf
    /// is absent or corrupt, uses another schema, or does not decode exactly.
    pub fn load(
        store: &CampaignExecutorStore,
        content: ContentId,
    ) -> Result<Self, GuardedCampaignFindingOracleSourceLoadError> {
        if content.kind() != ObjectKind::Trace
            || content.schema_version() != SUPPLEMENTAL_FINDING_SOURCE_SCHEMA
        {
            return Err(GuardedCampaignFindingOracleSourceLoadError::WrongSchema);
        }
        let bytes = store
            .load_executor_trace_leaf(
                content,
                (MAX_SUPPLEMENTAL_FINDING_SOURCE_PAYLOAD_BYTES
                    + MAX_SUPPLEMENTAL_FINDING_SOURCE_MEDIA_TYPE_BYTES
                    + 64) as u64,
            )
            .map_err(GuardedCampaignFindingOracleSourceLoadError::Repository)?;
        let source = Self::from_canonical_bytes(&bytes)
            .map_err(GuardedCampaignFindingOracleSourceLoadError::Decode)?;
        if source.content_id() != content {
            return Err(GuardedCampaignFindingOracleSourceLoadError::Identity);
        }
        Ok(source)
    }
}

/// Failure while reopening a retained supplemental-oracle source.
#[derive(Debug, Error)]
pub enum GuardedCampaignFindingOracleSourceLoadError {
    /// The requested leaf does not use the registered trace schema.
    #[error("supplemental finding source has the wrong object kind or schema")]
    WrongSchema,
    /// The immutable repository leaf could not be read and authenticated.
    #[error("load supplemental finding source: {0}")]
    Repository(#[source] CampaignRepositoryError),
    /// The retained bytes do not decode as the registered source format.
    #[error("decode supplemental finding source: {0}")]
    Decode(#[source] GuardedCampaignFindingOracleError),
    /// The decoded source derives another content identity.
    #[error("supplemental finding source identity mismatch")]
    Identity,
}

impl GuardedCampaignSupplementalFinding {
    /// Returns the authenticated supplemental-oracle source identity.
    #[must_use]
    pub const fn source(&self) -> CampaignHash {
        self.source
    }

    /// Returns the exact failure fingerprint reported for the configuration.
    #[must_use]
    pub const fn fingerprint(&self) -> CampaignHash {
        self.fingerprint
    }

    /// Returns the scenario-declared property selected by the oracle.
    #[must_use]
    pub fn property(&self) -> &str {
        &self.property
    }
}

/// One deterministic property failure returned by a supplemental oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingOracleEvaluation {
    finding: crucible::SearchAssertionFinding,
}

impl GuardedCampaignFindingOracleEvaluation {
    /// Retains one typed assertion finding returned by the immutable oracle.
    #[must_use]
    pub fn new(finding: crucible::SearchAssertionFinding) -> Self {
        Self { finding }
    }

    /// Returns the scenario-declared property selected by the oracle.
    #[must_use]
    pub fn property(&self) -> &str {
        &self.finding.violation().assertion.name
    }

    /// Returns the stable failure fingerprint for the evaluated configuration.
    #[must_use]
    pub fn fingerprint(&self) -> CampaignHash {
        CampaignHash::from_bytes(self.finding.fingerprint().bytes)
    }

    /// Returns the actual typed assertion violation produced by the oracle.
    #[must_use]
    pub const fn violation(&self) -> &crucible::HostAssertionViolation {
        self.finding.violation()
    }
}

/// Deterministic configuration oracle evaluated by the campaign owner.
pub trait GuardedCampaignFindingOracle: Send + Sync {
    /// Returns the versioned source bound into policy and retained as evidence.
    fn source(&self) -> &GuardedCampaignFindingOracleSource;

    /// Evaluates one repository-authenticated child configuration.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignFindingOracleError`] when the immutable source
    /// cannot evaluate the accepted configuration exactly.
    fn evaluate(
        &self,
        configuration: &Configuration,
    ) -> Result<Option<GuardedCampaignFindingOracleEvaluation>, GuardedCampaignFindingOracleError>;
}

/// Failure returned by an owner-attached supplemental finding oracle.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct GuardedCampaignFindingOracleError {
    message: String,
}

impl GuardedCampaignFindingOracleError {
    /// Builds an oracle error from stable diagnostic text.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
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
    finding_export: GuardedCampaignFindingExport,
    observations: Vec<GuardedDefaultCampaignObservation>,
    terminal: GuardedDefaultCampaignObservation,
    // crucible-lint: allow host-nondeterminism-state -- the owner exposes only the configuration decoded from the terminal authenticated campaign artifact.
    terminal_configuration: Configuration,
    branch_request_count: usize,
    branch_acceptances: Vec<GuardedCampaignBranchAcceptance>,
    exploration_completion: Option<GuardedCampaignExplorationCompletion>,
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

    /// Returns immutable, request-bound proof material for every final finding.
    #[must_use]
    pub const fn finding_export(&self) -> &GuardedCampaignFindingExport {
        &self.finding_export
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

    /// Returns each repository-accepted exploration request in acceptance order.
    #[must_use]
    pub fn branch_acceptances(&self) -> &[GuardedCampaignBranchAcceptance] {
        &self.branch_acceptances
    }

    /// Returns the bounded exploration completion reason for a search run.
    #[must_use]
    pub const fn exploration_completion(&self) -> Option<GuardedCampaignExplorationCompletion> {
        self.exploration_completion
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
    /// Decoding or authenticating retained measurement evidence failed.
    #[error("guarded default campaign measurement evidence failed: {0}")]
    Measurement(#[source] CrucibleMeasurementError),
    /// A selected replay schedule did not have an exact authenticated choice closure.
    #[error("guarded default campaign replay closure failed: {0}")]
    ReplayClosure(#[source] GuardedCampaignReplayClosureError),
    /// A published physical checkpoint closure failed authentication.
    #[error("guarded default campaign exact checkpoint failed: {0}")]
    ExactCheckpoint(#[source] ExactCheckpointStoreError),
    /// An authenticated supplemental search oracle could not evaluate an observation.
    #[error("guarded default campaign supplemental finding evaluation failed: {0}")]
    SupplementalFinding(#[source] GuardedCampaignFindingOracleError),
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
    /// Final finding proof export was canceled before a transfer or return.
    #[error("final finding proof export was canceled")]
    FindingExportCanceled,
    /// Final finding proof export exceeded its fixed operation or byte bound.
    #[error("final finding proof export exceeded its fixed bound")]
    FindingExportLimit,
    /// Final finding proof export exceeded its finite wall-clock deadline.
    #[error("final finding proof export exceeded its finite deadline")]
    FindingExportDeadline,
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
    /// A decoded child configuration did not match its accepted observation.
    #[error("an accepted observation names a different decoded configuration")]
    ObservationConfigurationMismatch,
    /// A modeled timeout did not match its accepted compound stop and scheduler evidence.
    #[error("an accepted modeled timeout has inconsistent attempt or scheduler evidence")]
    TimeoutEvidenceMismatch,
    /// A supplemental result was not retained by the accepted property evidence.
    #[error("an accepted supplemental finding lacks its exact retained source evidence")]
    SupplementalFindingEvidenceMismatch,
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
    /// Exploration was combined with a single-path checkpoint adapter.
    #[error("local exploration cannot share a campaign with savepoint capture or resume")]
    ConflictingExplorationMode,
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
    /// The source replay produced different raw observation evidence.
    #[error("the legacy resume source replay differs from its retained observation evidence")]
    ResumeSourceEvidenceMismatch,
    /// The source attempt ended at an unrelated nonterminal boundary.
    #[error("the legacy resume source attempt ended before its checkpoint boundary")]
    ResumeSourceStopNotReached,
    /// The selected continuation did not retain the exact capture provenance.
    #[error("the legacy resume continuation differs from its authenticated source capture")]
    ResumeContinuationMismatch,
    /// The completed run lost its authenticated legacy-resume proof.
    #[error("the completed campaign did not retain its legacy-resume proof")]
    MissingResumeProof,
    /// A modeled continuation input did not match the retained source or attempt.
    #[error("the campaign continuation input differs from its authenticated source or attempt")]
    ContinuationInputMismatch,
    /// A modeled continuation input was malformed or unsupported by this runner.
    #[error("the campaign continuation input is malformed or unsupported")]
    InvalidContinuationInput,
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
    let host = LinuxQemuAttemptHostResourceFactory::open(request.host.clone())
        .map_err(GuardedDefaultCampaignRunError::Host)?;
    run_guarded_default_campaign_with_host(request, host)
}

pub(super) fn run_guarded_default_campaign_with_host<H>(
    request: GuardedDefaultCampaignRunRequest,
    host: H,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError>
where
    H: QemuAttemptHostResourceFactory,
    H::Owner: Send + 'static,
{
    validate_initial_replay(&request)?;
    validate_resume_source(&request)?;
    continuation_lifecycle_config(&request)?;
    validate_fresh_qemu_scenario_resources(&request.scenario, request.resources)
        .map_err(GuardedDefaultCampaignRunError::Resource)?;

    let host = SharedQemuAttemptHostResourceFactory::new(host);
    let production = QemuAttemptProductionVmLifecycleFactory::new(
        request.lifecycle.clone(),
        ComposedQemuAttemptResourceGuardFactory::new(host.clone()),
    );
    let (lifecycle_factory, execution_evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(production);
    let supplemental_oracle = request.supplemental_finding_oracle.clone();
    let main_driver = QemuFreshSupplementalModeledDriver::new(supplemental_oracle.clone());
    let main = QemuFreshExecutionRunner::new(lifecycle_factory, main_driver);
    let replay_lifecycles = QemuAttemptProductionVmLifecycleFactory::new(
        request.lifecycle.clone(),
        ComposedQemuAttemptResourceGuardFactory::new(host),
    );
    let replay = QemuFreshExecutionRunner::new(
        replay_lifecycles,
        QemuFreshSupplementalModeledDriver::new(supplemental_oracle),
    );

    let (repository, planner_authority) = default_run_repository(
        Arc::new(MemoryBlobBackend::new(
            "legacy-run-campaign",
            DEFAULT_RUN_REPOSITORY_BYTES,
        )),
        Arc::new(MemoryRefBackend::new()),
    )?;
    let repository = Arc::new(repository);
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let mut runner = AutomaticFindingExecutionRunner::new(store, main, replay);
    if request.verify_determinism_findings {
        runner = runner.with_determinism_finding_verification();
    }

    run_guarded_default_campaign_with_repository(
        request,
        runner,
        execution_evidence,
        repository,
        planner_authority,
    )
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
    continuation_lifecycle_config(&request)?;

    run_guarded_default_campaign_with_validated_runner(request, runner, execution_evidence)
}

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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

    run_guarded_default_campaign_with_repository(
        request,
        runner,
        execution_evidence,
        repository,
        planner_authority,
    )
}

fn run_guarded_default_campaign_with_repository<R>(
    request: GuardedDefaultCampaignRunRequest,
    runner: R,
    execution_evidence: QemuAttemptExecutionEvidence,
    repository: Arc<CampaignRepository>,
    planner_authority: PlannerAuthorityKey,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError<R::Error>>
where
    R: CrucibleExecutionRunner,
    R::Error: Error + Send + Sync + 'static,
{
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
    let supplemental_finding_source = request
        .supplemental_finding_oracle
        .as_deref()
        .map(GuardedCampaignFindingOracle::source)
        .map(GuardedCampaignFindingOracleSource::identity);
    let policy = local_campaign_policy(
        &lineage,
        request.seed,
        &request.discovery_stop,
        request.exploration,
        supplemental_finding_source,
    )?;
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
    let (maximum_branch_requests, maximum_attempts) = request.exploration.map_or_else(
        || {
            (
                DEFAULT_RUN_MAX_CHOICES,
                DEFAULT_RUN_MAX_CHOICES
                    + if request.resume_source.is_some() {
                        2
                    } else {
                        1
                    },
            )
        },
        |exploration| {
            (
                exploration.maximum_attempts(),
                exploration.maximum_attempts(),
            )
        },
    );
    let funded = apply_campaign_control(
        &client,
        &principal,
        &campaign,
        created.snapshot(),
        0,
        CampaignControlAction::GrantBudget(
            BudgetGrant::new(maximum_branch_requests, maximum_attempts)
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
    if let Some(oracle) = request.supplemental_finding_oracle.as_deref() {
        let source_record = oracle.source();
        let expected_scenario =
            ScenarioDefId::from_hash(CampaignHash::from_bytes(request.scenario.id().bytes));
        if source_record.scenario() != expected_scenario {
            return Err(GuardedDefaultCampaignRunError::Codec(
                CampaignCodecError::InvalidValue {
                    reason: "supplemental finding source names another scenario",
                },
            ));
        }
        let source = source_record.content_id();
        let source_bytes = source_record.canonical_bytes();
        store
            .publish_executor_trace_leaf(source, SUPPLEMENTAL_FINDING_SOURCE_SCHEMA, &source_bytes)
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
    }
    let model = CrucibleExecutionModel::new(store.clone(), runner);
    let executor_profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let daemon_epoch =
        DaemonEpoch::from_bytes([0x59; 16]).map_err(GuardedDefaultCampaignRunError::Codec)?;
    let executor_service = SynchronousCampaignExecutor::new(
        store.clone(),
        model,
        RepositoryAttemptAdmission::new(Arc::clone(&repository), executor_profile),
        daemon_epoch,
        request.resources,
        request.cancellation.clone(),
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
    let planner = local_campaign_planner(&repository, planner_authority, request.exploration)?;
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
    let all_candidates = request
        .exploration
        .map(|_| publish_all_candidates_generator(&repository))
        .transpose()
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
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
            exploration: request.exploration,
            all_candidates,
            scenario: &request.scenario,
            scenario_content,
            executor_store: &store,
            supplemental_finding_oracle: request.supplemental_finding_oracle.as_deref(),
        },
        vec![created_state, running_state],
        watch_frames,
        request.collect_watch_frames,
        request.capture_reached_stop.is_some(),
        request.resume_source.as_ref(),
        &mut supervisor,
    )?;
    let finding_export = capture_final_finding_export(
        &client,
        &principal,
        &campaign,
        execution.final_snapshot,
        &request.cancellation,
    )?;
    materialize_result(
        &repository,
        campaign,
        execution,
        finding_export,
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
    if request.exploration.is_some()
        && (request.capture_reached_stop.is_some() || request.resume_source.is_some())
    {
        return Err(GuardedDefaultCampaignInvariantError::ConflictingExplorationMode.into());
    }
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
    branch_acceptances: Vec<GuardedCampaignBranchAcceptance>,
    exploration_completion: Option<GuardedCampaignExplorationCompletion>,
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
    supplemental_finding: Option<GuardedCampaignSupplementalFinding>,
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
    repository: &'a Arc<CampaignRepository>,
    client: &'a CampaignClient<S>,
    execution_evidence: &'a QemuAttemptExecutionEvidence,
    principal: &'a CampaignPrincipal,
    campaign: &'a CampaignName,
    policy: crucible_campaign::CampaignPolicyId,
    discovery_stop: &'a StopCondition,
    initial_configuration_content: crucible_campaign::ConfigurationArtifactId,
    exploration: Option<GuardedCampaignExploration>,
    all_candidates: Option<crucible_campaign::CandidateGeneratorSpecId>,
    scenario: &'a ScenarioDefForm,
    scenario_content: crucible_campaign::ScenarioArtifactId,
    executor_store: &'a CampaignExecutorStore,
    supplemental_finding_oracle: Option<&'a dyn GuardedCampaignFindingOracle>,
}

fn evaluate_supplemental_finding<S, E>(
    context: &DefaultRunContext<'_, S>,
    observation: &Observation,
) -> Result<Option<GuardedCampaignSupplementalFinding>, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let Some(oracle) = context.supplemental_finding_oracle else {
        return Ok(None);
    };
    let child = context
        .repository
        .load_configuration_artifact(observation.child_content())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let scenario_artifact = context
        .repository
        .load_scenario_artifact(context.scenario_content)
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let configuration = decode_crucible_configuration_artifact_with_selections(
        context.scenario,
        &scenario_artifact,
        &child,
        context.executor_store,
    )
    .map_err(GuardedDefaultCampaignRunError::Artifact)?;
    if configuration.id().bytes != observation.child().as_hash().as_bytes() {
        return Err(GuardedDefaultCampaignInvariantError::ObservationConfigurationMismatch.into());
    }
    let evaluation = oracle
        .evaluate(&configuration)
        .map_err(GuardedDefaultCampaignRunError::SupplementalFinding)?;
    let Some(evaluation) = evaluation else {
        return Ok(None);
    };
    let source = oracle.source().content_id();
    let properties = context
        .repository
        .load_property_verdict_set(observation.properties())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let Some(property) = properties.properties().get(evaluation.property()) else {
        return Err(
            GuardedDefaultCampaignInvariantError::SupplementalFindingEvidenceMismatch.into(),
        );
    };
    if property.verdict() != PropertyVerdict::Failed || !property.evidence().contains(&source) {
        return Err(
            GuardedDefaultCampaignInvariantError::SupplementalFindingEvidenceMismatch.into(),
        );
    }
    Ok(Some(GuardedCampaignSupplementalFinding {
        source: oracle.source().identity(),
        fingerprint: evaluation.fingerprint(),
        property: evaluation.property().to_owned(),
    }))
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
    let mut branch_acceptances = Vec::new();
    let mut planner_no_work_snapshot = None;
    let mut exploration_completion = None;
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
        if let CampaignSupervisorStepOutcome::Planner(planner_outcome) = &outcome {
            planner_no_work_snapshot = match planner_outcome {
                CampaignPlannerStepOutcome::Advanced {
                    result,
                    disposition: PlannerDisposition::NoWork,
                } => Some(result.new_snapshot),
                CampaignPlannerStepOutcome::Settled {
                    snapshot,
                    disposition: PlannerDisposition::NoWork,
                    ..
                } => Some(*snapshot),
                CampaignPlannerStepOutcome::BudgetBlocked { snapshot, .. } => {
                    exploration_completion =
                        Some(GuardedCampaignExplorationCompletion::AttemptBudget);
                    Some(*snapshot)
                }
                CampaignPlannerStepOutcome::Inactive { .. }
                | CampaignPlannerStepOutcome::Advanced { .. }
                | CampaignPlannerStepOutcome::Settled { .. } => None,
            };
            continue;
        }
        let CampaignSupervisorStepOutcome::Executor { outcome, .. } = outcome else {
            continue;
        };
        if context.exploration.is_some()
            && let CampaignExecutorStepOutcome::Idle { snapshot } = &outcome
            && Some(*snapshot) == planner_no_work_snapshot
        {
            let evidence = context
                .execution_evidence
                .snapshot()
                .map_err(GuardedDefaultCampaignRunError::Evidence)?;
            let final_snapshot = complete_default_campaign(
                &context,
                *snapshot,
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
                branch_acceptances,
                exploration_completion: Some(
                    exploration_completion
                        .unwrap_or(GuardedCampaignExplorationCompletion::Exhausted),
                ),
                final_snapshot,
                state_updates,
                watch_frames,
                savepoint: None,
                resume: None,
            });
        }

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
                if source.capture_only {
                    let proof = DefaultRunResumeProof {
                        source_checkpoint: source.checkpoint.id,
                        source_configuration: savepoint.reached,
                        source_frontier: source.checkpoint.virtual_time,
                        source_observation,
                        source_evidence: evidence.clone(),
                        source_capture: Some(savepoint),
                        ready_snapshot: None,
                        ready: None,
                        selection: None,
                        continuation: None,
                    };
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
                        branch_acceptances,
                        exploration_completion: None,
                        final_snapshot,
                        state_updates,
                        watch_frames,
                        savepoint: None,
                        resume: Some(proof),
                    });
                }
                let origin = context
                    .repository
                    .load_attempt(savepoint.description.attempt)
                    .map_err(GuardedDefaultCampaignRunError::Repository)?;
                let continuation_start = AttemptStart::AfterAttempt {
                    origin: savepoint.description.attempt,
                    reached: reached_content,
                };
                let continuation = match &source.continuation_control {
                    Some(control) => Attempt::new_with_continuation_input(
                        continuation_start,
                        origin.path(),
                        source.final_stop.clone(),
                        control
                            .input(source_observation)
                            .map_err(GuardedDefaultCampaignRunError::Codec)?,
                    ),
                    None => {
                        Attempt::new(continuation_start, origin.path(), source.final_stop.clone())
                    }
                }
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
                branch_acceptances,
                exploration_completion: None,
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
        let snapshot = result.final_snapshot();
        let observation_id = result.observation_result().observation;
        let execution_boundary = context
            .execution_evidence
            .snapshot()
            .map_err(GuardedDefaultCampaignRunError::Evidence)?;
        let virtual_time_ticks = execution_boundary.frontier().ticks;
        let observation = context
            .repository
            .load_observation(observation_id)
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        let supplemental_finding = evaluate_supplemental_finding(&context, &observation)?;
        let has_supplemental_finding = supplemental_finding.is_some();
        observations.push(DefaultRunAcceptedObservation {
            id: observation_id,
            virtual_time_ticks,
            evidence: execution_boundary.clone(),
            supplemental_finding,
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
            if let Some(expected) = source.source_observation_proof.as_ref()
                && !matches!(
                    observation.stop(),
                    StopOutcome::ObservationReached(actual) if actual.as_ref() == expected
                )
            {
                return Err(
                    GuardedDefaultCampaignInvariantError::ResumeSourceObservationMismatch.into(),
                );
            }
            if let Some(expected) = source.source_observation_evidence.as_ref() {
                let actual = load_observation_stop_evidence(context.repository, &observation)?
                    .ok_or(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch)?;
                let StopOutcome::ObservationReached(proof) = observation.stop() else {
                    return Err(
                        GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch.into(),
                    );
                };
                actual
                    .verify_observation_stop_proof(proof)
                    .map_err(GuardedDefaultCampaignRunError::Measurement)?;
                if &actual != expected {
                    return Err(
                        GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch.into(),
                    );
                }
            }

            if observation.stop().reaches(context.discovery_stop) {
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
                branch_acceptances,
                exploration_completion: None,
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
                        && observation.stop().reaches(&source.final_stop)
                });
        if let Some(exploration) = context.exploration
            && exploration.stop_on_finding()
            && (has_supplemental_finding
                || observation_has_finding(context.repository, &observation)?)
        {
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
                branch_acceptances,
                exploration_completion: Some(GuardedCampaignExplorationCompletion::Finding),
                final_snapshot,
                state_updates,
                watch_frames,
                savepoint: None,
                resume: None,
            });
        }
        if matches!(observation.stop(), StopOutcome::Reached(stop) if stop.accepts_next_choice())
            && !resume_final_stop_reached
        {
            if let Some(exploration) = context.exploration {
                let all_candidates = context
                    .all_candidates
                    .ok_or(GuardedDefaultCampaignInvariantError::MissingChoice)?;
                let mut expected_snapshot = snapshot;
                for opportunity in observation.discovered_choices() {
                    match exploration_branch_request(
                        context.repository,
                        exploration,
                        all_candidates,
                        observation_id,
                        &observation,
                        *opportunity,
                    )? {
                        ExplorationBranchDecision::Request {
                            request: branch,
                            exhausts_domain,
                        } => {
                            let submission = SubmitCampaignBranchRequest::new(
                                context.principal.clone(),
                                context.campaign.clone(),
                                expected_snapshot,
                                *branch,
                            )
                            .map_err(GuardedDefaultCampaignRunError::Codec)?;
                            let response = context
                                .client
                                .submit_branch_request(&submission)
                                .map_err(GuardedDefaultCampaignRunError::Service)?;
                            expected_snapshot = response.new_snapshot();
                            branch_acceptances.push(
                                GuardedCampaignBranchAcceptance::from_response(
                                    observation_id,
                                    &response,
                                    exhausts_domain,
                                ),
                            );
                            if !exhausts_domain && exploration_completion.is_none() {
                                exploration_completion =
                                    Some(GuardedCampaignExplorationCompletion::AttemptBudget);
                            }
                            branch_request_count += 1;
                        }
                        ExplorationBranchDecision::DepthBound => {
                            exploration_completion =
                                Some(GuardedCampaignExplorationCompletion::DepthBound);
                            break;
                        }
                    }
                }
                planner_no_work_snapshot = None;
                continue;
            }
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

        if context.exploration.is_some() {
            planner_no_work_snapshot = None;
            continue;
        }

        if capture_reached_stop {
            if !observation.stop().reaches(context.discovery_stop) {
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
            branch_acceptances,
            exploration_completion: None,
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

// crucible-lint: allow rust-allow -- the explicit inputs bind the control snapshot, observation, requested stop, capture reason, expected evidence, and optional resume source in one request.
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
    finding_export: GuardedCampaignFindingExport,
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
        let child = repository
            .load_configuration_artifact(observation.child_content())
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        let configuration = decode_crucible_configuration_artifact_with_selections(
            &scenario,
            &scenario_artifact,
            &child,
            &store,
        )
        .map_err(GuardedDefaultCampaignRunError::Artifact)?;
        let properties = repository
            .load_property_verdict_set(observation.properties())
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        let coverage = repository
            .load_coverage_projection(observation.coverage())
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        let replay_closure =
            GuardedCampaignReplayClosure::collect(&store, &scenario, &configuration.schedule)
                .map_err(GuardedDefaultCampaignRunError::ReplayClosure)?;
        let observation_evidence = load_observation_stop_evidence(repository, &observation)?;
        let timeout = authenticated_timeout_evidence(
            repository,
            accepted.id,
            &observation,
            &accepted.evidence,
        )?;
        if index + 1 == observation_count {
            terminal_configuration = Some(configuration.clone());
        }
        observations.push(GuardedDefaultCampaignObservation {
            id: accepted.id,
            observation,
            virtual_time_ticks: accepted.virtual_time_ticks,
            configuration,
            properties,
            coverage,
            evidence: accepted.evidence,
            observation_evidence,
            replay_closure,
            supplemental_finding: accepted.supplemental_finding,
            timeout,
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
        finding_export,
        observations,
        terminal,
        terminal_configuration,
        branch_request_count: execution.branch_request_count,
        branch_acceptances: execution.branch_acceptances,
        exploration_completion: execution.exploration_completion,
        state_updates: execution.state_updates,
        watch_frames: execution.watch_frames,
        evidence,
        replay_closure,
        savepoint,
        resume,
    })
}

fn load_observation_stop_evidence<E>(
    repository: &Arc<CampaignRepository>,
    observation: &Observation,
) -> Result<Option<CrucibleMeasurementReplayEvidence>, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let StopOutcome::ObservationReached(proof) = observation.stop() else {
        return Ok(None);
    };
    let store = CampaignExecutorStore::new(Arc::clone(repository));
    let measurements = repository
        .load_measurement_set(observation.measurements())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let retained = measurements
        .evaluation()
        .ok_or(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch)?;
    let mut evidence_ids = retained.evidence().iter();
    let evidence_id = evidence_ids
        .next()
        .copied()
        .ok_or(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch)?;
    if evidence_ids.next().is_some() {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch.into());
    }
    let bytes = store
        .read_measurement_evidence_leaf(
            observation.measurements(),
            evidence_id,
            MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES as u64,
        )
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let evidence = CrucibleMeasurementReplayEvidence::from_canonical_bytes(&bytes)
        .map_err(GuardedDefaultCampaignRunError::Measurement)?;
    if evidence
        .id()
        .map_err(GuardedDefaultCampaignRunError::Measurement)?
        != evidence_id
    {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch.into());
    }
    evidence
        .verify_observation_stop_proof(proof)
        .map_err(GuardedDefaultCampaignRunError::Measurement)?;

    Ok(Some(evidence))
}

fn authenticated_timeout_evidence<E>(
    repository: &CampaignRepository,
    observation_id: ObservationId,
    observation: &Observation,
    evidence: &QemuAttemptExecutionEvidenceSnapshot,
) -> Result<Option<GuardedCampaignTimeoutEvidence>, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let StopOutcome::ModeledTimeout(name) = observation.stop() else {
        return Ok(None);
    };
    let attempt = repository
        .load_attempt(observation.attempt())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let StopCondition::NextChoiceOrExecutionQuanta { execution_quanta } = attempt.stop() else {
        return Err(GuardedDefaultCampaignInvariantError::TimeoutEvidenceMismatch.into());
    };
    if name != "execution-quanta" || evidence.quanta() < *execution_quanta {
        return Err(GuardedDefaultCampaignInvariantError::TimeoutEvidenceMismatch.into());
    }
    Ok(Some(GuardedCampaignTimeoutEvidence {
        observation: observation_id,
        execution_quanta_limit: *execution_quanta,
        observed_execution_quanta: evidence.quanta(),
        frontier: evidence.frontier(),
    }))
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
        | StopCondition::NextChoiceOrExecutionQuanta { .. }
        | StopCondition::Observation(_)
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
