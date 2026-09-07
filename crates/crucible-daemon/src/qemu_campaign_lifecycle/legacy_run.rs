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
use crucible::Configuration;
use crucible::{ScenarioDefForm, Schedule, Seed};
// crucible-lint: allow host-nondeterminism-state -- the caller supplies a validated production lifecycle capability; host observations cannot alter modeled choices.
use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{
    ApplyCampaignCommandRequest, AttemptResourceLimits, AuthorizedPlannerService, BranchBudget,
    BranchRequest, BranchRequestCause, BudgetGrant, CampaignAuthorizationError, CampaignClient,
    CampaignClientError, CampaignCodecError, CampaignCommandId, CampaignControlAction,
    CampaignExecutorDriver, CampaignExecutorDriverConfigError, CampaignExecutorStepOutcome,
    CampaignExecutorStore, CampaignHash, CampaignLineage, CampaignMode, CampaignName,
    CampaignPlannerDriver, CampaignPlannerDriverConfigError, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignRepository, CampaignRepositoryError, CampaignSeed,
    CampaignServiceOperation, CampaignSnapshotId, CampaignState, CampaignSupervisor,
    CampaignSupervisorConfigError, CampaignSupervisorStepOutcome, CandidateSource,
    CreateCampaignRequest, DaemonEpoch, DebuggerAuthorityKey, ExecutionRetentionIntent,
    ExecutorCompatibilityProfile, ExplorerPolicy, FairnessPolicy, Observation, ObservationId,
    PlannerAuthorityKey, PlannerClient, PlannerService, PlanningBudget, RepositoryCampaignService,
    RetentionPolicy, StopOutcome, SubmitCampaignBranchRequest,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};
use thiserror::Error;

use super::{
    QemuAttemptExecutionEvidence, QemuAttemptExecutionEvidenceSnapshot,
    QemuAttemptProductionVmLifecycleFactory, QemuFreshExecutionRunner,
    QemuFreshScenarioResourceError, QemuObservedFreshAttemptLifecycleFactory,
    validate_fresh_qemu_scenario_resources,
};
use crate::{
    ComposedQemuAttemptResourceGuardFactory, CrucibleArtifactError, CrucibleCampaignArtifactStore,
    CrucibleExecutionModel, CrucibleExecutionRunner, LinuxQemuAttemptHostConfig,
    LinuxQemuAttemptHostResourceFactory, QemuFreshModeledDriver, RepositoryAttemptAdmission,
    decode_crucible_configuration_artifact,
};

mod executor;
use executor::{LocalPlannerMeter, SynchronousCampaignExecutor};

#[cfg(test)]
mod tests;

const DEFAULT_RUN_MAX_CHOICES: u64 = 65_536;
const DEFAULT_RUN_REPOSITORY_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_RUN_EXECUTOR_SCAN: usize = 1_024;
const DEFAULT_RUN_PLANNER_SCAN: u32 = 1_024;
const DEFAULT_RUN_MAX_SUPERVISOR_STEPS: usize = 1_000_000;
const DEFAULT_RUN_RECONCILIATION_STEPS: usize = 64;

/// Opaque shared-owner failure while advancing one guarded campaign.
#[derive(Debug)]
pub struct GuardedDefaultCampaignSupervisorError(Box<dyn Error + Send + Sync>);

impl fmt::Display for GuardedDefaultCampaignSupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Error for GuardedDefaultCampaignSupervisorError {
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
        }
    }

    /// Starts discovery from an authenticated recorded schedule.
    ///
    /// This is the campaign replay adapter: the executor re-materializes the
    /// supplied configuration before publishing any observation. The schedule
    /// remains modeled input and does not weaken host resource ownership.
    #[must_use]
    pub fn with_initial_schedule(mut self, schedule: Schedule) -> Self {
        self.initial_schedule = schedule;
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
    evidence: QemuAttemptExecutionEvidenceSnapshot,
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

    /// Returns the bounded scheduler-authored evidence from the terminal attempt.
    #[must_use]
    pub const fn evidence(&self) -> &QemuAttemptExecutionEvidenceSnapshot {
        &self.evidence
    }
}

/// Failure while owning one guarded default campaign run.
#[derive(Debug, Error)]
pub enum GuardedDefaultCampaignRunError {
    /// A canonical campaign request or artifact record was invalid.
    #[error("guarded default campaign record is invalid: {0}")]
    Codec(#[source] CampaignCodecError),
    /// Crucible artifact encoding or decoding failed authentication.
    #[error("guarded default campaign artifact failed: {0}")]
    Artifact(#[source] CrucibleArtifactError),
    /// The campaign repository rejected a durable operation.
    #[error("guarded default campaign repository failed: {0}")]
    Repository(#[source] CampaignRepositoryError),
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
    /// Static supervisor composition was invalid.
    #[error("guarded default campaign supervisor configuration failed: {0}")]
    SupervisorConfiguration(#[source] CampaignSupervisorConfigError),
    /// The shared campaign planner or executor supervisor failed.
    #[error("guarded default campaign supervisor failed: {0}")]
    Supervisor(#[source] GuardedDefaultCampaignSupervisorError),
    /// Reading the bounded terminal-attempt evidence failed.
    #[error("guarded default campaign evidence failed: {0}")]
    Evidence(#[source] crucible::SchedulerError),
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
    /// An accepted choice was not paired with the required next-choice stop.
    #[error("a choice was accepted outside the next-choice boundary")]
    ChoiceOutsideBoundary,
    /// A nonterminal observation contained no choice to continue.
    #[error("a nonterminal observation contained no authenticated choice")]
    MissingChoice,
    /// The completed campaign did not retain a terminal observation.
    #[error("the completed campaign retained no terminal observation")]
    MissingTerminalObservation,
    /// A bounded control-command ordinal overflowed.
    #[error("the campaign control-command ordinal overflowed")]
    CommandOrdinalOverflow,
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

    run_guarded_default_campaign_with_runner(request, runner, execution_evidence)
}

fn run_guarded_default_campaign_with_runner<R>(
    request: GuardedDefaultCampaignRunRequest,
    runner: R,
    execution_evidence: QemuAttemptExecutionEvidence,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError>
where
    R: CrucibleExecutionRunner,
    R::Error: Error + Send + Sync + 'static,
{
    let planner_authority = PlannerAuthorityKey::from_bytes([0x31; 32])
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let debugger_authority = DebuggerAuthorityKey::from_bytes([0x47; 32])
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let repository = Arc::new(
        CampaignRepository::with_component_authorities(
            Arc::new(MemoryBlobBackend::new(
                "legacy-run-campaign",
                DEFAULT_RUN_REPOSITORY_BYTES,
            )),
            Arc::new(MemoryRefBackend::new()),
            planner_authority.clone(),
            debugger_authority,
        )
        .map_err(GuardedDefaultCampaignRunError::Repository)?,
    );
    let artifacts = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    let initial_schedule = request.initial_schedule.clone();
    let scenario_content = artifacts
        .import_scenario(&request.scenario)
        .map_err(GuardedDefaultCampaignRunError::Artifact)?;
    let genesis_content = artifacts
        .import_configuration(&request.scenario, &initial_schedule)
        .map_err(GuardedDefaultCampaignRunError::Artifact)?;
    let lineage = default_run_lineage(&request, scenario_content, genesis_content)?;
    let policy = default_run_policy(&lineage, request.seed)?;
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
            BudgetGrant::new(DEFAULT_RUN_MAX_CHOICES, DEFAULT_RUN_MAX_CHOICES + 1)
                .map_err(GuardedDefaultCampaignRunError::Codec)?,
        ),
    )?;
    apply_campaign_control(
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
    let planner_basis = repository
        .publish_canonical_frontier_planner_basis()
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let planner_service = AuthorizedPlannerService::new(
        crucible_campaign::CanonicalFrontierPlanner,
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
    .map_err(GuardedDefaultCampaignRunError::PlannerConfiguration)?;
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

    let execution = drive_default_campaign(
        DefaultRunContext {
            repository: &repository,
            client: &client,
            execution_evidence: &execution_evidence,
            principal: &principal,
            campaign: &campaign,
            policy: policy.id().map_err(GuardedDefaultCampaignRunError::Codec)?,
        },
        vec![created_state, running_state],
        &mut supervisor,
    )?;
    materialize_result(
        &repository,
        campaign,
        execution,
        execution_evidence
            .snapshot()
            .map_err(GuardedDefaultCampaignRunError::Evidence)?,
    )
}

fn default_run_lineage(
    request: &GuardedDefaultCampaignRunRequest,
    scenario_content: crucible_campaign::ScenarioArtifactId,
    genesis_content: crucible_campaign::ConfigurationArtifactId,
) -> Result<CampaignLineage, GuardedDefaultCampaignRunError> {
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

fn default_run_policy(
    lineage: &CampaignLineage,
    seed: Seed,
) -> Result<crucible_campaign::CampaignPolicy, GuardedDefaultCampaignRunError> {
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
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).map_err(GuardedDefaultCampaignRunError::Codec)?,
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .map_err(GuardedDefaultCampaignRunError::Codec)
}

fn apply_campaign_control<S>(
    client: &CampaignClient<S>,
    principal: &CampaignPrincipal,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    ordinal: u64,
    action: CampaignControlAction,
) -> Result<CampaignSnapshotId, GuardedDefaultCampaignRunError>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
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
}

struct DefaultRunAcceptedObservation {
    id: ObservationId,
    virtual_time_ticks: u64,
}

struct DefaultRunContext<'a, S> {
    repository: &'a CampaignRepository,
    client: &'a CampaignClient<S>,
    execution_evidence: &'a QemuAttemptExecutionEvidence,
    principal: &'a CampaignPrincipal,
    campaign: &'a CampaignName,
    policy: crucible_campaign::CampaignPolicyId,
}

fn drive_default_campaign<P, E, S>(
    context: DefaultRunContext<'_, S>,
    mut state_updates: Vec<CampaignState>,
    supervisor: &mut CampaignSupervisor<P, E>,
) -> Result<DefaultRunExecution, GuardedDefaultCampaignRunError>
where
    P: PlannerService,
    P::Error: Error + Send + Sync + 'static,
    E: crucible_campaign::ExecutorControlService + crucible_campaign::ExecutorResumeService,
    E::Error: Error + Send + Sync + 'static,
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let mut observations = Vec::new();
    let mut branch_request_count = 0usize;
    for supervisor_iteration in 0..DEFAULT_RUN_MAX_SUPERVISOR_STEPS {
        // crucible-lint: allow host-nondeterminism-state -- the shared supervisor advances only authenticated campaign planner and executor operations.
        let supervisor_result = supervisor.step();
        let outcome = supervisor_result
            .map_err(|error| GuardedDefaultCampaignSupervisorError(Box::new(error)))
            .map_err(GuardedDefaultCampaignRunError::Supervisor)?;
        let CampaignSupervisorStepOutcome::Executor {
            outcome: CampaignExecutorStepOutcome::Incorporated(result),
            ..
        } = outcome
        else {
            continue;
        };
        let snapshot = result.new_snapshot;
        let observation_id = result.observation;
        let virtual_time_ticks = context
            .execution_evidence
            .snapshot()
            .map_err(GuardedDefaultCampaignRunError::Evidence)?
            .frontier()
            .ticks;
        let observation = context
            .repository
            .load_observation(observation_id)
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        observations.push(DefaultRunAcceptedObservation {
            id: observation_id,
            virtual_time_ticks,
        });

        if let Some(opportunity_id) = observation.discovered_choices().iter().next().copied() {
            if observation.stop()
                != &StopOutcome::Reached(crucible_campaign::StopCondition::NextChoice)
            {
                return Err(GuardedDefaultCampaignInvariantError::ChoiceOutsideBoundary.into());
            }
            if branch_request_count >= DEFAULT_RUN_MAX_CHOICES as usize {
                return Err(GuardedDefaultCampaignInvariantError::ChoiceLimit.into());
            }
            let opportunity = context
                .repository
                .load_choice_opportunity(opportunity_id)
                .map_err(GuardedDefaultCampaignRunError::Repository)?;
            let branch = BranchRequest::new(
                opportunity.branch_point_id(observation.child()),
                observation.child_content(),
                opportunity_id,
                opportunity.domain(),
                CandidateSource::finite(BTreeSet::from([opportunity.default().clone()]))
                    .map_err(GuardedDefaultCampaignRunError::Codec)?,
                BranchRequestCause::ScenarioDefault(context.policy),
                BranchBudget::new(1, 1).map_err(GuardedDefaultCampaignRunError::Codec)?,
                crucible_campaign::StopCondition::NextChoice,
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

        if matches!(observation.stop(), StopOutcome::Reached(_)) {
            return Err(GuardedDefaultCampaignInvariantError::MissingChoice.into());
        }

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
        return Ok(DefaultRunExecution {
            observations,
            branch_request_count,
            final_snapshot,
            state_updates,
        });
    }
    Err(GuardedDefaultCampaignInvariantError::SupervisorStepLimit.into())
}

fn materialize_result(
    repository: &CampaignRepository,
    campaign: CampaignName,
    execution: DefaultRunExecution,
    evidence: QemuAttemptExecutionEvidenceSnapshot,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError> {
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
    let mut observations = Vec::new();
    observations
        .try_reserve(execution.observations.len())
        .map_err(GuardedDefaultCampaignRunError::Allocation)?;
    let observation_count = execution.observations.len();
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
                decode_crucible_configuration_artifact(&scenario, &scenario_artifact, &child)
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
    Ok(GuardedDefaultCampaignRun {
        campaign,
        final_snapshot: execution.final_snapshot,
        observations,
        terminal,
        terminal_configuration,
        branch_request_count: execution.branch_request_count,
        state_updates: execution.state_updates,
        evidence,
    })
}

impl From<GuardedDefaultCampaignInvariantError> for GuardedDefaultCampaignRunError {
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
