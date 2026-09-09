//! Bounded local exploration policy and branch-request construction.
//!
//! The compatibility campaign owner uses these types to translate one local
//! search into ordinary campaign policy, planner, branch-request, and
//! observation transitions. The CLI never owns a second frontier or expands a
//! choice outside the authenticated campaign repository.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use crucible::Seed;
use crucible_campaign::{
    AuthorizedPlannerService, AuthorizedPlannerServiceError, BranchBudget, BranchRequest,
    BranchRequestCause, CampaignCodecError, CampaignCommandId, CampaignHash, CampaignLineage,
    CampaignMode, CampaignPlannerDriver, CampaignPolicy, CampaignRepository,
    CampaignRepositoryError, CampaignSeed, CampaignSnapshotId, CandidateGeneratorAlgorithm,
    CandidateGeneratorSpec, CandidateSource, ExplorerPolicy, FairnessPolicy, Observation,
    ObservationId, PlannerAuthorityKey, PlannerClient, PlannerRequest, PlannerResponse,
    PlannerService, PlanningBudget, PropertyVerdict, PuctPolicy, RetentionPolicy, StopCondition,
    SubmitCampaignBranchResponse,
};

use super::executor::{LocalPlannerMeter, LocalPlannerMeterError};
use super::{DEFAULT_RUN_PLANNER_SCAN, GuardedDefaultCampaignRunError};

type AuthorizedFrontierPlanner =
    AuthorizedPlannerService<crucible_campaign::CanonicalFrontierPlanner, LocalPlannerMeter>;
type AuthorizedPuctPlanner =
    AuthorizedPlannerService<crucible_campaign::CanonicalPuctPlanner, LocalPlannerMeter>;
type AuthorizedBeamPlanner =
    AuthorizedPlannerService<crucible_campaign::CanonicalBeamPlanner, LocalPlannerMeter>;

pub(super) type LocalCampaignPlannerServiceError =
    AuthorizedPlannerServiceError<CampaignCodecError, LocalPlannerMeterError>;

/// Search order implemented by the local campaign's canonical planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardedCampaignExplorationStrategy {
    /// Consumes the canonical frontier in deterministic order.
    CanonicalFrontier,
    /// Ranks candidates with accepted campaign coverage guidance.
    CoverageGuided,
}

/// Bounded exploration contract for one guarded local campaign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardedCampaignExploration {
    maximum_attempts: u64,
    maximum_depth: Option<u64>,
    stop_on_finding: bool,
    strategy: GuardedCampaignExplorationStrategy,
}

impl GuardedCampaignExploration {
    /// Builds a local exploration contract with an inclusive admission budget.
    ///
    /// The budget counts distinct semantic attempts admitted by the campaign,
    /// including initial discovery. Deduplicated proposals do not spend it.
    /// `maximum_depth` counts authenticated branch-path edges from discovery.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the attempt budget is zero.
    pub fn new(
        maximum_attempts: u64,
        maximum_depth: Option<u64>,
        stop_on_finding: bool,
        strategy: GuardedCampaignExplorationStrategy,
    ) -> Result<Self, CampaignCodecError> {
        if maximum_attempts == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "guarded campaign exploration attempt budget is zero",
            });
        }
        Ok(Self {
            maximum_attempts,
            maximum_depth,
            stop_on_finding,
            strategy,
        })
    }

    /// Returns the maximum distinct semantic attempts admitted by the campaign.
    #[must_use]
    pub const fn maximum_attempts(self) -> u64 {
        self.maximum_attempts
    }

    /// Returns the maximum authenticated branch-path depth, when bounded.
    #[must_use]
    pub const fn maximum_depth(self) -> Option<u64> {
        self.maximum_depth
    }

    /// Returns whether the owner completes after its first accepted finding.
    #[must_use]
    pub const fn stop_on_finding(self) -> bool {
        self.stop_on_finding
    }

    /// Returns the canonical planner strategy for the campaign.
    #[must_use]
    pub const fn strategy(self) -> GuardedCampaignExplorationStrategy {
        self.strategy
    }
}

/// One exact branch request accepted while exploring an observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardedCampaignBranchAcceptance {
    observation: ObservationId,
    request: crucible_campaign::BranchRequestId,
    snapshot: CampaignSnapshotId,
    maximum_attempts: u64,
    exhausts_domain: bool,
}

impl GuardedCampaignBranchAcceptance {
    pub(super) fn from_response(
        observation: ObservationId,
        response: &SubmitCampaignBranchResponse,
        exhausts_domain: bool,
    ) -> Self {
        Self {
            observation,
            request: response.request(),
            snapshot: response.new_snapshot(),
            maximum_attempts: response.summary().maximum_attempts(),
            exhausts_domain,
        }
    }

    /// Returns the accepted observation that exposed the branch point.
    #[must_use]
    pub const fn observation(self) -> ObservationId {
        self.observation
    }

    /// Returns the exact immutable branch-request identity.
    #[must_use]
    pub const fn request(self) -> crucible_campaign::BranchRequestId {
        self.request
    }

    /// Returns the snapshot that accepted the request.
    #[must_use]
    pub const fn snapshot(self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the request-local attempt allowance accepted by the repository.
    #[must_use]
    pub const fn maximum_attempts(self) -> u64 {
        self.maximum_attempts
    }

    /// Returns whether the accepted proposal window covers the entire domain.
    #[must_use]
    pub const fn exhausts_domain(self) -> bool {
        self.exhausts_domain
    }
}

/// Why a bounded exploration campaign stopped producing work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardedCampaignExplorationCompletion {
    /// Every admitted candidate was executed and no frontier work remains.
    Exhausted,
    /// The inclusive campaign attempt budget was consumed.
    AttemptBudget,
    /// At least one discovered branch point was pruned by the depth bound.
    DepthBound,
    /// The owner stopped after accepting a finding observation.
    Finding,
}

pub(super) enum LocalCampaignPlannerService {
    Frontier(AuthorizedFrontierPlanner),
    Puct(AuthorizedPuctPlanner),
    Beam(AuthorizedBeamPlanner),
}

impl PlannerService for LocalCampaignPlannerService {
    type Error = LocalCampaignPlannerServiceError;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerResponse, Self::Error> {
        match (self, request.policy().explorer()) {
            (Self::Frontier(service), ExplorerPolicy::Exhaustive { .. }) => service.plan(request),
            (Self::Puct(service), ExplorerPolicy::TreeSearch { .. }) => service.plan(request),
            (Self::Beam(service), ExplorerPolicy::Beam { .. }) => service.plan(request),
            _ => Err(AuthorizedPlannerServiceError::InvalidOutput(
                CampaignCodecError::InvalidValue {
                    reason: "local campaign explorer policy changed after planner attachment",
                },
            )),
        }
    }
}

pub(super) enum ExplorationBranchDecision {
    Request {
        request: Box<BranchRequest>,
        exhausts_domain: bool,
    },
    DepthBound,
}

pub(super) fn local_campaign_policy<E>(
    lineage: &CampaignLineage,
    seed: Seed,
    discovery_stop: &StopCondition,
    exploration: Option<GuardedCampaignExploration>,
) -> Result<CampaignPolicy, GuardedDefaultCampaignRunError<E>>
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
    let explorer = match exploration.map(GuardedCampaignExploration::strategy) {
        Some(GuardedCampaignExplorationStrategy::CanonicalFrontier) => ExplorerPolicy::Exhaustive {
            maximum_cardinality: u64::MAX,
        },
        Some(GuardedCampaignExplorationStrategy::CoverageGuided) => ExplorerPolicy::TreeSearch {
            puct: PuctPolicy::new(1_000_000, 1_000_000, 0),
            widening: None,
        },
        None => ExplorerPolicy::Beam {
            width: 1,
            novelty_reserve: 0,
        },
    };
    CampaignPolicy::new(
        lineage.scenario(),
        CampaignSeed::from_bytes(seed.bytes()),
        CampaignMode::Strict,
        explorer,
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        stop_conditions,
        FairnessPolicy::new(0, 0).map_err(GuardedDefaultCampaignRunError::Codec)?,
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .and_then(|policy| {
        policy.with_intervention_learning_policy(
            crucible_campaign::InterventionLearningPolicy::IncludeInGuidance,
        )
    })
    .map_err(GuardedDefaultCampaignRunError::Codec)
}

pub(super) fn local_campaign_planner<E>(
    repository: &std::sync::Arc<CampaignRepository>,
    planner_authority: PlannerAuthorityKey,
    exploration: Option<GuardedCampaignExploration>,
) -> Result<CampaignPlannerDriver<LocalCampaignPlannerService>, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let planning_budget = PlanningBudget::new(1, 1, 64, 1024 * 1024, 4096)
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let (engine, artifact, initial_state, service) =
        match exploration.map(GuardedCampaignExploration::strategy) {
            Some(GuardedCampaignExplorationStrategy::CanonicalFrontier) => {
                let basis = repository
                    .publish_canonical_frontier_planner_basis()
                    .map_err(GuardedDefaultCampaignRunError::Repository)?;
                (
                    basis.engine().clone(),
                    basis.artifact().clone(),
                    basis.initial_state().clone(),
                    LocalCampaignPlannerService::Frontier(AuthorizedPlannerService::new(
                        crucible_campaign::CanonicalFrontierPlanner,
                        LocalPlannerMeter,
                        planner_authority.clone(),
                    )),
                )
            }
            Some(GuardedCampaignExplorationStrategy::CoverageGuided) => {
                let basis = repository
                    .publish_canonical_puct_planner_basis()
                    .map_err(GuardedDefaultCampaignRunError::Repository)?;
                (
                    basis.engine().clone(),
                    basis.artifact().clone(),
                    basis.initial_state().clone(),
                    LocalCampaignPlannerService::Puct(AuthorizedPlannerService::new(
                        crucible_campaign::CanonicalPuctPlanner,
                        LocalPlannerMeter,
                        planner_authority.clone(),
                    )),
                )
            }
            None => {
                let basis = repository
                    .publish_canonical_beam_planner_basis()
                    .map_err(GuardedDefaultCampaignRunError::Repository)?;
                (
                    basis.engine().clone(),
                    basis.artifact().clone(),
                    basis.initial_state().clone(),
                    LocalCampaignPlannerService::Beam(AuthorizedPlannerService::new(
                        crucible_campaign::CanonicalBeamPlanner,
                        LocalPlannerMeter,
                        planner_authority.clone(),
                    )),
                )
            }
        };
    let planner = CampaignPlannerDriver::new(
        std::sync::Arc::clone(repository),
        PlannerClient::new(service, planner_authority),
        engine,
        artifact,
        initial_state,
        DEFAULT_RUN_PLANNER_SCAN,
        planning_budget,
    )
    .map_err(GuardedDefaultCampaignRunError::PlannerConfiguration)?;
    Ok(
        match exploration.map(GuardedCampaignExploration::strategy) {
            Some(GuardedCampaignExplorationStrategy::CanonicalFrontier) => {
                planner.require_exhaustive_policy()
            }
            Some(GuardedCampaignExplorationStrategy::CoverageGuided) => {
                planner.require_tree_search_policy()
            }
            None => planner.require_beam_policy(),
        },
    )
}

pub(super) fn publish_all_candidates_generator(
    repository: &CampaignRepository,
) -> Result<crucible_campaign::CandidateGeneratorSpecId, CampaignRepositoryError> {
    let generator = CandidateGeneratorSpec::new(
        crucible_campaign::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )?;
    repository.publish_generator(&generator)
}

pub(super) fn exploration_branch_request<E>(
    repository: &CampaignRepository,
    exploration: GuardedCampaignExploration,
    all_candidates: crucible_campaign::CandidateGeneratorSpecId,
    observation_id: ObservationId,
    observation: &Observation,
    opportunity_id: crucible_campaign::ChoiceOpportunityId,
) -> Result<ExplorationBranchDecision, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let path = repository
        .load_branch_path(observation.path())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let path_depth = u64::try_from(path.edges().len()).unwrap_or(u64::MAX);
    if exploration
        .maximum_depth()
        .is_some_and(|maximum| path_depth >= maximum)
    {
        return Ok(ExplorationBranchDecision::DepthBound);
    }
    let opportunity = repository
        .load_choice_opportunity(opportunity_id)
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let domain = repository
        .load_choice_domain(opportunity.domain())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    // The campaign ledger, rather than the observation count, is authoritative
    // for unique attempt admission. This request-local cap may therefore exceed
    // the remaining global allowance: the planner charges only newly admitted
    // attempts and reports budget exhaustion after deduplicating proposals.
    let maximum_attempts = u64::try_from(
        domain
            .cardinality()
            .min(u128::from(exploration.maximum_attempts())),
    )
    .map_err(|_| CampaignCodecError::LimitExceeded {
        limit: "guarded-campaign-branch-cardinality",
    })
    .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let mut command_basis = observation_id.content_id().encode().into_bytes();
    command_basis.extend_from_slice(opportunity_id.content_id().encode().as_bytes());
    let command = CampaignCommandId::from_hash(CampaignHash::derive(
        "crucible.daemon.local-exploration-branch.v1",
        &command_basis,
    ));
    let request = BranchRequest::new(
        opportunity.branch_point_id(observation.child()),
        observation.child_content(),
        opportunity_id,
        opportunity.domain(),
        CandidateSource::generated(all_candidates),
        BranchRequestCause::Operator(command),
        BranchBudget::new(maximum_attempts, maximum_attempts)
            .map_err(GuardedDefaultCampaignRunError::Codec)?,
        StopCondition::NextChoice,
    )
    .map_err(GuardedDefaultCampaignRunError::Codec)?;
    Ok(ExplorationBranchDecision::Request {
        request: Box::new(request),
        exhausts_domain: domain.cardinality() <= u128::from(maximum_attempts),
    })
}

pub(super) fn observation_has_finding<E>(
    repository: &CampaignRepository,
    observation: &Observation,
) -> Result<bool, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let properties = repository
        .load_property_verdict_set(observation.properties())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    Ok(properties
        .properties()
        .values()
        .any(|evidence| evidence.verdict() == PropertyVerdict::Failed)
        || matches!(
            observation.stop(),
            crucible_campaign::StopOutcome::AssertionFailure(_)
                | crucible_campaign::StopOutcome::ScenarioFailure(_)
        ))
}
