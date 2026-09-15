//! Exercises the complete RFC-0020 branch-point model through public APIs.
//!
//! The gate covers parent-scoped branch identity, finite/generated convergence,
//! lazy request progress, semantic-attempt deduplication, retained causes,
//! immutable execution basis, idempotent observation credit, cold-restart
//! cursor recovery, and statistical exclusion of operator/debugger executions.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::sync::{Arc, Mutex, MutexGuard};

use crucible_campaign::{
    Attempt, AttemptAdmissionResult, AttemptAdmissionRole, AttemptStart, BooleanDomain,
    BranchBudget, BranchPath, BranchPathSegment, BranchRequest, BranchRequestCause, BudgetGrant,
    CampaignAuthorizationError, CampaignClient, CampaignCodecError, CampaignCommandId,
    CampaignControlAction, CampaignHash, CampaignLineage, CampaignMode, CampaignName,
    CampaignPlannerDriver, CampaignPlannerStepOutcome, CampaignPolicy, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignRepository, CampaignRepositoryError, CampaignSeed,
    CampaignServiceOperation, CandidateGeneratorAlgorithm, CandidateGeneratorSpec, CandidateSource,
    CanonicalFrontierPlanner, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceOpportunity, ChoicePolicy, ChoiceSource, ChoiceValue, ConfigurationId, ContinuationState,
    ControlRequest, CoverageProjection, DebugSessionId, DebuggerAuthorityKey, DebuggerSubmission,
    ExplainCampaignAttemptRequest, ExplorerPolicy, FairnessPolicy,
    GetCampaignFrontierObjectRequest, MeasurementSet, Observation, PlannerAuthorityKey,
    PlannerDisposition, PlannerExecutionSupervisor, PlannerProposalDisposition, PlannerRequest,
    PlanningBudget, ProgressiveWideningPolicy, PropertyVerdictSet, Proposal, PuctPolicy,
    RepositoryCampaignService, RetentionPolicy, ScenarioDefId, SelectableDeclaration, Selection,
    SelectionOrigin, StatisticalDistribution, StatisticalDrawPlan, StatisticalSamplingDesign,
    StopCondition, StopOutcome, SupervisedPlannerExecution,
};
use crucible_cas::content_store::{
    ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend, MutableRefBackend,
};

const BRANCH_CAMPAIGN: &str = "branch-point-model";
const STATISTICAL_CAMPAIGN: &str = "branch-point-statistical";

struct AllowCampaignQueries;

impl CampaignPrincipalAuthorizer for AllowCampaignQueries {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

#[derive(Clone)]
struct RecordingPlannerSupervisor {
    requests: Arc<Mutex<Vec<BranchRequest>>>,
    proposals: Arc<Mutex<Vec<Proposal>>>,
}

impl PlannerExecutionSupervisor<CanonicalFrontierPlanner> for RecordingPlannerSupervisor {
    type Error = Infallible;

    fn execute(
        &mut self,
        engine: &mut CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        use crucible_campaign::PurePlannerEngine;

        let output = engine.plan(request);
        if let Ok(output) = &output
            && let PlannerProposalDisposition::Issue {
                branch_requests,
                proposals,
                ..
            } = output.proposal().disposition()
        {
            lock(&self.requests).extend(branch_requests.iter().cloned());
            lock(&self.proposals).extend(proposals.iter().cloned());
        }

        Ok(SupervisedPlannerExecution::new(
            output,
            request.invocation().scan_page().input_objects() + 1,
        ))
    }
}

#[test]
fn finite_and_generated_sources_converge_and_resume_after_restart() -> Result<(), Box<dyn Error>> {
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(MemoryBlobBackend::new(
        "branch-point-model-gate",
        64 * 1024 * 1024,
    ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(MemoryRefBackend::new());
    let planner_authority = PlannerAuthorityKey::from_bytes([0x21; 32])?;
    let debugger_authority = DebuggerAuthorityKey::from_bytes([0x22; 32])?;
    let repository = CampaignRepository::with_component_authorities(
        Arc::clone(&blobs),
        Arc::clone(&refs),
        planner_authority.clone(),
        debugger_authority.clone(),
    )?;
    let (lineage, domain, opportunity) = publish_boolean_choice(&repository, "branch-point")?;

    let generator = CandidateGeneratorSpec::new(
        crucible_campaign::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )?;
    let generator_id = generator.id()?;
    let policy = tree_search_policy(
        lineage.scenario(),
        "product.network.retry.branch-point",
        generator_id,
    )?;
    let created = repository.create(
        BRANCH_CAMPAIGN,
        &lineage,
        &policy,
        &BTreeMap::from([(generator_id, generator)]),
    )?;
    let funded = fund_campaign(&repository, BRANCH_CAMPAIGN, created.snapshot_id(), 8, 4)?;
    let discovered = repository.discover_choice_opportunity(
        BRANCH_CAMPAIGN,
        funded,
        lineage.genesis_content(),
        opportunity.id()?,
    )?;

    let branch_point = opportunity.branch_point_id(lineage.genesis());
    let other_parent = ConfigurationId::from_hash(CampaignHash::derive(
        "gate.branch-point.parent",
        b"different parent",
    ));
    assert_ne!(branch_point, opportunity.branch_point_id(other_parent));

    let finite_cause = BranchRequestCause::Operator(command_id("finite-request"));
    let finite_request = BranchRequest::new(
        BranchRequest::identity(
            branch_point,
            lineage.genesis_content(),
            opportunity.id()?,
            domain.id()?,
        ),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))?,
        finite_cause,
        BranchBudget::new(2, 2)?,
        StopCondition::NextChoice,
    )?;
    let finite_accepted = repository.submit_operator_branch_request(
        BRANCH_CAMPAIGN,
        discovered.new_snapshot,
        &finite_request,
    )?;

    let debug_session = DebugSessionId::from_hash(CampaignHash::derive(
        "gate.branch-point.debug-session",
        b"generated request",
    ));
    let generated_cause = BranchRequestCause::Debugger(debug_session);
    let generated_request = BranchRequest::new(
        BranchRequest::identity(
            branch_point,
            lineage.genesis_content(),
            opportunity.id()?,
            domain.id()?,
        ),
        CandidateSource::generated(generator_id),
        generated_cause,
        BranchBudget::new(2, 2)?,
        StopCondition::NextChoice,
    )?;
    let debugger_submission = DebuggerSubmission::authorize(
        &debugger_authority,
        finite_accepted.new_snapshot,
        debug_session,
        generated_request.clone(),
    )?;
    let generated_accepted =
        repository.submit_debugger_branch_request(BRANCH_CAMPAIGN, &debugger_submission)?;

    let initial_expansion =
        repository.load_expansion_state(repository.project_finite_expansion(
            generated_accepted.new_snapshot,
            branch_point,
            None,
            8,
        )?)?;
    assert_eq!(initial_expansion.continuations().len(), 2);
    assert_eq!(
        initial_expansion.continuations().get(&finite_request.id()?),
        Some(&ContinuationState::Ready)
    );
    assert_eq!(
        initial_expansion
            .continuations()
            .get(&generated_request.id()?),
        Some(&ContinuationState::Ready)
    );

    let finite_proposal = proposal_at_head(
        &repository,
        BRANCH_CAMPAIGN,
        &policy,
        &finite_request,
        ChoiceValue::Boolean(false),
        1,
    )?;
    let finite_proposed = repository.issue_proposal(
        BRANCH_CAMPAIGN,
        generated_accepted.new_snapshot,
        &finite_proposal,
    )?;
    let (selection, path, attempt) =
        branch_attempt(&opportunity, &domain, &finite_request, &finite_proposal)?;
    let finite_admitted = repository.admit_proposal(
        BRANCH_CAMPAIGN,
        finite_proposed.new_snapshot,
        finite_proposed.proposal,
        &selection,
        &path,
        &attempt,
    )?;

    let generated_proposal = proposal_at_head(
        &repository,
        BRANCH_CAMPAIGN,
        &policy,
        &generated_request,
        ChoiceValue::Boolean(false),
        1,
    )?;
    let generated_proposed = repository.issue_proposal(
        BRANCH_CAMPAIGN,
        finite_admitted.new_snapshot,
        &generated_proposal,
    )?;
    let (generated_selection, generated_path, generated_attempt) = branch_attempt(
        &opportunity,
        &domain,
        &generated_request,
        &generated_proposal,
    )?;
    assert_eq!(generated_selection.origin(), selection.origin());
    assert_eq!(generated_attempt.id()?, attempt.id()?);
    let generated_admitted = repository.admit_proposal(
        BRANCH_CAMPAIGN,
        generated_proposed.new_snapshot,
        generated_proposed.proposal,
        &generated_selection,
        &generated_path,
        &generated_attempt,
    )?;
    assert_eq!(generated_admitted.attempt, finite_admitted.attempt);

    assert_execution_basis(
        &repository,
        &finite_admitted,
        finite_proposal.id()?,
        finite_cause,
    )?;
    let additional = repository.load_attempt_admission(generated_admitted.admission)?;
    assert_eq!(
        additional.role(),
        AttemptAdmissionRole::AdditionalCause {
            proposal: generated_proposal.id()?
        }
    );

    let observed = publish_observation(
        &repository,
        &lineage,
        CampaignHead {
            name: BRANCH_CAMPAIGN,
            snapshot: generated_admitted.new_snapshot,
        },
        &generated_request,
        &generated_path,
        generated_admitted.attempt,
        "converged-child",
    )?;
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        return Err("branch selection lost its semantic edge".into());
    };
    let visits = repository.project_branch_edge_visits(observed, branch_point)?;
    assert_eq!(visits.parent_visits(), 1);
    assert_eq!(visits.edge_visits(), &BTreeMap::from([(edge, 1)]));
    assert_explained_basis(
        &repository,
        BRANCH_CAMPAIGN,
        observed,
        ExpectedExecutionBasis {
            attempt: finite_admitted.attempt,
            admission: finite_admitted.admission,
            proposal: finite_proposal.id()?,
            request: finite_request.id()?,
            cause: finite_cause,
        },
    )?;
    assert_additional_cause(
        &repository,
        BRANCH_CAMPAIGN,
        observed,
        generated_admitted.admission,
        generated_proposal.id()?,
        &generated_request,
    )?;

    drop(repository);
    let restarted = CampaignRepository::with_component_authorities(
        blobs,
        refs,
        planner_authority,
        debugger_authority,
    )?;
    let restarted_head = restarted.head(BRANCH_CAMPAIGN)?;
    assert_eq!(restarted_head.snapshot_id(), observed);
    assert_execution_basis(
        &restarted,
        &finite_admitted,
        finite_proposal.id()?,
        finite_cause,
    )?;
    assert_eq!(
        restarted
            .load_attempt_admission(generated_admitted.admission)?
            .role(),
        AttemptAdmissionRole::AdditionalCause {
            proposal: generated_proposal.id()?
        }
    );
    assert_explained_basis(
        &restarted,
        BRANCH_CAMPAIGN,
        restarted_head.snapshot_id(),
        ExpectedExecutionBasis {
            attempt: finite_admitted.attempt,
            admission: finite_admitted.admission,
            proposal: finite_proposal.id()?,
            request: finite_request.id()?,
            cause: finite_cause,
        },
    )?;
    assert_additional_cause(
        &restarted,
        BRANCH_CAMPAIGN,
        restarted_head.snapshot_id(),
        generated_admitted.admission,
        generated_proposal.id()?,
        &generated_request,
    )?;

    let client = CampaignClient::new(RepositoryCampaignService::new(
        &restarted,
        AllowCampaignQueries,
    ));
    let principal = CampaignPrincipal::new("gate:branch-point-model")?;
    let campaign = CampaignName::new(BRANCH_CAMPAIGN)?;
    for (expected, request_id) in [
        (&finite_request, finite_request.id()?),
        (&generated_request, generated_request.id()?),
    ] {
        let response =
            client.get_campaign_frontier_object(&GetCampaignFrontierObjectRequest::new(
                principal.clone(),
                campaign.clone(),
                restarted_head.snapshot_id(),
                request_id,
            )?)?;
        assert_eq!(response.object(), expected);
        assert_eq!(response.projection().state(), ContinuationState::Ready);
    }

    let resumed_finite = proposal_at_head(
        &restarted,
        BRANCH_CAMPAIGN,
        &policy,
        &finite_request,
        ChoiceValue::Boolean(true),
        2,
    )?;
    let finite_resumed = restarted.issue_proposal(
        BRANCH_CAMPAIGN,
        restarted_head.snapshot_id(),
        &resumed_finite,
    )?;
    let resumed_generated = proposal_at_head(
        &restarted,
        BRANCH_CAMPAIGN,
        &policy,
        &generated_request,
        ChoiceValue::Boolean(true),
        2,
    )?;
    restarted.issue_proposal(
        BRANCH_CAMPAIGN,
        finite_resumed.new_snapshot,
        &resumed_generated,
    )?;
    assert_eq!(
        (resumed_finite.ordinal(), resumed_generated.ordinal()),
        (2, 2)
    );

    Ok(())
}

#[test]
fn statistical_estimate_only_includes_policy_predeclared_executions() -> Result<(), Box<dyn Error>>
{
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(MemoryBlobBackend::new(
        "branch-point-statistical-gate",
        64 * 1024 * 1024,
    ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(MemoryRefBackend::new());
    let planner_authority = PlannerAuthorityKey::from_bytes([0x31; 32])?;
    let debugger_authority = DebuggerAuthorityKey::from_bytes([0x32; 32])?;
    let repository = CampaignRepository::with_component_authorities(
        Arc::clone(&blobs),
        Arc::clone(&refs),
        planner_authority.clone(),
        debugger_authority.clone(),
    )?;
    let (lineage, domain, opportunity) = publish_modeled_boolean_choice(&repository)?;
    let model = opportunity
        .model_prior()
        .ok_or("modeled opportunity has no model")?;
    let distribution = StatisticalDistribution::new(
        BTreeMap::from([
            (ChoiceValue::Boolean(false), 1),
            (ChoiceValue::Boolean(true), 3),
        ]),
        BTreeMap::from([
            (ChoiceValue::Boolean(false), 3),
            (ChoiceValue::Boolean(true), 1),
        ]),
    )?;
    let design = StatisticalSamplingDesign::new(
        BTreeMap::from([(model, distribution)]),
        BTreeMap::from([(
            0,
            StatisticalDrawPlan::new(None, &opportunity, model, StopCondition::NextChoice)?,
        )]),
        BTreeSet::from([0]),
    )?;
    let policy = exhaustive_statistical_policy(lineage.scenario(), design)?;
    let created = repository.create(STATISTICAL_CAMPAIGN, &lineage, &policy, &BTreeMap::new())?;
    let funded = fund_campaign(
        &repository,
        STATISTICAL_CAMPAIGN,
        created.snapshot_id(),
        8,
        8,
    )?;
    let discovered = repository.discover_choice_opportunity(
        STATISTICAL_CAMPAIGN,
        funded,
        lineage.genesis_content(),
        opportunity.id()?,
    )?;
    let running = repository.apply_control(
        STATISTICAL_CAMPAIGN,
        &ControlRequest {
            command: command_id("statistical-resume"),
            expected_snapshot: discovered.new_snapshot,
            action: CampaignControlAction::Resume,
        },
    )?;
    assert_eq!(
        repository.head(STATISTICAL_CAMPAIGN)?.snapshot_id(),
        running.new_snapshot
    );

    let repository = Arc::new(repository);
    let recorded_requests = Arc::new(Mutex::new(Vec::new()));
    let recorded_proposals = Arc::new(Mutex::new(Vec::new()));
    let (engine, artifact, initial_state) = repository
        .publish_canonical_frontier_planner_basis()?
        .into_parts();
    let planner = crucible_campaign::PlannerClient::new(
        crucible_campaign::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            RecordingPlannerSupervisor {
                requests: Arc::clone(&recorded_requests),
                proposals: Arc::clone(&recorded_proposals),
            },
            planner_authority.clone(),
        ),
        planner_authority.clone(),
    );
    let mut driver = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        planner,
        engine,
        artifact,
        initial_state,
        4,
        PlanningBudget::new(1, 1, 8, 8_192, 100)?,
    )?
    .require_exhaustive_policy();

    let CampaignPlannerStepOutcome::Advanced {
        disposition:
            PlannerDisposition::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            },
        ..
    } = driver.step(STATISTICAL_CAMPAIGN)?
    else {
        return Err("planner did not issue the predeclared statistical request".into());
    };
    assert_eq!(
        (issued_branch_requests.len(), issued_proposals.len()),
        (1, 0)
    );
    let statistical_request = lock(&recorded_requests)
        .pop()
        .ok_or("statistical request was not recorded")?;

    let CampaignPlannerStepOutcome::Advanced {
        result: statistical_admitted,
        disposition:
            PlannerDisposition::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            },
    } = driver.step(STATISTICAL_CAMPAIGN)?
    else {
        return Err("planner did not admit the predeclared statistical proposal".into());
    };
    assert_eq!(
        (issued_branch_requests.len(), issued_proposals.len()),
        (0, 1)
    );
    let statistical_proposal = lock(&recorded_proposals)
        .pop()
        .ok_or("statistical proposal was not recorded")?;
    let (_statistical_selection, statistical_path, statistical_attempt) = branch_attempt(
        &opportunity,
        &domain,
        &statistical_request,
        &statistical_proposal,
    )?;
    let statistical_observed = publish_observation(
        repository.as_ref(),
        &lineage,
        CampaignHead {
            name: STATISTICAL_CAMPAIGN,
            snapshot: statistical_admitted.new_snapshot,
        },
        &statistical_request,
        &statistical_path,
        statistical_attempt.id()?,
        "declared-statistical-child",
    )?;
    let declared_observation = repository
        .project_statistical_estimate(STATISTICAL_CAMPAIGN, statistical_observed)?
        .endpoints()[0]
        .observation();
    let statistical_basis = repository
        .collect_finite_statistical_evidence(STATISTICAL_CAMPAIGN, statistical_observed)?
        .draws()[0]
        .execution()
        .execution_basis()
        .admission()
        .id()?;

    let operator_request = intervention_request(
        &statistical_request,
        statistical_proposal.value().clone(),
        BranchRequestCause::Operator(command_id("statistical-operator")),
        StopCondition::NamedBoundary(String::from("operator-intervention")),
    )?;
    let operator_requested = repository.submit_operator_branch_request(
        STATISTICAL_CAMPAIGN,
        statistical_observed,
        &operator_request,
    )?;
    let operator_proposal = proposal_at_head(
        repository.as_ref(),
        STATISTICAL_CAMPAIGN,
        &policy,
        &operator_request,
        statistical_proposal.value().clone(),
        1,
    )?;
    let operator_proposed = repository.issue_proposal(
        STATISTICAL_CAMPAIGN,
        operator_requested.new_snapshot,
        &operator_proposal,
    )?;
    let (operator_selection, operator_path, operator_attempt) =
        branch_attempt(&opportunity, &domain, &operator_request, &operator_proposal)?;
    assert_ne!(operator_attempt.id()?, statistical_attempt.id()?);
    let operator_admitted = repository.admit_proposal(
        STATISTICAL_CAMPAIGN,
        operator_proposed.new_snapshot,
        operator_proposed.proposal,
        &operator_selection,
        &operator_path,
        &operator_attempt,
    )?;
    assert_execution_basis(
        repository.as_ref(),
        &operator_admitted,
        operator_proposal.id()?,
        operator_request.cause(),
    )?;
    let operator_observed = publish_observation(
        repository.as_ref(),
        &lineage,
        CampaignHead {
            name: STATISTICAL_CAMPAIGN,
            snapshot: operator_admitted.new_snapshot,
        },
        &operator_request,
        &operator_path,
        operator_admitted.attempt,
        "declared-statistical-child",
    )?;

    let debug_session = DebugSessionId::from_hash(CampaignHash::derive(
        "gate.branch-point.statistical-debugger",
        b"session",
    ));
    let debugger_request = intervention_request(
        &statistical_request,
        statistical_proposal.value().clone(),
        BranchRequestCause::Debugger(debug_session),
        StopCondition::EventCount(1),
    )?;
    let debugger_submission = DebuggerSubmission::authorize(
        &debugger_authority,
        operator_observed,
        debug_session,
        debugger_request.clone(),
    )?;
    let debugger_requested =
        repository.submit_debugger_branch_request(STATISTICAL_CAMPAIGN, &debugger_submission)?;
    let debugger_proposal = proposal_at_head(
        repository.as_ref(),
        STATISTICAL_CAMPAIGN,
        &policy,
        &debugger_request,
        statistical_proposal.value().clone(),
        1,
    )?;
    let debugger_proposed = repository.issue_proposal(
        STATISTICAL_CAMPAIGN,
        debugger_requested.new_snapshot,
        &debugger_proposal,
    )?;
    let (debugger_selection, debugger_path, debugger_attempt) =
        branch_attempt(&opportunity, &domain, &debugger_request, &debugger_proposal)?;
    assert_ne!(debugger_attempt.id()?, statistical_attempt.id()?);
    assert_ne!(debugger_attempt.id()?, operator_attempt.id()?);
    let debugger_admitted = repository.admit_proposal(
        STATISTICAL_CAMPAIGN,
        debugger_proposed.new_snapshot,
        debugger_proposed.proposal,
        &debugger_selection,
        &debugger_path,
        &debugger_attempt,
    )?;
    assert_execution_basis(
        repository.as_ref(),
        &debugger_admitted,
        debugger_proposal.id()?,
        debugger_request.cause(),
    )?;
    let debugger_observed = publish_observation(
        repository.as_ref(),
        &lineage,
        CampaignHead {
            name: STATISTICAL_CAMPAIGN,
            snapshot: debugger_admitted.new_snapshot,
        },
        &debugger_request,
        &debugger_path,
        debugger_admitted.attempt,
        "declared-statistical-child",
    )?;

    let duplicate_request = intervention_request(
        &statistical_request,
        statistical_proposal.value().clone(),
        BranchRequestCause::Operator(command_id("statistical-duplicate")),
        statistical_request.stop().clone(),
    )?;
    let duplicate_requested = repository.submit_operator_branch_request(
        STATISTICAL_CAMPAIGN,
        debugger_observed,
        &duplicate_request,
    )?;
    let duplicate_proposal = proposal_at_head(
        repository.as_ref(),
        STATISTICAL_CAMPAIGN,
        &policy,
        &duplicate_request,
        statistical_proposal.value().clone(),
        1,
    )?;
    let duplicate_proposed = repository.issue_proposal(
        STATISTICAL_CAMPAIGN,
        duplicate_requested.new_snapshot,
        &duplicate_proposal,
    )?;
    let (duplicate_selection, duplicate_path, duplicate_attempt) = branch_attempt(
        &opportunity,
        &domain,
        &duplicate_request,
        &duplicate_proposal,
    )?;
    assert_eq!(duplicate_attempt.id()?, statistical_attempt.id()?);
    let duplicate_admitted = repository.admit_proposal(
        STATISTICAL_CAMPAIGN,
        duplicate_proposed.new_snapshot,
        duplicate_proposed.proposal,
        &duplicate_selection,
        &duplicate_path,
        &duplicate_attempt,
    )?;
    assert_eq!(duplicate_admitted.attempt, statistical_attempt.id()?);
    assert_eq!(
        repository
            .load_attempt_admission(duplicate_admitted.admission)?
            .role(),
        AttemptAdmissionRole::AdditionalCause {
            proposal: duplicate_proposal.id()?
        }
    );
    assert_explained_basis(
        repository.as_ref(),
        STATISTICAL_CAMPAIGN,
        duplicate_admitted.new_snapshot,
        ExpectedExecutionBasis {
            attempt: statistical_attempt.id()?,
            admission: statistical_basis,
            proposal: statistical_proposal.id()?,
            request: statistical_request.id()?,
            cause: statistical_request.cause(),
        },
    )?;
    let completed_head = duplicate_admitted.new_snapshot;

    // A caller also cannot disguise an intervention as a policy draw because
    // the canonical statistical source admits only planner causes.
    let target_masses = BTreeMap::from([
        (ChoiceValue::Boolean(false), 1),
        (ChoiceValue::Boolean(true), 3),
    ]);
    let proposal_masses = BTreeMap::from([
        (ChoiceValue::Boolean(false), 3),
        (ChoiceValue::Boolean(true), 1),
    ]);
    for cause in [operator_request.cause(), debugger_request.cause()] {
        let disguised = BranchRequest::new(
            BranchRequest::identity(
                statistical_request.branch_point(),
                statistical_request.parent(),
                statistical_request.opportunity(),
                statistical_request.domain(),
            ),
            CandidateSource::statistical_finite(
                0,
                model,
                target_masses.clone(),
                proposal_masses.clone(),
            )?,
            cause,
            BranchBudget::new(1, 1)?,
            StopCondition::NextChoice,
        );
        assert!(matches!(
            disguised,
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical source requires one planner draw"
            })
        ));
    }

    let mismatched_smc = BranchRequest::new(
        BranchRequest::identity(
            statistical_request.branch_point(),
            statistical_request.parent(),
            statistical_request.opportunity(),
            statistical_request.domain(),
        ),
        CandidateSource::statistical_smc(
            crucible_campaign::StatisticalGenerationId::from_hash(CampaignHash::derive(
                "gate.branch-point.mismatched-smc-generation",
                b"generation",
            )),
            crucible_campaign::StatisticalParticleId::from_hash(CampaignHash::derive(
                "gate.branch-point.mismatched-smc-particle",
                b"particle",
            )),
            1,
            0,
            model,
            target_masses,
            proposal_masses,
        )?,
        statistical_request.cause(),
        BranchBudget::new(1, 1)?,
        StopCondition::NextChoice,
    )?;
    assert!(matches!(
        repository.submit_branch_request(
            STATISTICAL_CAMPAIGN,
            duplicate_admitted.new_snapshot,
            &mismatched_smc,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical-policy-requires-statistical-request"
        })
    ));

    assert_eq!(
        repository.head(STATISTICAL_CAMPAIGN)?.snapshot_id(),
        completed_head
    );
    let raw_visits = repository
        .project_branch_edge_visits(completed_head, statistical_request.branch_point())?;
    assert_eq!(raw_visits.parent_visits(), 3);
    let estimate = repository.project_statistical_estimate(STATISTICAL_CAMPAIGN, completed_head)?;
    assert_eq!(estimate.endpoints().len(), 1);
    assert_eq!(estimate.endpoints()[0].observation(), declared_observation);

    drop(driver);
    drop(repository);
    let restarted = CampaignRepository::with_component_authorities(
        blobs,
        refs,
        planner_authority,
        debugger_authority,
    )?;
    let rebuilt = restarted.project_statistical_estimate(STATISTICAL_CAMPAIGN, completed_head)?;
    assert_eq!(rebuilt.endpoints(), estimate.endpoints());
    assert_explained_basis(
        &restarted,
        STATISTICAL_CAMPAIGN,
        completed_head,
        ExpectedExecutionBasis {
            attempt: statistical_attempt.id()?,
            admission: statistical_basis,
            proposal: statistical_proposal.id()?,
            request: statistical_request.id()?,
            cause: statistical_request.cause(),
        },
    )?;
    assert_additional_cause(
        &restarted,
        STATISTICAL_CAMPAIGN,
        completed_head,
        duplicate_admitted.admission,
        duplicate_proposal.id()?,
        &duplicate_request,
    )?;

    // The declared draw is a planner execution basis with authenticated P/Q
    // evidence. Completed operator and debugger executions remain useful raw
    // history without entering the one-coordinate statistical population.
    assert!(matches!(
        statistical_request.cause(),
        BranchRequestCause::Planner(_)
    ));
    assert!(statistical_proposal.statistical_evidence().is_some());

    Ok(())
}

#[path = "gate_branch_point_model/support.rs"]
mod support;

use support::*;
