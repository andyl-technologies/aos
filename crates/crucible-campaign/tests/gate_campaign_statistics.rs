//! Implements the finite static subset of `gate:campaign-statistics`.
//!
//! The gate drives a policy-declared unequal `P`/`Q` draw through the public
//! repository and planner surfaces, then rebuilds the exact report after a
//! repository restart. Adaptive resampling and sequential Monte Carlo remain
//! outside this first executable contract.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::sync::{Arc, Mutex, MutexGuard};

use crucible_campaign::{
    Attempt, AttemptStart, BooleanDomain, BranchPath, BranchPathSegment, BranchRequest,
    BudgetGrant, CampaignCodecError, CampaignCommandId, CampaignControlAction, CampaignHash,
    CampaignLineage, CampaignMode, CampaignPlannerDriver, CampaignPlannerStepOutcome,
    CampaignPolicy, CampaignRepository, CampaignRepositoryError, CampaignSeed,
    CanonicalFrontierPlanner, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceOpportunity, ChoiceSource, ChoiceValue, ControlRequest, CoverageProjection,
    DebuggerAuthorityKey, ExplorerPolicy, FairnessPolicy, MeasurementSet, Observation,
    PlannerAuthorityKey, PlannerDisposition, PlannerExecutionSupervisor,
    PlannerProposalDisposition, PlannerRequest, PlanningBudget, PropertyVerdictSet, Proposal,
    PurePlannerEngine, RetentionPolicy, ScenarioDefId, SelectableDeclaration, Selection,
    SelectionOrigin, StatisticalDistribution, StatisticalDrawPlan, StatisticalSamplingDesign,
    StopCondition, StopOutcome, SupervisedPlannerExecution,
};
use crucible_cas::content_store::{
    ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend, MutableRefBackend,
};

#[derive(Clone)]
struct GatePlannerSupervisor {
    issued_requests: Arc<Mutex<Vec<BranchRequest>>>,
    issued_proposals: Arc<Mutex<Vec<Proposal>>>,
}

fn lock_recorder<T>(recorder: &Mutex<T>) -> MutexGuard<'_, T> {
    match recorder.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl PlannerExecutionSupervisor<CanonicalFrontierPlanner> for GatePlannerSupervisor {
    type Error = Infallible;

    fn execute(
        &mut self,
        engine: &mut CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let output = engine.plan(request);
        if let Ok(output) = &output
            && let PlannerProposalDisposition::Issue {
                branch_requests,
                proposals,
                ..
            } = output.proposal().disposition()
        {
            lock_recorder(&self.issued_requests).extend(branch_requests.iter().cloned());
            lock_recorder(&self.issued_proposals).extend(proposals.iter().cloned());
        }
        Ok(SupervisedPlannerExecution::new(
            output,
            request.invocation().scan_page().input_objects() + 1,
        ))
    }
}

#[test]
fn finite_static_statistical_report_preserves_exact_p_q_after_restart() -> Result<(), Box<dyn Error>>
{
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(MemoryBlobBackend::new(
        "campaign-statistics-gate",
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

    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "gate.campaign-statistics",
        b"scenario",
    ));
    let genesis = crucible_campaign::ConfigurationId::from_hash(CampaignHash::derive(
        "gate.campaign-statistics",
        b"genesis",
    ));
    let scenario_content =
        repository.publish_scenario_artifact(scenario, 1, b"statistical scenario".to_vec())?;
    let genesis_content = repository.publish_configuration_artifact(
        scenario,
        scenario_content,
        genesis,
        1,
        b"statistical genesis".to_vec(),
    )?;
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-statistics-gate",
        "qemu-statistics-gate",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )?;

    let model = crucible_campaign::ProbabilityModelId::from_hash(CampaignHash::derive(
        "gate.campaign-statistics",
        b"model",
    ));
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1)?);
    let declaration = SelectableDeclaration::new(
        "product.network.retry",
        ChoiceSource::Workload {
            producer: String::from("statistics-gate"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from([String::from("network-recovery")]))?,
        BTreeSet::new(),
        true,
    )?;
    repository.publish_choice_domain(&domain)?;
    repository.publish_selectable(&declaration)?;
    let opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("gate.campaign-statistics", b"scheduler"),
            producer: CampaignHash::derive("gate.campaign-statistics", b"producer"),
        },
        "statistical-draw",
        Some(model),
    )?;
    repository.publish_choice_opportunity(&opportunity)?;

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
    let policy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([0x41; 32]),
        CampaignMode::Statistical,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 2,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0)?,
        RetentionPolicy::new(true, 1, true, true),
        true,
    )?
    .with_statistical_sampling_design(design)?;

    let campaign = "campaign-statistics-gate";
    let created = repository.create(campaign, &lineage, &policy, &BTreeMap::new())?;
    let funded = repository.apply_control(
        campaign,
        &ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "gate.campaign-statistics",
                b"fund",
            )),
            expected_snapshot: created.snapshot_id(),
            action: CampaignControlAction::GrantBudget(BudgetGrant::new(8, 8)?),
        },
    )?;
    let discovered = repository.discover_operator_choice_opportunity(
        campaign,
        funded.new_snapshot,
        genesis_content,
        opportunity.id()?,
    )?;
    repository.apply_control(
        campaign,
        &ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "gate.campaign-statistics",
                b"resume",
            )),
            expected_snapshot: discovered.new_snapshot,
            action: CampaignControlAction::Resume,
        },
    )?;

    let repository = Arc::new(repository);
    let basis = repository.publish_canonical_frontier_planner_basis()?;
    let (engine, artifact, initial_state) = basis.into_parts();
    let recorded_requests = Arc::new(Mutex::new(Vec::new()));
    let recorded_proposals = Arc::new(Mutex::new(Vec::new()));
    let planner = crucible_campaign::PlannerClient::new(
        crucible_campaign::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            GatePlannerSupervisor {
                issued_requests: Arc::clone(&recorded_requests),
                issued_proposals: Arc::clone(&recorded_proposals),
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
    } = driver.step(campaign)?
    else {
        return Err("statistical planner did not issue the declared request".into());
    };
    assert_eq!(issued_branch_requests.len(), 1);
    assert!(issued_proposals.is_empty());
    let request = lock_recorder(&recorded_requests)
        .pop()
        .ok_or("planner request recorder is empty")?;
    assert_eq!(request.id()?, issued_branch_requests[0]);

    let CampaignPlannerStepOutcome::Advanced {
        result: admitted,
        disposition:
            PlannerDisposition::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            },
    } = driver.step(campaign)?
    else {
        return Err("statistical planner did not admit the declared proposal".into());
    };
    assert!(issued_branch_requests.is_empty());
    assert_eq!(issued_proposals.len(), 1);
    let proposal = lock_recorder(&recorded_proposals)
        .pop()
        .ok_or("planner proposal recorder is empty")?;
    assert_eq!(proposal.id()?, issued_proposals[0]);
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        request.branch_point(),
    )?;
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        return Err("statistical selection lost its campaign origin".into());
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(request.branch_point(), edge)])?;
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: request.parent(),
            selection: selection.id()?,
        },
        path.id()?,
        request.stop().clone(),
    )?;

    let child = crucible_campaign::ConfigurationId::from_hash(CampaignHash::derive(
        "gate.campaign-statistics",
        b"child",
    ));
    let child_content = repository.publish_configuration_artifact(
        scenario,
        scenario_content,
        child,
        1,
        b"statistical child".to_vec(),
    )?;
    let measurements =
        repository.publish_measurement_set(&MeasurementSet::new(BTreeMap::new())?)?;
    let properties =
        repository.publish_property_verdict_set(&PropertyVerdictSet::new(BTreeMap::new())?)?;
    let coverage = repository
        .publish_coverage_projection(&CoverageProjection::new(BTreeSet::new(), BTreeSet::new())?)?;
    let observation = Observation::new(
        attempt.id()?,
        child,
        child_content,
        path.id()?,
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([request.opportunity()]),
    )?;
    let observed = repository.publish_observation(campaign, admitted.new_snapshot, &observation)?;

    let report = repository.project_statistical_estimate(campaign, observed.new_snapshot)?;
    assert_eq!(report.endpoints().len(), 1);
    let endpoint = &report.endpoints()[0];
    match proposal.value() {
        ChoiceValue::Boolean(false) => {
            assert_eq!(
                (
                    endpoint.target_probability().numerator(),
                    endpoint.target_probability().denominator()
                ),
                (1, 4)
            );
            assert_eq!(
                (
                    endpoint.proposal_probability().numerator(),
                    endpoint.proposal_probability().denominator()
                ),
                (3, 4)
            );
            assert_eq!(
                (
                    endpoint.importance_weight().numerator(),
                    endpoint.importance_weight().denominator()
                ),
                (1, 3)
            );
        }
        ChoiceValue::Boolean(true) => {
            assert_eq!(
                (
                    endpoint.target_probability().numerator(),
                    endpoint.target_probability().denominator()
                ),
                (3, 4)
            );
            assert_eq!(
                (
                    endpoint.proposal_probability().numerator(),
                    endpoint.proposal_probability().denominator()
                ),
                (1, 4)
            );
            assert_eq!(
                (
                    endpoint.importance_weight().numerator(),
                    endpoint.importance_weight().denominator()
                ),
                (3, 1)
            );
        }
        value => return Err(format!("unexpected statistical value: {value:?}").into()),
    }
    let event = BTreeSet::from([endpoint.observation()]);
    assert_eq!(report.estimate_event(&event)?, endpoint.importance_weight());
    assert_eq!(
        (
            report.estimate_event_self_normalized(&event)?.numerator(),
            report.estimate_event_self_normalized(&event)?.denominator(),
        ),
        (1, 1)
    );

    let restarted = CampaignRepository::with_component_authorities(
        blobs,
        refs,
        planner_authority,
        debugger_authority,
    )?;
    let rebuilt = restarted.project_statistical_estimate(campaign, observed.new_snapshot)?;
    assert_eq!(rebuilt, report);

    Ok(())
}

#[test]
fn finite_static_policy_rejects_support_drift_and_unmodeled_probability_claims()
-> Result<(), Box<dyn Error>> {
    assert!(matches!(
        StatisticalDistribution::new(
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 1),
                (ChoiceValue::Boolean(true), 1),
            ]),
            BTreeMap::from([(ChoiceValue::Boolean(false), 1)]),
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "statistical distribution has invalid P or Q support"
        })
    ));

    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(MemoryBlobBackend::new(
        "campaign-statistics-refusal-gate",
        8 * 1024 * 1024,
    ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs, refs);
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "gate.campaign-statistics.refusal",
        b"scenario",
    ));
    let genesis = crucible_campaign::ConfigurationId::from_hash(CampaignHash::derive(
        "gate.campaign-statistics.refusal",
        b"genesis",
    ));
    let scenario_content = repository.publish_scenario_artifact(scenario, 1, vec![1])?;
    let genesis_content = repository.publish_configuration_artifact(
        scenario,
        scenario_content,
        genesis,
        1,
        vec![2],
    )?;
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-statistics-refusal",
        "qemu-statistics-refusal",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )?;
    let legacy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([0x51; 32]),
        CampaignMode::Statistical,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 2,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0)?,
        RetentionPolicy::new(true, 1, true, true),
        true,
    )?;
    let created =
        repository.create("unmodeled-statistical", &lineage, &legacy, &BTreeMap::new())?;
    assert!(matches!(
        repository.project_statistical_estimate("unmodeled-statistical", created.snapshot_id()),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical-report-policy-lacks-design"
        })
    ));

    Ok(())
}
