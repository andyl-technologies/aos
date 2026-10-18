//! Shared branch-point model gate fixtures.

use super::*;

pub(super) fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    match value.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(super) fn publish_boolean_choice(
    repository: &CampaignRepository,
    label: &str,
) -> Result<(CampaignLineage, ChoiceDomain, ChoiceOpportunity), Box<dyn Error>> {
    publish_boolean_choice_with_model(repository, label, None)
}

pub(super) fn publish_modeled_boolean_choice(
    repository: &CampaignRepository,
) -> Result<(CampaignLineage, ChoiceDomain, ChoiceOpportunity), Box<dyn Error>> {
    let model = crucible_campaign::ProbabilityModelId::from_hash(CampaignHash::derive(
        "gate.branch-point.statistical-model",
        b"modeled boolean",
    ));
    publish_boolean_choice_with_model(repository, "statistical", Some(model))
}

pub(super) fn publish_boolean_choice_with_model(
    repository: &CampaignRepository,
    label: &str,
    model: Option<crucible_campaign::ProbabilityModelId>,
) -> Result<(CampaignLineage, ChoiceDomain, ChoiceOpportunity), Box<dyn Error>> {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "gate.branch-point.scenario",
        label.as_bytes(),
    ));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive(
        "gate.branch-point.genesis",
        label.as_bytes(),
    ));
    let scenario_content =
        repository.publish_scenario_artifact(scenario, 1, format!("{label} scenario").into())?;
    let genesis_content = repository.publish_configuration_artifact(
        scenario,
        scenario_content,
        genesis,
        1,
        format!("{label} genesis").into(),
    )?;
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-branch-point-gate",
        "qemu-branch-point-gate",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )?;
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1)?);
    let declaration = SelectableDeclaration::new(
        format!("product.network.retry.{label}"),
        ChoiceSource::Workload {
            producer: String::from("branch-point-gate"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new())?,
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
            scheduler: CampaignHash::derive("gate.branch-point.coordinate", label.as_bytes()),
            producer: CampaignHash::derive("gate.branch-point.producer", label.as_bytes()),
        },
        label,
        model,
    )?;
    repository.publish_choice_opportunity(&opportunity)?;

    Ok((lineage, domain, opportunity))
}

pub(super) fn tree_search_policy(
    scenario: ScenarioDefId,
    selector: &str,
    generator: crucible_campaign::CandidateGeneratorSpecId,
) -> Result<CampaignPolicy, Box<dyn Error>> {
    let widening = ProgressiveWideningPolicy::new(
        crucible_campaign::ExactRational::new(1, 1)?,
        crucible_campaign::ExactRational::new(1, 2)?,
        1,
        16,
        1,
    )?;
    Ok(CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([0x17; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::from([(
                selector.to_owned(),
                ChoicePolicy::new(selector, generator, false)?,
            )]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0)?,
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )?)
}

pub(super) fn exhaustive_statistical_policy(
    scenario: ScenarioDefId,
    design: StatisticalSamplingDesign,
) -> Result<CampaignPolicy, Box<dyn Error>> {
    Ok(CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([0x27; 32]),
            CampaignMode::Statistical,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 2,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0)?,
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )?
    .with_statistical_sampling_design(design)?)
}

pub(super) fn fund_campaign(
    repository: &CampaignRepository,
    campaign: &str,
    snapshot: crucible_campaign::CampaignSnapshotId,
    proposals: u64,
    attempts: u64,
) -> Result<crucible_campaign::CampaignSnapshotId, Box<dyn Error>> {
    Ok(repository
        .apply_control(
            campaign,
            &ControlRequest {
                command: command_id(&format!("fund-{campaign}")),
                expected_snapshot: snapshot,
                action: CampaignControlAction::GrantBudget(BudgetGrant::new(proposals, attempts)?),
            },
        )?
        .new_snapshot)
}

pub(super) fn proposal_at_head(
    repository: &CampaignRepository,
    campaign: &str,
    policy: &CampaignPolicy,
    request: &BranchRequest,
    value: ChoiceValue,
    ordinal: u64,
) -> Result<Proposal, Box<dyn Error>> {
    let head = repository.head(campaign)?;
    Ok(Proposal::new_for_request(
        request.branch_point(),
        request.id()?,
        request.domain(),
        value,
        policy.id()?,
        None,
        ordinal,
        head.snapshot().planning_view().id()?,
        request,
    )?)
}

pub(super) fn branch_attempt(
    opportunity: &ChoiceOpportunity,
    domain: &ChoiceDomain,
    request: &BranchRequest,
    proposal: &Proposal,
) -> Result<(Selection, BranchPath, Attempt), Box<dyn Error>> {
    let selection = Selection::new_campaign_branch(
        opportunity,
        domain,
        proposal.value().clone(),
        request.branch_point(),
    )?;
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        return Err("selection is not a campaign branch".into());
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

    Ok((selection, path, attempt))
}

pub(super) fn intervention_request(
    basis: &BranchRequest,
    value: ChoiceValue,
    cause: BranchRequestCause,
    stop: StopCondition,
) -> Result<BranchRequest, Box<dyn Error>> {
    Ok(BranchRequest::new(
        BranchRequest::identity(
            basis.branch_point(),
            basis.parent(),
            basis.opportunity(),
            basis.domain(),
        ),
        CandidateSource::finite(BTreeSet::from([value]))?,
        cause,
        BranchBudget::new(1, 1)?,
        stop,
    )?)
}

pub(super) fn assert_execution_basis(
    repository: &CampaignRepository,
    admitted: &AttemptAdmissionResult,
    proposal: crucible_campaign::ProposalId,
    cause: BranchRequestCause,
) -> Result<(), Box<dyn Error>> {
    let basis = repository.load_attempt_admission(admitted.admission)?;
    let AttemptAdmissionRole::ExecutionBasis {
        proposal: Some(actual_proposal),
        cause: actual_cause,
        admission_ordinal,
    } = basis.role()
    else {
        return Err("attempt admission is not a proposal-backed execution basis".into());
    };
    assert_eq!(actual_proposal, proposal);
    assert_eq!(actual_cause, cause);
    assert!(admission_ordinal.value() > 0);

    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct ExpectedExecutionBasis {
    pub(super) attempt: crucible_campaign::AttemptId,
    pub(super) admission: crucible_campaign::AttemptAdmissionId,
    pub(super) proposal: crucible_campaign::ProposalId,
    pub(super) request: crucible_campaign::BranchRequestId,
    pub(super) cause: BranchRequestCause,
}

pub(super) fn assert_explained_basis(
    repository: &CampaignRepository,
    campaign: &str,
    snapshot: crucible_campaign::CampaignSnapshotId,
    expected: ExpectedExecutionBasis,
) -> Result<(), Box<dyn Error>> {
    let client = CampaignClient::new(RepositoryCampaignService::new(
        repository,
        AllowCampaignQueries,
    ));
    let query = ExplainCampaignAttemptRequest::new(
        CampaignPrincipal::new("gate:branch-point-model")?,
        CampaignName::new(campaign)?,
        snapshot,
        expected.attempt,
    )?;
    let response = client.explain_campaign_attempt(&query)?;
    let explained_admission = response.admission();
    assert_eq!(explained_admission.id()?, expected.admission);
    let AttemptAdmissionRole::ExecutionBasis {
        proposal: Some(explained_proposal_id),
        cause: explained_cause,
        ..
    } = explained_admission.role()
    else {
        return Err("explained admission is not a proposal-backed execution basis".into());
    };
    assert_eq!(explained_proposal_id, expected.proposal);
    assert_eq!(explained_cause, expected.cause);

    let explained_proposal = response
        .proposal()
        .ok_or("explained branch attempt has no proposal")?;
    assert_eq!(explained_proposal.id()?, expected.proposal);
    assert_eq!(explained_proposal.request(), expected.request);
    assert!(response.observation().is_some());

    Ok(())
}

pub(super) fn assert_additional_cause(
    repository: &CampaignRepository,
    campaign: &str,
    snapshot: crucible_campaign::CampaignSnapshotId,
    admission: crucible_campaign::AttemptAdmissionId,
    proposal: crucible_campaign::ProposalId,
    request: &BranchRequest,
) -> Result<(), Box<dyn Error>> {
    let retained_admission = repository.load_attempt_admission(admission)?;
    assert_eq!(
        retained_admission.role(),
        AttemptAdmissionRole::AdditionalCause { proposal }
    );
    let retained_proposal = repository.load_proposal(proposal)?;
    assert_eq!(retained_proposal.request(), request.id()?);

    let client = CampaignClient::new(RepositoryCampaignService::new(
        repository,
        AllowCampaignQueries,
    ));
    let query = GetCampaignFrontierObjectRequest::new(
        CampaignPrincipal::new("gate:branch-point-model")?,
        CampaignName::new(campaign)?,
        snapshot,
        request.id()?,
    )?;
    assert_eq!(
        client.get_campaign_frontier_object(&query)?.object(),
        request
    );

    Ok(())
}

pub(super) struct CampaignHead<'a> {
    pub(super) name: &'a str,
    pub(super) snapshot: crucible_campaign::CampaignSnapshotId,
}

pub(super) fn publish_observation(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    head: CampaignHead<'_>,
    request: &BranchRequest,
    path: &BranchPath,
    attempt: crucible_campaign::AttemptId,
    label: &str,
) -> Result<crucible_campaign::CampaignSnapshotId, Box<dyn Error>> {
    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "gate.branch-point.child",
        label.as_bytes(),
    ));
    let child_content = repository.publish_configuration_artifact(
        lineage.scenario(),
        lineage.scenario_content(),
        child,
        1,
        label.as_bytes().to_vec(),
    )?;
    let measurements = repository.publish_measurement_set(&MeasurementSet::from_evaluation(
        CampaignHash::derive("test.measurement", b"branch-point.measurement-definitions"),
        1,
        CampaignHash::derive("test.measurement", b"branch-point.measurement-evaluation"),
        b"branch-point-measurements".to_vec(),
        BTreeSet::new(),
    )?)?;
    let properties =
        repository.publish_property_verdict_set(&PropertyVerdictSet::new(BTreeMap::new())?)?;
    let coverage = repository
        .publish_coverage_projection(&CoverageProjection::new(BTreeSet::new(), BTreeSet::new())?)?;
    let observation = Observation::new(
        attempt,
        Observation::outcome(
            child,
            child_content,
            path.id()?,
            StopOutcome::Reached(request.stop().clone()),
            measurements,
            properties,
            coverage,
        ),
        BTreeSet::from([request.opportunity()]),
    )?;

    Ok(repository
        .publish_observation(head.name, head.snapshot, &observation)?
        .new_snapshot)
}

pub(super) fn command_id(label: &str) -> CampaignCommandId {
    CampaignCommandId::from_hash(CampaignHash::derive(
        "gate.branch-point.command",
        label.as_bytes(),
    ))
}
