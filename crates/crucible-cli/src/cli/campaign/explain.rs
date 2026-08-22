//! Authenticated choice-legality and frontier-cause explanations.

use super::object::{
    campaign_branch_cause_label, campaign_choice_domain_kind, campaign_choice_source_label,
    campaign_choice_value_label, campaign_stop_condition_label,
};
use super::*;

use crucible_campaign::{
    AttemptAdmissionRole, AttemptId, AttemptStart, CampaignChoiceObject, CampaignChoiceObjectKind,
    CampaignFindingObject, CampaignFindingObjectKind, ChoiceOpportunity,
    ExplainCampaignAttemptRequest, Finding, FindingId, FindingTarget,
    GetCampaignChoiceObjectRequest, GetCampaignFindingObjectRequest,
    GetCampaignFrontierObjectRequest, Observation, ReproductionArtifact, SelectableDeclaration,
    SelectionOrigin, StopOutcome,
};

const CAMPAIGN_EXPLANATION_REPORT_SCHEMA: &str = "crucible.cli.campaign-explanation.v1";
const CAMPAIGN_FINDING_EXPLANATION_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-finding-explanation.v1";
const CAMPAIGN_ATTEMPT_EXPLANATION_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-attempt-explanation.v1";

#[derive(Debug, Serialize)]
pub(super) struct CampaignExplanationReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    opportunity: CampaignExplainedOpportunity,
    legality: CampaignChoiceLegality,
    cause: CampaignFrontierCause,
}

#[derive(Debug, Serialize)]
struct CampaignExplainedOpportunity {
    id: String,
    semantic_id: String,
    scenario: String,
    class: String,
    source: String,
    scheduler_coordinate: String,
    producer_coordinate: String,
    instance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_prior: Option<String>,
}

#[derive(Debug, Serialize)]
struct CampaignChoiceLegality {
    declaration: String,
    name: String,
    domain: String,
    domain_semantics: String,
    domain_kind: &'static str,
    cardinality: String,
    default: String,
    required: bool,
    semantic_tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CampaignFrontierCause {
    request: String,
    branch_point: String,
    parent: String,
    source: &'static str,
    finite_values: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generator: Option<String>,
    cause: String,
    maximum_proposals: u64,
    maximum_attempts: u64,
    stop: String,
    continuation_state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_visits: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_visits: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(super) struct CampaignFindingExplanationReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    finding: CampaignExplainedFinding,
    observation: CampaignExplainedObservation,
    reproduction: CampaignExplainedReproduction,
}

#[derive(Debug, Serialize)]
struct CampaignExplainedFinding {
    id: String,
    cluster: String,
    kind: &'static str,
    fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    property: Option<String>,
    failure_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    causal_evidence: Vec<String>,
    first_seen_snapshot: String,
    occurrence_count: u32,
    latest_occurrence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimized_reproduction: Option<String>,
    exact_pins: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CampaignExplainedObservation {
    id: String,
    attempt: String,
    path: String,
    child: String,
    child_artifact: String,
    stop: String,
    measurements: String,
    properties: String,
    coverage: String,
    discovered_choices: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CampaignExplainedReproduction {
    id: String,
    scenario: String,
    scenario_artifact: String,
    configuration: String,
    configuration_artifact: String,
    finding_fingerprint: String,
    payload_schema: u32,
    payload_bytes: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct CampaignAttemptExplanationReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    attempt: CampaignExplainedAttempt,
    admission: CampaignExplainedAttemptAdmission,
    path: CampaignExplainedAttemptPath,
    #[serde(skip_serializing_if = "Option::is_none")]
    selection: Option<CampaignExplainedSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proposal: Option<CampaignExplainedProposal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observation: Option<CampaignExplainedObservation>,
}

#[derive(Debug, Serialize)]
struct CampaignExplainedAttempt {
    id: String,
    start: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    configuration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edge: Option<String>,
    path: String,
    stop: String,
}

#[derive(Debug, Serialize)]
struct CampaignExplainedAttemptAdmission {
    cause: String,
    admission_ordinal: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    proposal: Option<String>,
}

#[derive(Debug, Serialize)]
struct CampaignExplainedAttemptPath {
    id: String,
    edges: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    segments: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct CampaignExplainedSelection {
    id: String,
    opportunity: String,
    domain: String,
    value: String,
    origin: String,
}

#[derive(Debug, Serialize)]
struct CampaignExplainedProposal {
    id: String,
    branch_point: String,
    request: String,
    domain: String,
    value: String,
    policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    planner_invocation: Option<String>,
    ordinal: u64,
    guidance_basis: String,
}

pub(super) fn validate_campaign_explain_command(command: &CampaignCommand) -> Result<(), CliError> {
    let CampaignCommand::Explain(args) = command else {
        return Err(backend_error(
            "non-explain campaign command reached explanation validation",
        ));
    };
    campaign_name(&args.name)?;
    CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign explanation snapshot: {error}")))?;
    ChoiceOpportunityId::parse(&args.opportunity).map_err(|error| {
        usage_error(format!("invalid campaign explanation opportunity: {error}"))
    })?;
    BranchRequestId::parse(&args.request)
        .map_err(|error| usage_error(format!("invalid campaign explanation request: {error}")))?;
    Ok(())
}

pub(super) fn validate_campaign_finding_explain_command(
    command: &CampaignCommand,
) -> Result<(), CliError> {
    let CampaignCommand::ExplainFinding(args) = command else {
        return Err(backend_error(
            "non-finding-explain command reached finding explanation validation",
        ));
    };
    campaign_name(&args.name)?;
    CampaignSnapshotId::parse(&args.snapshot).map_err(|error| {
        usage_error(format!(
            "invalid campaign finding explanation snapshot: {error}"
        ))
    })?;
    FindingId::parse(&args.finding).map_err(|error| {
        usage_error(format!(
            "invalid campaign finding explanation identity: {error}"
        ))
    })?;
    Ok(())
}

pub(super) fn validate_campaign_attempt_explain_command(
    command: &CampaignCommand,
) -> Result<(), CliError> {
    let CampaignCommand::ExplainAttempt(args) = command else {
        return Err(backend_error(
            "non-attempt-explain command reached attempt explanation validation",
        ));
    };
    campaign_name(&args.name)?;
    CampaignSnapshotId::parse(&args.snapshot).map_err(|error| {
        usage_error(format!(
            "invalid campaign attempt explanation snapshot: {error}"
        ))
    })?;
    AttemptId::parse(&args.attempt).map_err(|error| {
        usage_error(format!(
            "invalid campaign attempt explanation identity: {error}"
        ))
    })?;
    Ok(())
}

pub(super) fn query_campaign_explanation<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignExplanationReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let CampaignCommand::Explain(args) = command else {
        return Err(backend_error(
            "non-explain campaign command reached explanation query",
        ));
    };
    let campaign = campaign_name(&args.name)?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign explanation snapshot: {error}")))?;
    let opportunity = ChoiceOpportunityId::parse(&args.opportunity).map_err(|error| {
        usage_error(format!("invalid campaign explanation opportunity: {error}"))
    })?;
    let request_id = BranchRequestId::parse(&args.request)
        .map_err(|error| usage_error(format!("invalid campaign explanation request: {error}")))?;

    let choice_request = GetCampaignChoiceObjectRequest::new(
        principal.clone(),
        campaign.clone(),
        snapshot,
        opportunity,
        CampaignChoiceObjectKind::Declaration,
    )
    .map_err(|error| {
        usage_error(format!(
            "invalid campaign explanation choice query: {error}"
        ))
    })?;
    let choice_response = client
        .get_campaign_choice_object(&choice_request)
        .map_err(|error| {
            backend_error(format!("campaign explanation choice query failed: {error}"))
        })?;
    let declaration = match choice_response.object() {
        CampaignChoiceObject::Declaration(declaration) => declaration,
        CampaignChoiceObject::Domain(_) => {
            return Err(backend_error(
                "campaign explanation choice response carried a domain",
            ));
        }
    };

    let frontier_request =
        GetCampaignFrontierObjectRequest::new(principal, campaign.clone(), snapshot, request_id)
            .map_err(|error| {
                usage_error(format!(
                    "invalid campaign explanation frontier query: {error}"
                ))
            })?;
    let frontier_response = client
        .get_campaign_frontier_object(&frontier_request)
        .map_err(|error| {
            backend_error(format!(
                "campaign explanation frontier query failed: {error}"
            ))
        })?;
    let branch = frontier_response.object();
    let opportunity_body = choice_response.opportunity();
    let declaration_domain = declaration.domain().id().map_err(|error| {
        backend_error(format!(
            "authenticated explanation declaration domain is invalid: {error}"
        ))
    })?;
    if branch.opportunity() != opportunity
        || branch.domain() != opportunity_body.domain()
        || declaration_domain != opportunity_body.domain()
    {
        return Err(backend_error(
            "campaign explanation records do not share one opportunity and domain",
        ));
    }

    let projection = frontier_response.projection();
    let (continuation_state, completed_visits, required_visits) =
        continuation_state_report(projection.state());
    let finite_values = branch
        .source()
        .finite_values()
        .into_iter()
        .flatten()
        .map(campaign_choice_value_label)
        .collect();
    let source = if branch.source().finite_values().is_some() {
        "finite"
    } else {
        "generated"
    };

    Ok(CampaignExplanationReport {
        schema: CAMPAIGN_EXPLANATION_REPORT_SCHEMA,
        operation: "choice-frontier",
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        opportunity: explained_opportunity(opportunity_body, opportunity),
        legality: explained_legality(declaration)?,
        cause: CampaignFrontierCause {
            request: request_id.to_string(),
            branch_point: branch.branch_point().to_string(),
            parent: branch.parent().to_string(),
            source,
            finite_values,
            generator: branch.source().generator().map(|value| value.to_string()),
            cause: campaign_branch_cause_label(branch.cause()),
            maximum_proposals: branch.budget().maximum_proposals(),
            maximum_attempts: branch.budget().maximum_attempts(),
            stop: campaign_stop_condition_label(branch.stop()),
            continuation_state,
            completed_visits,
            required_visits,
        },
    })
}

pub(super) fn query_campaign_finding_explanation<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignFindingExplanationReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let CampaignCommand::ExplainFinding(args) = command else {
        return Err(backend_error(
            "non-finding-explain command reached finding explanation query",
        ));
    };
    let campaign = campaign_name(&args.name)?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot).map_err(|error| {
        usage_error(format!(
            "invalid campaign finding explanation snapshot: {error}"
        ))
    })?;
    let finding_id = FindingId::parse(&args.finding).map_err(|error| {
        usage_error(format!(
            "invalid campaign finding explanation identity: {error}"
        ))
    })?;

    let observation_request = GetCampaignFindingObjectRequest::new(
        principal.clone(),
        campaign.clone(),
        snapshot,
        finding_id,
        CampaignFindingObjectKind::Observation,
    )
    .map_err(|error| {
        usage_error(format!(
            "invalid campaign finding observation query: {error}"
        ))
    })?;
    let observation_response = client
        .get_campaign_finding_object(&observation_request)
        .map_err(|error| {
            backend_error(format!(
                "campaign finding observation query failed: {error}"
            ))
        })?;
    let observation = match observation_response.object() {
        CampaignFindingObject::Observation(value) => value,
        CampaignFindingObject::LatestOccurrence(_)
        | CampaignFindingObject::Reproduction(_)
        | CampaignFindingObject::MinimizedReproduction(_) => {
            return Err(backend_error(
                "campaign finding observation response carried another dependency kind",
            ));
        }
    };

    let reproduction_request = GetCampaignFindingObjectRequest::new(
        principal,
        campaign.clone(),
        snapshot,
        finding_id,
        CampaignFindingObjectKind::Reproduction,
    )
    .map_err(|error| {
        usage_error(format!(
            "invalid campaign finding reproduction query: {error}"
        ))
    })?;
    let reproduction_response = client
        .get_campaign_finding_object(&reproduction_request)
        .map_err(|error| {
            backend_error(format!(
                "campaign finding reproduction query failed: {error}"
            ))
        })?;
    let reproduction = match reproduction_response.object() {
        CampaignFindingObject::Reproduction(value) => value,
        CampaignFindingObject::Observation(_)
        | CampaignFindingObject::LatestOccurrence(_)
        | CampaignFindingObject::MinimizedReproduction(_) => {
            return Err(backend_error(
                "campaign finding reproduction response carried another dependency kind",
            ));
        }
    };
    if observation_response.finding() != reproduction_response.finding()
        || reproduction.configuration_artifact() != observation.child_content()
    {
        return Err(backend_error(
            "campaign finding explanation records do not share one finding and configuration",
        ));
    }

    Ok(CampaignFindingExplanationReport {
        schema: CAMPAIGN_FINDING_EXPLANATION_REPORT_SCHEMA,
        operation: "finding",
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        finding: explained_finding(observation_response.finding(), finding_id),
        observation: explained_observation(observation)?,
        reproduction: explained_reproduction(reproduction)?,
    })
}

pub(super) fn query_campaign_attempt_explanation<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignAttemptExplanationReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let CampaignCommand::ExplainAttempt(args) = command else {
        return Err(backend_error(
            "non-attempt-explain command reached attempt explanation query",
        ));
    };
    let campaign = campaign_name(&args.name)?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot).map_err(|error| {
        usage_error(format!(
            "invalid campaign attempt explanation snapshot: {error}"
        ))
    })?;
    let attempt_id = AttemptId::parse(&args.attempt).map_err(|error| {
        usage_error(format!(
            "invalid campaign attempt explanation identity: {error}"
        ))
    })?;
    let request =
        ExplainCampaignAttemptRequest::new(principal, campaign.clone(), snapshot, attempt_id)
            .map_err(|error| {
                usage_error(format!(
                    "invalid campaign attempt explanation query: {error}"
                ))
            })?;
    let response = client.explain_campaign_attempt(&request).map_err(|error| {
        backend_error(format!(
            "campaign attempt explanation query failed: {error}"
        ))
    })?;

    let attempt = response.attempt();
    let (start, configuration, parent, selection_id, edge) = match attempt.start() {
        AttemptStart::Discover { configuration } => (
            "discover",
            Some(configuration.to_string()),
            None,
            None,
            None,
        ),
        AttemptStart::Branch {
            edge,
            parent,
            selection,
        } => (
            "branch",
            None,
            Some(parent.to_string()),
            Some(selection.to_string()),
            Some(edge.to_string()),
        ),
    };
    let AttemptAdmissionRole::ExecutionBasis {
        proposal,
        cause,
        admission_ordinal,
    } = response.admission().role()
    else {
        return Err(backend_error(
            "attempt explanation carried a non-execution admission",
        ));
    };
    let path = response.path();
    let selection = response.selection().map(explained_selection).transpose()?;
    let proposal_body = response.proposal().map(explained_proposal).transpose()?;
    let observation = response
        .observation()
        .map(explained_observation)
        .transpose()?;

    Ok(CampaignAttemptExplanationReport {
        schema: CAMPAIGN_ATTEMPT_EXPLANATION_REPORT_SCHEMA,
        operation: "attempt",
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        attempt: CampaignExplainedAttempt {
            id: attempt_id.to_string(),
            start,
            configuration,
            parent,
            selection: selection_id,
            edge,
            path: attempt.path().to_string(),
            stop: campaign_stop_condition_label(attempt.stop()),
        },
        admission: CampaignExplainedAttemptAdmission {
            cause: campaign_branch_cause_label(cause),
            admission_ordinal: admission_ordinal.value(),
            proposal: proposal.map(|value| value.to_string()),
        },
        path: CampaignExplainedAttemptPath {
            id: attempt.path().to_string(),
            edges: path.edges().iter().map(ToString::to_string).collect(),
            segments: path.segments().map(|segments| {
                segments
                    .iter()
                    .map(|segment| format!("{}:{}", segment.branch_point(), segment.edge()))
                    .collect()
            }),
        },
        selection,
        proposal: proposal_body,
        observation,
    })
}

fn explained_selection(
    selection: &crucible_campaign::Selection,
) -> Result<CampaignExplainedSelection, CliError> {
    let id = selection.id().map_err(|error| {
        backend_error(format!(
            "authenticated attempt selection identity is invalid: {error}"
        ))
    })?;
    let origin = match selection.origin() {
        SelectionOrigin::Default => String::from("default"),
        SelectionOrigin::LockedReplay => String::from("locked-replay"),
        SelectionOrigin::ModelSample(evidence) => format!(
            "model-sample:{}:{}:{}",
            evidence.model(),
            evidence.stream(),
            evidence.draw()
        ),
        SelectionOrigin::CampaignBranch { branch_point, edge } => {
            format!("campaign-branch:{branch_point}:{edge}")
        }
    };
    Ok(CampaignExplainedSelection {
        id: id.to_string(),
        opportunity: selection.opportunity().to_string(),
        domain: selection.domain().to_string(),
        value: campaign_choice_value_label(selection.value()),
        origin,
    })
}

fn explained_proposal(
    proposal: &crucible_campaign::Proposal,
) -> Result<CampaignExplainedProposal, CliError> {
    let id = proposal.id().map_err(|error| {
        backend_error(format!(
            "authenticated attempt proposal identity is invalid: {error}"
        ))
    })?;
    Ok(CampaignExplainedProposal {
        id: id.to_string(),
        branch_point: proposal.branch_point().to_string(),
        request: proposal.request().to_string(),
        domain: proposal.domain().to_string(),
        value: campaign_choice_value_label(proposal.value()),
        policy: proposal.policy().to_string(),
        planner_invocation: proposal.planner_invocation().map(|value| value.to_string()),
        ordinal: proposal.ordinal(),
        guidance_basis: proposal.guidance_basis().to_string(),
    })
}

fn explained_finding(finding: &Finding, id: FindingId) -> CampaignExplainedFinding {
    CampaignExplainedFinding {
        id: id.to_string(),
        cluster: finding.signature().cluster_key().to_hex(),
        kind: finding_kind_label(finding.signature().kind()),
        fingerprint: finding.signature().fingerprint().to_hex(),
        property: finding.signature().property().map(str::to_owned),
        failure_class: finding.signature().failure_class().to_owned(),
        target: finding.signature().target().map(finding_target_label),
        causal_evidence: finding
            .signature()
            .causal_evidence()
            .iter()
            .map(ToString::to_string)
            .collect(),
        first_seen_snapshot: finding.first_seen_snapshot().to_string(),
        occurrence_count: finding.occurrence_count(),
        latest_occurrence: finding.latest_occurrence().to_string(),
        minimized_reproduction: finding.minimized().map(|value| value.to_string()),
        exact_pins: finding
            .exact_pins()
            .iter()
            .map(ToString::to_string)
            .collect(),
    }
}

fn explained_observation(
    observation: &Observation,
) -> Result<CampaignExplainedObservation, CliError> {
    let id = observation.id().map_err(|error| {
        backend_error(format!(
            "authenticated finding observation identity is invalid: {error}"
        ))
    })?;
    Ok(CampaignExplainedObservation {
        id: id.to_string(),
        attempt: observation.attempt().to_string(),
        path: observation.path().to_string(),
        child: observation.child().to_string(),
        child_artifact: observation.child_content().to_string(),
        stop: stop_outcome_label(observation.stop()),
        measurements: observation.measurements().to_string(),
        properties: observation.properties().to_string(),
        coverage: observation.coverage().to_string(),
        discovered_choices: observation
            .discovered_choices()
            .iter()
            .map(ToString::to_string)
            .collect(),
    })
}

fn explained_reproduction(
    reproduction: &ReproductionArtifact,
) -> Result<CampaignExplainedReproduction, CliError> {
    let id = reproduction.id().map_err(|error| {
        backend_error(format!(
            "authenticated finding reproduction identity is invalid: {error}"
        ))
    })?;
    Ok(CampaignExplainedReproduction {
        id: id.to_string(),
        scenario: reproduction.scenario().to_string(),
        scenario_artifact: reproduction.scenario_artifact().to_string(),
        configuration: reproduction.configuration().to_string(),
        configuration_artifact: reproduction.configuration_artifact().to_string(),
        finding_fingerprint: reproduction.finding_fingerprint().to_hex(),
        payload_schema: reproduction.payload_schema(),
        payload_bytes: reproduction.payload().len(),
    })
}

fn finding_target_label(target: FindingTarget) -> String {
    match target {
        FindingTarget::Configuration(value) => format!("configuration:{value}"),
        FindingTarget::ChoiceOpportunity(value) => format!("choice-opportunity:{value}"),
    }
}

fn stop_outcome_label(outcome: &StopOutcome) -> String {
    match outcome {
        StopOutcome::Reached(stop) => {
            format!("reached:{}", campaign_stop_condition_label(stop))
        }
        StopOutcome::TerminalSuccess => String::from("terminal-success"),
        StopOutcome::ModeledTimeout(name) => format!("modeled-timeout:{name}"),
        StopOutcome::GuestCrash(class) => format!("guest-crash:{class}"),
        StopOutcome::AssertionFailure(property) => format!("assertion-failure:{property}"),
    }
}

fn explained_opportunity(
    opportunity: &ChoiceOpportunity,
    id: ChoiceOpportunityId,
) -> CampaignExplainedOpportunity {
    let coordinate = opportunity.coordinate();
    CampaignExplainedOpportunity {
        id: id.to_string(),
        semantic_id: opportunity.semantic_id().to_string(),
        scenario: opportunity.scenario().to_string(),
        class: opportunity.class().to_string(),
        source: campaign_choice_source_label(opportunity.source()),
        scheduler_coordinate: coordinate.scheduler.to_hex(),
        producer_coordinate: coordinate.producer.to_hex(),
        instance: opportunity.instance().to_owned(),
        model_prior: opportunity.model_prior().map(|value| value.to_string()),
    }
}

fn explained_legality(
    declaration: &SelectableDeclaration,
) -> Result<CampaignChoiceLegality, CliError> {
    let declaration_id = declaration.id().map_err(|error| {
        backend_error(format!(
            "authenticated explanation declaration is invalid: {error}"
        ))
    })?;
    let domain = declaration.domain();
    let domain_id = domain.id().map_err(|error| {
        backend_error(format!(
            "authenticated explanation domain is invalid: {error}"
        ))
    })?;
    Ok(CampaignChoiceLegality {
        declaration: declaration_id.to_string(),
        name: declaration.name().to_owned(),
        domain: domain_id.to_string(),
        domain_semantics: domain.semantic_id().to_string(),
        domain_kind: campaign_choice_domain_kind(domain),
        cardinality: domain.cardinality().to_string(),
        default: campaign_choice_value_label(declaration.default()),
        required: declaration.required(),
        semantic_tags: declaration.semantic_tags().iter().cloned().collect(),
    })
}

pub(super) fn render_campaign_explanation(
    report: &CampaignExplanationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(explanation_fields(report)?
            .into_iter()
            .map(|(field, value)| format!("{field:<32} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in explanation_fields(report)? {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

pub(super) fn render_campaign_finding_explanation(
    report: &CampaignFindingExplanationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(finding_explanation_fields(report)?
            .into_iter()
            .map(|(field, value)| format!("{field:<32} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in finding_explanation_fields(report)? {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

pub(super) fn render_campaign_attempt_explanation(
    report: &CampaignAttemptExplanationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(attempt_explanation_fields(report)?
            .into_iter()
            .map(|(field, value)| format!("{field:<32} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in attempt_explanation_fields(report)? {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

fn attempt_explanation_fields(
    report: &CampaignAttemptExplanationReport,
) -> Result<Vec<(String, String)>, CliError> {
    let value = serde_json::to_value(report).map_err(|error| {
        backend_error(format!(
            "campaign attempt explanation encoding failed: {error}"
        ))
    })?;
    let mut fields = Vec::new();
    flatten_explanation_value(None, &value, &mut fields)?;
    Ok(fields)
}

fn finding_explanation_fields(
    report: &CampaignFindingExplanationReport,
) -> Result<Vec<(String, String)>, CliError> {
    let value = serde_json::to_value(report).map_err(|error| {
        backend_error(format!(
            "campaign finding explanation encoding failed: {error}"
        ))
    })?;
    let mut fields = Vec::new();
    flatten_explanation_value(None, &value, &mut fields)?;
    Ok(fields)
}

fn explanation_fields(
    report: &CampaignExplanationReport,
) -> Result<Vec<(String, String)>, CliError> {
    let value = serde_json::to_value(report)
        .map_err(|error| backend_error(format!("campaign explanation encoding failed: {error}")))?;
    let mut fields = Vec::new();
    flatten_explanation_value(None, &value, &mut fields)?;
    Ok(fields)
}

fn flatten_explanation_value(
    prefix: Option<&str>,
    value: &serde_json::Value,
    fields: &mut Vec<(String, String)>,
) -> Result<(), CliError> {
    if let serde_json::Value::Object(object) = value {
        for (key, value) in object {
            let field = prefix.map_or_else(|| key.clone(), |prefix| format!("{prefix}.{key}"));
            flatten_explanation_value(Some(&field), value, fields)?;
        }
        return Ok(());
    }
    let field = prefix
        .ok_or_else(|| backend_error("campaign explanation report has no field name"))?
        .to_owned();
    let rendered = match value {
        serde_json::Value::Null => String::from("-"),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Array(_) => serde_json::to_string(value).map_err(|error| {
            backend_error(format!(
                "campaign explanation array encoding failed: {error}"
            ))
        })?,
        serde_json::Value::Object(_) => {
            return Err(backend_error(
                "campaign explanation retained an unflattened object",
            ));
        }
    };
    fields.push((field, rendered));
    Ok(())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures intentionally abort on malformed report data.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn explanation_reports_render_exact_legality_and_cause() {
        let report = CampaignExplanationReport {
            schema: CAMPAIGN_EXPLANATION_REPORT_SCHEMA,
            operation: "choice-frontier",
            campaign: String::from("example"),
            snapshot: String::from("snapshot"),
            opportunity: CampaignExplainedOpportunity {
                id: String::from("opportunity"),
                semantic_id: String::from("semantic-opportunity"),
                scenario: String::from("scenario"),
                class: String::from("class"),
                source: String::from("workload:product"),
                scheduler_coordinate: String::from("scheduler"),
                producer_coordinate: String::from("producer"),
                instance: String::from("instance"),
                model_prior: None,
            },
            legality: CampaignChoiceLegality {
                declaration: String::from("declaration"),
                name: String::from("product.retry"),
                domain: String::from("domain"),
                domain_semantics: String::from("domain-semantics"),
                domain_kind: "boolean",
                cardinality: String::from("2"),
                default: String::from("false"),
                required: true,
                semantic_tags: vec![String::from("network")],
            },
            cause: CampaignFrontierCause {
                request: String::from("request"),
                branch_point: String::from("branch-point"),
                parent: String::from("parent"),
                source: "finite",
                finite_values: vec![String::from("true")],
                generator: None,
                cause: String::from("operator:command"),
                maximum_proposals: 1,
                maximum_attempts: 1,
                stop: String::from("next-choice"),
                continuation_state: "ready",
                completed_visits: None,
                required_visits: None,
            },
        };

        let json =
            render_campaign_explanation(&report, OutputFormat::Json).expect("JSON explanation");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_EXPLANATION_REPORT_SCHEMA);
        assert_eq!(decoded["legality"]["domain_kind"], "boolean");
        assert_eq!(decoded["cause"]["finite_values"][0], "true");

        let table =
            render_campaign_explanation(&report, OutputFormat::Table).expect("table explanation");
        assert!(table.contains("legality.domain_kind"));
        let markdown = render_campaign_explanation(&report, OutputFormat::Markdown)
            .expect("Markdown explanation");
        assert!(markdown.contains("| cause.cause | operator:command |"));
    }
}
