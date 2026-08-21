//! Authenticated choice-legality and frontier-cause explanations.

use super::object::{
    campaign_branch_cause_label, campaign_choice_domain_kind, campaign_choice_source_label,
    campaign_choice_value_label, campaign_stop_condition_label,
};
use super::*;

use crucible_campaign::{
    CampaignChoiceObject, CampaignChoiceObjectKind, ChoiceOpportunity,
    GetCampaignChoiceObjectRequest, GetCampaignFrontierObjectRequest, SelectableDeclaration,
};

const CAMPAIGN_EXPLANATION_REPORT_SCHEMA: &str = "crucible.cli.campaign-explanation.v1";

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
