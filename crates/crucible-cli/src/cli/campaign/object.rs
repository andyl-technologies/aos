//! Authenticated rich campaign-object inspection and rendering.

use super::*;

use crucible_campaign::{
    CampaignChoiceObject, CampaignChoiceObjectKind, ChoiceDomain, ChoiceOpportunity, ChoiceSource,
    ConfigurationArtifact, GetCampaignChoiceObjectRequest, GetCampaignFrontierObjectRequest,
    GetCampaignGraphObjectRequest, SelectableDeclaration,
};

const CAMPAIGN_OBJECT_REPORT_SCHEMA: &str = "crucible.cli.campaign-object.v1";

#[derive(Serialize)]
pub(super) struct CampaignObjectReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    object: CampaignObjectView,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CampaignObjectView {
    #[serde(rename = "configuration")]
    ConfigArtifact {
        key: String,
        object: String,
        scenario: String,
        scenario_artifact: String,
        configuration: String,
        payload_schema: u32,
        payload_bytes: usize,
    },
    Opportunity {
        key: String,
        object: String,
        #[serde(flatten)]
        opportunity: CampaignOpportunityView,
    },
    Declaration {
        opportunity: CampaignOpportunityView,
        declaration: String,
        name: String,
        source: String,
        domain: String,
        domain_semantics: String,
        domain_kind: &'static str,
        domain_cardinality: String,
        default: String,
        semantic_tags: Vec<String>,
        required: bool,
    },
    Domain {
        opportunity: CampaignOpportunityView,
        domain: String,
        domain_semantics: String,
        domain_kind: &'static str,
        cardinality: String,
    },
    Frontier {
        request: String,
        branch_point: String,
        parent: String,
        opportunity: String,
        domain: String,
        source: &'static str,
        finite_values: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        generator: Option<String>,
        cause: String,
        maximum_proposals: u64,
        maximum_attempts: u64,
        stop: String,
        state: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        completed_visits: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        required_visits: Option<u64>,
    },
}

#[derive(Serialize)]
struct CampaignOpportunityView {
    opportunity: String,
    semantic_opportunity: String,
    scenario: String,
    class: String,
    source: String,
    declaration: String,
    declaration_semantics: String,
    domain: String,
    domain_semantics: String,
    scheduler_coordinate: String,
    producer_coordinate: String,
    instance: String,
    default: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_prior: Option<String>,
}

pub(super) fn validate_campaign_object_basis(name: &str, snapshot: &str) -> Result<(), CliError> {
    campaign_name(name)?;
    CampaignSnapshotId::parse(snapshot)
        .map_err(|error| usage_error(format!("invalid campaign object snapshot: {error}")))?;
    Ok(())
}

pub(super) fn query_campaign_object<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignObjectReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    match command {
        CampaignCommand::GraphObject(args) => {
            let (campaign, snapshot) = campaign_object_basis(&args.name, &args.snapshot)?;
            let key = CampaignHash::parse(&args.key)
                .map_err(|error| usage_error(format!("invalid campaign graph key: {error}")))?;
            let request =
                GetCampaignGraphObjectRequest::new(principal, campaign.clone(), snapshot, key)
                    .map_err(|error| {
                        usage_error(format!("invalid campaign graph object query: {error}"))
                    })?;
            let response = client
                .get_campaign_graph_object(&request)
                .map_err(|error| {
                    backend_error(format!("campaign graph object query failed: {error}"))
                })?;
            let envelope = response.object();
            let object = match envelope.record_kind() {
                crucible_campaign::CampaignRecordKind::ConfigurationArtifact => {
                    let artifact = ConfigurationArtifact::from_canonical_bytes(envelope.body())
                        .map_err(|error| {
                            backend_error(format!(
                                "authenticated configuration artifact is invalid: {error}"
                            ))
                        })?;
                    CampaignObjectView::ConfigArtifact {
                        key: key.to_hex(),
                        object: envelope.content_id().to_string(),
                        scenario: artifact.scenario().to_string(),
                        scenario_artifact: artifact.scenario_artifact().to_string(),
                        configuration: artifact.configuration().to_string(),
                        payload_schema: artifact.payload_schema(),
                        payload_bytes: artifact.payload().len(),
                    }
                }
                crucible_campaign::CampaignRecordKind::ChoiceOpportunity => {
                    let opportunity = ChoiceOpportunity::from_canonical_bytes(envelope.body())
                        .map_err(|error| {
                            backend_error(format!(
                                "authenticated choice opportunity is invalid: {error}"
                            ))
                        })?;
                    CampaignObjectView::Opportunity {
                        key: key.to_hex(),
                        object: envelope.content_id().to_string(),
                        opportunity: campaign_opportunity_view(&opportunity)?,
                    }
                }
                _ => {
                    return Err(backend_error(
                        "campaign graph object response carried an unsupported record kind",
                    ));
                }
            };
            Ok(CampaignObjectReport {
                schema: CAMPAIGN_OBJECT_REPORT_SCHEMA,
                operation: "graph-object",
                campaign: campaign.as_str().to_owned(),
                snapshot: snapshot.to_string(),
                object,
            })
        }
        CampaignCommand::ChoiceObject(args) => {
            let (campaign, snapshot) = campaign_object_basis(&args.name, &args.snapshot)?;
            let opportunity = ChoiceOpportunityId::parse(&args.opportunity).map_err(|error| {
                usage_error(format!("invalid campaign choice opportunity: {error}"))
            })?;
            let kind = match args.kind {
                CampaignChoiceObjectKindArg::Declaration => CampaignChoiceObjectKind::Declaration,
                CampaignChoiceObjectKindArg::Domain => CampaignChoiceObjectKind::Domain,
            };
            let request = GetCampaignChoiceObjectRequest::new(
                principal,
                campaign.clone(),
                snapshot,
                opportunity,
                kind,
            )
            .map_err(|error| {
                usage_error(format!("invalid campaign choice object query: {error}"))
            })?;
            let response = client
                .get_campaign_choice_object(&request)
                .map_err(|error| {
                    backend_error(format!("campaign choice object query failed: {error}"))
                })?;
            let opportunity = campaign_opportunity_view(response.opportunity())?;
            let object = match response.object() {
                CampaignChoiceObject::Declaration(declaration) => {
                    campaign_declaration_view(opportunity, declaration)?
                }
                CampaignChoiceObject::Domain(domain) => campaign_domain_view(opportunity, domain)?,
            };
            Ok(CampaignObjectReport {
                schema: CAMPAIGN_OBJECT_REPORT_SCHEMA,
                operation: "choice-object",
                campaign: campaign.as_str().to_owned(),
                snapshot: snapshot.to_string(),
                object,
            })
        }
        CampaignCommand::FrontierObject(args) => {
            let (campaign, snapshot) = campaign_object_basis(&args.name, &args.snapshot)?;
            let request_id = BranchRequestId::parse(&args.request).map_err(|error| {
                usage_error(format!("invalid campaign frontier request: {error}"))
            })?;
            let request = GetCampaignFrontierObjectRequest::new(
                principal,
                campaign.clone(),
                snapshot,
                request_id,
            )
            .map_err(|error| {
                usage_error(format!("invalid campaign frontier object query: {error}"))
            })?;
            let response = client
                .get_campaign_frontier_object(&request)
                .map_err(|error| {
                    backend_error(format!("campaign frontier object query failed: {error}"))
                })?;
            let branch = response.object();
            let projection = response.projection();
            let (state, completed_visits, required_visits) =
                continuation_state_report(projection.state());
            let finite_values = branch
                .source()
                .finite_values()
                .into_iter()
                .flatten()
                .map(campaign_choice_value_label)
                .collect::<Vec<_>>();
            let source = if branch.source().finite_values().is_some() {
                "finite"
            } else {
                "generated"
            };
            let object = CampaignObjectView::Frontier {
                request: request_id.to_string(),
                branch_point: branch.branch_point().to_string(),
                parent: branch.parent().to_string(),
                opportunity: branch.opportunity().to_string(),
                domain: branch.domain().to_string(),
                source,
                finite_values,
                generator: branch.source().generator().map(|value| value.to_string()),
                cause: campaign_branch_cause_label(branch.cause()),
                maximum_proposals: branch.budget().maximum_proposals(),
                maximum_attempts: branch.budget().maximum_attempts(),
                stop: campaign_stop_condition_label(branch.stop()),
                state,
                completed_visits,
                required_visits,
            };
            Ok(CampaignObjectReport {
                schema: CAMPAIGN_OBJECT_REPORT_SCHEMA,
                operation: "frontier-object",
                campaign: campaign.as_str().to_owned(),
                snapshot: snapshot.to_string(),
                object,
            })
        }
        _ => Err(backend_error(
            "non-object campaign command reached the object query path",
        )),
    }
}

fn campaign_object_basis(
    name: &str,
    snapshot: &str,
) -> Result<(CampaignName, CampaignSnapshotId), CliError> {
    let campaign = campaign_name(name)?;
    let snapshot = CampaignSnapshotId::parse(snapshot)
        .map_err(|error| usage_error(format!("invalid campaign object snapshot: {error}")))?;
    Ok((campaign, snapshot))
}

fn campaign_opportunity_view(
    opportunity: &ChoiceOpportunity,
) -> Result<CampaignOpportunityView, CliError> {
    let coordinate = opportunity.coordinate();
    let id = opportunity.id().map_err(|error| {
        backend_error(format!(
            "authenticated choice opportunity identity is invalid: {error}"
        ))
    })?;
    Ok(CampaignOpportunityView {
        opportunity: id.to_string(),
        semantic_opportunity: opportunity.semantic_id().to_string(),
        scenario: opportunity.scenario().to_string(),
        class: opportunity.class().to_string(),
        source: campaign_choice_source_label(opportunity.source()),
        declaration: opportunity.declaration().to_string(),
        declaration_semantics: opportunity.declaration_semantics().to_string(),
        domain: opportunity.domain().to_string(),
        domain_semantics: opportunity.domain_semantics().to_string(),
        scheduler_coordinate: coordinate.scheduler.to_hex(),
        producer_coordinate: coordinate.producer.to_hex(),
        instance: opportunity.instance().to_owned(),
        default: campaign_choice_value_label(opportunity.default()),
        model_prior: opportunity.model_prior().map(|value| value.to_string()),
    })
}

fn campaign_declaration_view(
    opportunity: CampaignOpportunityView,
    declaration: &SelectableDeclaration,
) -> Result<CampaignObjectView, CliError> {
    let declaration_id = declaration.id().map_err(|error| {
        backend_error(format!(
            "authenticated selectable declaration identity is invalid: {error}"
        ))
    })?;
    let domain = declaration.domain();
    let domain_id = domain.id().map_err(|error| {
        backend_error(format!(
            "authenticated selectable declaration domain is invalid: {error}"
        ))
    })?;
    Ok(CampaignObjectView::Declaration {
        opportunity,
        declaration: declaration_id.to_string(),
        name: declaration.name().to_owned(),
        source: campaign_choice_source_label(declaration.source()),
        domain: domain_id.to_string(),
        domain_semantics: domain.semantic_id().to_string(),
        domain_kind: campaign_choice_domain_kind(domain),
        domain_cardinality: domain.cardinality().to_string(),
        default: campaign_choice_value_label(declaration.default()),
        semantic_tags: declaration.semantic_tags().iter().cloned().collect(),
        required: declaration.required(),
    })
}

fn campaign_domain_view(
    opportunity: CampaignOpportunityView,
    domain: &ChoiceDomain,
) -> Result<CampaignObjectView, CliError> {
    let domain_id = domain.id().map_err(|error| {
        backend_error(format!(
            "authenticated choice domain identity is invalid: {error}"
        ))
    })?;
    Ok(CampaignObjectView::Domain {
        opportunity,
        domain: domain_id.to_string(),
        domain_semantics: domain.semantic_id().to_string(),
        domain_kind: campaign_choice_domain_kind(domain),
        cardinality: domain.cardinality().to_string(),
    })
}

pub(super) const fn campaign_choice_domain_kind(domain: &ChoiceDomain) -> &'static str {
    match domain {
        ChoiceDomain::Boolean(_) => "boolean",
        ChoiceDomain::Discrete(_) => "discrete",
        ChoiceDomain::Integer(_) => "integer",
    }
}

pub(super) fn campaign_choice_source_label(source: &ChoiceSource) -> String {
    match source {
        ChoiceSource::Environment { adapter, target } => {
            format!("environment:{adapter}:{}", target.to_hex())
        }
        ChoiceSource::Guest {
            node,
            protocol_version,
        } => format!("guest:{node}:v{protocol_version}"),
        ChoiceSource::Scheduler { producer } => format!("scheduler:{producer}"),
        ChoiceSource::Workload { producer } => format!("workload:{producer}"),
    }
}

pub(super) fn campaign_choice_value_label(value: &ChoiceValue) -> String {
    match value {
        ChoiceValue::Boolean(value) => value.to_string(),
        ChoiceValue::Discrete(value) => format!("discrete:{value}"),
        ChoiceValue::Integer(IntegerValue::Signed(value)) => format!("i64:{value}"),
        ChoiceValue::Integer(IntegerValue::Unsigned(value)) => format!("u64:{value}"),
    }
}

pub(super) fn campaign_branch_cause_label(cause: BranchRequestCause) -> String {
    match cause {
        BranchRequestCause::Planner(value) => format!("planner:{value}"),
        BranchRequestCause::Operator(value) => format!("operator:{value}"),
        BranchRequestCause::Debugger(value) => format!("debugger:{value}"),
        BranchRequestCause::ExhaustivePolicy(value) => format!("policy:{value}"),
    }
}

pub(super) fn campaign_stop_condition_label(stop: &StopCondition) -> String {
    match stop {
        StopCondition::NextChoice => String::from("next-choice"),
        StopCondition::NamedBoundary(value) => format!("boundary:{value}"),
        StopCondition::VirtualTimeNanoseconds(value) => format!("virtual-time-ns:{value}"),
        StopCondition::EventCount(value) => format!("events:{value}"),
        StopCondition::Terminal => String::from("terminal"),
    }
}

pub(super) fn render_campaign_object(
    report: &CampaignObjectReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(campaign_object_fields(report)?
            .into_iter()
            .map(|(field, value)| format!("{field:<28} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in campaign_object_fields(report)? {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

fn campaign_object_fields(
    report: &CampaignObjectReport,
) -> Result<Vec<(String, String)>, CliError> {
    let value = serde_json::to_value(report)
        .map_err(|error| backend_error(format!("campaign object encoding failed: {error}")))?;
    let mut fields = Vec::new();
    flatten_campaign_object_value(None, &value, &mut fields)?;
    Ok(fields)
}

fn flatten_campaign_object_value(
    prefix: Option<&str>,
    value: &serde_json::Value,
    fields: &mut Vec<(String, String)>,
) -> Result<(), CliError> {
    if let serde_json::Value::Object(object) = value {
        for (key, value) in object {
            let field = prefix.map_or_else(|| key.clone(), |prefix| format!("{prefix}.{key}"));
            flatten_campaign_object_value(Some(&field), value, fields)?;
        }
        return Ok(());
    }
    let field = prefix
        .ok_or_else(|| backend_error("campaign object report has no field name"))?
        .to_owned();
    let rendered = match value {
        serde_json::Value::Null => String::from("-"),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Array(_) => serde_json::to_string(value).map_err(|error| {
            backend_error(format!("campaign object array encoding failed: {error}"))
        })?,
        serde_json::Value::Object(_) => {
            return Err(backend_error(
                "campaign object report retained an unflattened object",
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
    fn object_reports_render_nested_machine_and_human_views() {
        let report = CampaignObjectReport {
            schema: CAMPAIGN_OBJECT_REPORT_SCHEMA,
            operation: "frontier-object",
            campaign: String::from("example"),
            snapshot: String::from("snapshot"),
            object: CampaignObjectView::Frontier {
                request: String::from("request"),
                branch_point: String::from("branch-point"),
                parent: String::from("parent"),
                opportunity: String::from("opportunity"),
                domain: String::from("domain"),
                source: "finite",
                finite_values: vec![String::from("false"), String::from("true")],
                generator: None,
                cause: String::from("operator:test"),
                maximum_proposals: 2,
                maximum_attempts: 1,
                stop: String::from("next-choice"),
                state: "waiting-for-feedback",
                completed_visits: Some(3),
                required_visits: Some(5),
            },
        };

        let json = render_campaign_object(&report, OutputFormat::Json).expect("JSON object");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_OBJECT_REPORT_SCHEMA);
        assert_eq!(decoded["object"]["kind"], "frontier");
        assert_eq!(decoded["object"]["finite_values"][1], "true");

        let table = render_campaign_object(&report, OutputFormat::Table).expect("table object");
        assert!(table.contains("object.maximum_attempts"));
        assert!(table.contains("object.finite_values"));
        let markdown =
            render_campaign_object(&report, OutputFormat::Markdown).expect("Markdown object");
        assert!(markdown.contains("| object.required_visits | 5 |"));
    }
}
