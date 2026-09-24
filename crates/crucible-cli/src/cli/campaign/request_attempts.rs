//! Authenticated, request-local execution-basis attempt lookup for operators.

use super::object::campaign_choice_value_label;
use super::*;
use crucible_campaign::{
    AttemptAdmissionRole, MAX_CAMPAIGN_REQUEST_ATTEMPT_PAGE_ITEMS, ProposalId,
    QueryCampaignRequestAttemptsRequest,
};

const REPORT_SCHEMA: &str = "crucible.cli.campaign-request-attempts.v2";

#[derive(Serialize)]
pub(super) struct CampaignRequestAttemptsReport {
    schema: &'static str,
    campaign: String,
    snapshot: String,
    request: String,
    page_limit: u32,
    page_budget: u32,
    pages_scanned: u32,
    complete: bool,
    next_after: Option<String>,
    entries: Vec<CampaignRequestAttemptEntry>,
}

#[derive(Serialize)]
struct CampaignRequestAttemptEntry {
    attempt: String,
    admission: String,
    proposal: String,
    request: String,
    role: &'static str,
    value: String,
}

pub(super) fn validate_campaign_request_attempts(
    args: &CampaignRequestAttemptsArgs,
) -> Result<(), CliError> {
    campaign_name(&args.name)?;
    CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign snapshot: {error}")))?;
    BranchRequestId::parse(&args.request)
        .map_err(|error| usage_error(format!("invalid branch request: {error}")))?;
    if let Some(after) = &args.after {
        ProposalId::parse(after)
            .map_err(|error| usage_error(format!("invalid proposal cursor: {error}")))?;
    }
    if args.limit == 0 || args.limit > MAX_CAMPAIGN_REQUEST_ATTEMPT_PAGE_ITEMS {
        return Err(usage_error(format!(
            "request-attempt page limit must be between 1 and {MAX_CAMPAIGN_REQUEST_ATTEMPT_PAGE_ITEMS}"
        )));
    }
    if args.pages == 0 || args.pages > MAX_CAMPAIGN_PAGE_FOLLOW_PAGES {
        return Err(usage_error(format!(
            "request-attempt page budget must be between 1 and {MAX_CAMPAIGN_PAGE_FOLLOW_PAGES}"
        )));
    }
    Ok(())
}

pub(super) fn query_campaign_request_attempts<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    args: &CampaignRequestAttemptsArgs,
) -> Result<CampaignRequestAttemptsReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    validate_campaign_request_attempts(args)?;
    let campaign = campaign_name(&args.name)?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign snapshot: {error}")))?;
    let branch_request = BranchRequestId::parse(&args.request)
        .map_err(|error| usage_error(format!("invalid branch request: {error}")))?;
    let mut after = args
        .after
        .as_deref()
        .map(ProposalId::parse)
        .transpose()
        .map_err(|error| usage_error(format!("invalid proposal cursor: {error}")))?;
    let mut pages_scanned = 0;
    let mut entries = Vec::new();

    for _ in 0..args.pages {
        let request = QueryCampaignRequestAttemptsRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            branch_request,
            after,
            args.limit,
        )
        .map_err(|error| usage_error(format!("invalid request-attempt query: {error}")))?;
        let response = client
            .query_campaign_request_attempts(&request)
            .map_err(|error| {
                backend_error(format!("campaign request-attempt query failed: {error}"))
            })?;
        pages_scanned += 1;
        for entry in response.entries() {
            let admission = entry.admission();
            entries.push(CampaignRequestAttemptEntry {
                attempt: admission.attempt().to_string(),
                admission: admission
                    .id()
                    .map_err(|error| backend_error(format!("invalid attempt admission: {error}")))?
                    .to_string(),
                proposal: entry
                    .proposal()
                    .id()
                    .map_err(|error| backend_error(format!("invalid proposal: {error}")))?
                    .to_string(),
                request: entry.proposal().request().to_string(),
                role: match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis { .. } => "execution-basis",
                    AttemptAdmissionRole::AdditionalCause { .. } => "additional-cause",
                },
                value: campaign_choice_value_label(entry.proposal().value()),
            });
        }
        let next = response.next_after();
        if next == after && next.is_some() {
            return Err(backend_error(
                "request-attempt query returned a repeated cursor",
            ));
        }
        after = next;
        if after.is_none() {
            break;
        }
    }

    Ok(CampaignRequestAttemptsReport {
        schema: REPORT_SCHEMA,
        campaign: args.name.clone(),
        snapshot: args.snapshot.clone(),
        request: args.request.clone(),
        page_limit: args.limit,
        page_budget: args.pages,
        pages_scanned,
        complete: after.is_none(),
        next_after: after.map(|id| id.to_string()),
        entries,
    })
}

pub(super) fn render_campaign_request_attempts(
    report: &CampaignRequestAttemptsReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => {
            let mut lines = vec![
                format!("campaign {}", report.campaign),
                format!("snapshot {}", report.snapshot),
                format!("request {}", report.request),
                format!("complete {}", report.complete),
            ];
            lines.extend(report.entries.iter().map(|entry| {
                format!(
                    "{} {} {} {} {}",
                    entry.attempt, entry.admission, entry.proposal, entry.role, entry.value
                )
            }));
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut lines = vec![
                format!(
                    "Request `{}` at snapshot `{}`",
                    report.request, report.snapshot
                ),
                String::new(),
                "| Attempt | Admission | Proposal | Role | Value |".to_owned(),
                "| --- | --- | --- | --- | --- |".to_owned(),
            ];
            lines.extend(report.entries.iter().map(|entry| {
                format!(
                    "| {} | {} | {} | {} | {} |",
                    entry.attempt, entry.admission, entry.proposal, entry.role, entry.value
                )
            }));
            Ok(lines.join("\n"))
        }
    }
}
