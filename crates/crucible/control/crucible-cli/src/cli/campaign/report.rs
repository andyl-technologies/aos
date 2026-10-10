//! Public rendering for snapshot-bound campaign reports.

use super::*;
use crucible_campaign::{
    CampaignEstimateLabel, CampaignMode, CampaignReportEndpoint, CampaignReportSummary,
    MAX_CAMPAIGN_REPORT_PAGE_ITEMS, QueryCampaignReportRequest,
};

const CAMPAIGN_REPORT_SCHEMA: &str = "crucible.cli.campaign-report.v1";

#[derive(Debug, Serialize)]
pub(super) struct CampaignReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    state: &'static str,
    mode: &'static str,
    explored_attempts: u64,
    stopped_attempts: u64,
    successful_attempts: u64,
    failed_attempts: u64,
    unexplored_attempts: u64,
    findings: u64,
    unvisited_continuations: u64,
    exhausted_continuations: u64,
    pruned_continuations: u64,
    policy_execution_bases: u64,
    operator_execution_bases: u64,
    debugger_execution_bases: u64,
    additional_causes: u64,
    planner_steps: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_planner_step: Option<String>,
    estimate: &'static str,
    estimator_endpoints: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight_concentration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_sample_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_after: Option<u32>,
    page_limit: u32,
    page_budget: u32,
    pages_scanned: u32,
    response_bytes: u64,
    complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_after: Option<u32>,
    endpoints: Vec<CampaignReportEndpointView>,
}

#[derive(Debug, Serialize)]
struct CampaignReportEndpointView {
    ordinal: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<u32>,
    source_coordinate: u64,
    proposal: String,
    attempt: String,
    observation: String,
    path: String,
    target_probability: String,
    proposal_probability: String,
    estimator_weight: String,
}

pub(super) fn validate_campaign_report_command(command: &CampaignCommand) -> Result<(), CliError> {
    let CampaignCommand::Report(args) = command else {
        return Err(backend_error(
            "campaign report validation received another command",
        ));
    };
    campaign_name(&args.name)?;
    CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign report snapshot: {error}")))?;
    if args.after == Some(0) {
        return Err(usage_error(
            "campaign report cursor must be greater than zero",
        ));
    }
    if args.limit == 0 || args.limit > MAX_CAMPAIGN_REPORT_PAGE_ITEMS {
        return Err(usage_error(format!(
            "campaign report page size must be between 1 and {MAX_CAMPAIGN_REPORT_PAGE_ITEMS}"
        )));
    }
    if args.pages == 0 || args.pages > MAX_CAMPAIGN_PAGE_FOLLOW_PAGES {
        return Err(usage_error(format!(
            "campaign report page budget must be between 1 and {MAX_CAMPAIGN_PAGE_FOLLOW_PAGES}"
        )));
    }
    let endpoints = usize::try_from(args.limit)
        .ok()
        .and_then(|limit| {
            usize::try_from(args.pages)
                .ok()
                .and_then(|pages| limit.checked_mul(pages))
        })
        .ok_or_else(|| usage_error("campaign report endpoint count overflows"))?;
    if endpoints > MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES {
        return Err(usage_error(format!(
            "campaign report request exceeds the {MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES}-endpoint aggregate bound"
        )));
    }
    Ok(())
}

pub(super) fn query_campaign_report<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    validate_campaign_report_command(command)?;
    let CampaignCommand::Report(args) = command else {
        return Err(backend_error(
            "campaign report query received another command",
        ));
    };
    let campaign = campaign_name(&args.name)?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign report snapshot: {error}")))?;
    let start_after = args.after;
    let mut after = args.after;
    let mut summary = None;
    let mut pages_scanned = 0_u32;
    let mut response_bytes = 0_u64;
    let mut endpoints = Vec::new();

    for _ in 0..args.pages {
        let request = QueryCampaignReportRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            after,
            args.limit,
        )
        .map_err(|error| usage_error(format!("invalid campaign report request: {error}")))?;
        let response = client
            .query_campaign_report(&request)
            .map_err(|error| backend_error(format!("campaign report failed: {error}")))?;
        if summary.is_some_and(|current| current != response.summary()) {
            return Err(backend_error(
                "campaign report summary changed between snapshot-bound pages",
            ));
        }
        summary = Some(response.summary());
        pages_scanned = pages_scanned
            .checked_add(1)
            .ok_or_else(|| backend_error("campaign report page count overflowed"))?;
        response_bytes = response_bytes
            .checked_add(
                u64::try_from(response.canonical_bytes().len())
                    .map_err(|_| backend_error("campaign report response size overflowed"))?,
            )
            .ok_or_else(|| backend_error("campaign report response bytes overflowed"))?;
        if response_bytes > MAX_CAMPAIGN_PAGE_AGGREGATE_RESPONSE_BYTES {
            return Err(backend_error(format!(
                "campaign report responses exceed the {MAX_CAMPAIGN_PAGE_AGGREGATE_RESPONSE_BYTES}-byte aggregate bound"
            )));
        }
        for endpoint in response.endpoints() {
            if endpoints.len() >= MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES {
                return Err(backend_error(format!(
                    "campaign report exceeds the {MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES}-endpoint aggregate bound"
                )));
            }
            endpoints.push(endpoint_view(*endpoint));
        }
        let next = response.next_after();
        if next.is_some_and(|next| after.is_some_and(|prior| next <= prior)) {
            return Err(backend_error(
                "campaign report endpoint cursor did not advance",
            ));
        }
        after = next;
        if after.is_none() {
            break;
        }
    }

    let summary = summary.ok_or_else(|| backend_error("campaign report returned no page"))?;
    report_view(
        &campaign,
        snapshot,
        args,
        summary,
        start_after,
        after,
        pages_scanned,
        response_bytes,
        endpoints,
    )
}

// crucible-lint: allow rust-allow -- report assembly keeps each snapshot, pagination, and evidence input explicit.
#[allow(clippy::too_many_arguments)]
fn report_view(
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    args: &CampaignReportArgs,
    summary: CampaignReportSummary,
    start_after: Option<u32>,
    next_after: Option<u32>,
    pages_scanned: u32,
    response_bytes: u64,
    endpoints: Vec<CampaignReportEndpointView>,
) -> Result<CampaignReport, CliError> {
    let semantic = summary.semantic();
    let continuations = semantic.continuations();
    let outcomes = summary.outcomes();
    let execution = summary.execution_bases();
    let planner = summary.planner();
    let estimate = summary.estimate();
    let diagnostics = estimate.diagnostics();
    let unexplored_attempts = semantic
        .admitted_attempts()
        .checked_sub(outcomes.explored())
        .ok_or_else(|| backend_error("campaign report explored count exceeds admissions"))?;
    let unvisited_continuations = continuations
        .latent_or_open()
        .map_err(|error| backend_error(format!("campaign report is invalid: {error}")))?;
    Ok(CampaignReport {
        schema: CAMPAIGN_REPORT_SCHEMA,
        operation: "report",
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        state: campaign_state_label(summary.state()),
        mode: campaign_mode_label(summary.mode()),
        explored_attempts: outcomes.explored(),
        stopped_attempts: outcomes.requested_stops(),
        successful_attempts: outcomes.terminal_successes(),
        failed_attempts: outcomes.failures(),
        unexplored_attempts,
        findings: outcomes.findings(),
        unvisited_continuations,
        exhausted_continuations: continuations.exhausted(),
        pruned_continuations: continuations.closed(),
        policy_execution_bases: execution.policy(),
        operator_execution_bases: execution.operator(),
        debugger_execution_bases: execution.debugger(),
        additional_causes: execution.additional_causes(),
        planner_steps: planner.steps(),
        latest_planner_step: planner.latest().map(|step| step.to_string()),
        estimate: estimate_label(estimate.label()),
        estimator_endpoints: estimate.endpoints(),
        weight_concentration: diagnostics.map(|value| rational(value.concentration())),
        effective_sample_size: diagnostics.map(|value| rational(value.effective_sample_size())),
        start_after,
        page_limit: args.limit,
        page_budget: args.pages,
        pages_scanned,
        response_bytes,
        complete: next_after.is_none(),
        next_after,
        endpoints,
    })
}

fn endpoint_view(endpoint: CampaignReportEndpoint) -> CampaignReportEndpointView {
    CampaignReportEndpointView {
        ordinal: endpoint.ordinal(),
        stage: endpoint.stage(),
        source_coordinate: endpoint.source_coordinate(),
        proposal: endpoint.proposal().to_string(),
        attempt: endpoint.attempt().to_string(),
        observation: endpoint.observation().to_string(),
        path: endpoint.path().to_string(),
        target_probability: rational(endpoint.target_probability()),
        proposal_probability: rational(endpoint.proposal_probability()),
        estimator_weight: rational(endpoint.estimator_weight()),
    }
}

fn rational(value: crucible_campaign::StatisticalRational) -> String {
    format!("{}/{}", value.numerator(), value.denominator())
}

fn estimate_label(label: CampaignEstimateLabel) -> &'static str {
    match label {
        CampaignEstimateLabel::NoEstimate => "no-estimate",
        CampaignEstimateLabel::Descriptive => "descriptive",
        CampaignEstimateLabel::GuidanceBiased => "guidance-biased",
        CampaignEstimateLabel::StatisticallyWeighted => "statistically-weighted",
    }
}

fn campaign_mode_label(mode: CampaignMode) -> &'static str {
    match mode {
        CampaignMode::Strict => "strict",
        CampaignMode::Streaming => "streaming",
        CampaignMode::Statistical => "statistical",
    }
}

pub(super) fn render_campaign_report(
    report: &CampaignReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!("campaign report JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!("campaign report JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => Ok(render_table(report)),
        OutputFormat::Markdown => Ok(render_markdown(report)),
    }
}

fn render_table(report: &CampaignReport) -> String {
    let mut lines = report_rows(report)
        .into_iter()
        .map(|(field, value)| format!("{field:<25} {value}"))
        .collect::<Vec<_>>();
    lines.push(String::new());
    lines.push(String::from(
        "ordinal\tstage\tsource\tproposal\tattempt\tobservation\tpath\ttarget_p\tproposal_q\tweight",
    ));
    for endpoint in &report.endpoints {
        lines.push(endpoint_row(endpoint, "\t"));
    }
    lines.join("\n")
}

fn render_markdown(report: &CampaignReport) -> String {
    let mut output = String::from("| Field | Value |\n| --- | --- |\n");
    for (field, value) in report_rows(report) {
        output.push_str(&format!("| {field} | {value} |\n"));
    }
    output.push_str(
        "\n| Ordinal | Stage | Source | Proposal | Attempt | Observation | Path | Target P | Proposal Q | Weight |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for endpoint in &report.endpoints {
        output.push_str("| ");
        output.push_str(&endpoint_row(endpoint, " | "));
        output.push_str(" |\n");
    }
    output.trim_end().to_owned()
}

fn report_rows(report: &CampaignReport) -> Vec<(&'static str, String)> {
    vec![
        ("campaign", report.campaign.clone()),
        ("snapshot", report.snapshot.clone()),
        ("state", report.state.to_owned()),
        ("mode", report.mode.to_owned()),
        ("explored_attempts", report.explored_attempts.to_string()),
        ("stopped_attempts", report.stopped_attempts.to_string()),
        (
            "successful_attempts",
            report.successful_attempts.to_string(),
        ),
        ("failed_attempts", report.failed_attempts.to_string()),
        (
            "unexplored_attempts",
            report.unexplored_attempts.to_string(),
        ),
        ("findings", report.findings.to_string()),
        (
            "unvisited_continuations",
            report.unvisited_continuations.to_string(),
        ),
        (
            "exhausted_continuations",
            report.exhausted_continuations.to_string(),
        ),
        (
            "pruned_continuations",
            report.pruned_continuations.to_string(),
        ),
        (
            "policy_execution_bases",
            report.policy_execution_bases.to_string(),
        ),
        (
            "operator_execution_bases",
            report.operator_execution_bases.to_string(),
        ),
        (
            "debugger_execution_bases",
            report.debugger_execution_bases.to_string(),
        ),
        ("additional_causes", report.additional_causes.to_string()),
        ("planner_steps", report.planner_steps.to_string()),
        (
            "latest_planner_step",
            report
                .latest_planner_step
                .clone()
                .unwrap_or_else(|| "-".into()),
        ),
        ("estimate", report.estimate.to_owned()),
        (
            "estimator_endpoints",
            report.estimator_endpoints.to_string(),
        ),
        (
            "weight_concentration",
            report
                .weight_concentration
                .clone()
                .unwrap_or_else(|| "-".into()),
        ),
        (
            "effective_sample_size",
            report
                .effective_sample_size
                .clone()
                .unwrap_or_else(|| "-".into()),
        ),
        (
            "start_after",
            report
                .start_after
                .map_or_else(|| "-".into(), |value| value.to_string()),
        ),
        ("page_limit", report.page_limit.to_string()),
        ("page_budget", report.page_budget.to_string()),
        ("pages_scanned", report.pages_scanned.to_string()),
        ("response_bytes", report.response_bytes.to_string()),
        ("complete", report.complete.to_string()),
        (
            "next_after",
            report
                .next_after
                .map_or_else(|| "-".into(), |value| value.to_string()),
        ),
        ("returned_endpoints", report.endpoints.len().to_string()),
    ]
}

fn endpoint_row(endpoint: &CampaignReportEndpointView, separator: &str) -> String {
    [
        endpoint.ordinal.to_string(),
        endpoint
            .stage
            .map_or_else(|| "-".into(), |stage| stage.to_string()),
        endpoint.source_coordinate.to_string(),
        endpoint.proposal.clone(),
        endpoint.attempt.clone(),
        endpoint.observation.clone(),
        endpoint.path.clone(),
        endpoint.target_probability.clone(),
        endpoint.proposal_probability.clone(),
        endpoint.estimator_weight.clone(),
    ]
    .join(separator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_reports_name_each_operator_outcome_class() {
        let report = CampaignReport {
            schema: CAMPAIGN_REPORT_SCHEMA,
            operation: "report",
            campaign: String::from("network-recovery"),
            snapshot: String::from("snapshot"),
            state: "paused",
            mode: "statistical",
            explored_attempts: 9,
            stopped_attempts: 4,
            successful_attempts: 2,
            failed_attempts: 3,
            unexplored_attempts: 1,
            findings: 2,
            unvisited_continuations: 5,
            exhausted_continuations: 6,
            pruned_continuations: 7,
            policy_execution_bases: 8,
            operator_execution_bases: 1,
            debugger_execution_bases: 1,
            additional_causes: 2,
            planner_steps: 3,
            latest_planner_step: Some(String::from("step")),
            estimate: "no-estimate",
            estimator_endpoints: 0,
            weight_concentration: None,
            effective_sample_size: None,
            start_after: None,
            page_limit: 8,
            page_budget: 1,
            pages_scanned: 1,
            response_bytes: 512,
            complete: true,
            next_after: None,
            endpoints: Vec::new(),
        };

        let table = render_table(&report);
        let markdown = render_markdown(&report);
        assert!(table.contains("findings                  2"));
        assert!(markdown.contains("| findings | 2 |"));

        for rendered in [table, markdown] {
            for field in [
                "explored_attempts",
                "stopped_attempts",
                "failed_attempts",
                "unexplored_attempts",
                "findings",
                "unvisited_continuations",
                "exhausted_continuations",
                "pruned_continuations",
                "latest_planner_step",
                "no-estimate",
            ] {
                assert!(
                    rendered.contains(field),
                    "missing `{field}` in:\n{rendered}"
                );
            }
        }
    }
}
