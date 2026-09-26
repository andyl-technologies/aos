//! Authenticated exact capture, status, and selected continuation commands.

use super::*;
use crucible_campaign::{
    AttemptId, CampaignFactId, CampaignSavepointAction, CampaignSavepointRequest,
    CampaignSavepointResult, SavepointCaptureOutcome,
};

const CAMPAIGN_SAVEPOINT_REPORT_SCHEMA: &str = "crucible.cli.campaign-savepoint.v1";

#[derive(Serialize)]
pub(super) struct CampaignSavepointReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_observation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reached_configuration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replayed: Option<bool>,
}

pub(super) fn prepare_campaign_savepoint_command(
    command: &CampaignCommand,
    principal: &CampaignPrincipal,
) -> Result<CampaignSavepointRequest, CliError> {
    let (name, snapshot, action) = match command {
        CampaignCommand::CaptureAttempt(args) => {
            let command = CampaignCommandId::parse(&args.command)
                .map_err(|error| usage_error(format!("invalid capture command: {error}")))?;
            let attempt = AttemptId::parse(&args.attempt)
                .map_err(|error| usage_error(format!("invalid capture attempt: {error}")))?;
            (
                &args.name,
                &args.snapshot,
                CampaignSavepointAction::Capture { command, attempt },
            )
        }
        CampaignCommand::CaptureStatus(args) => {
            let request = CampaignFactId::parse(&args.request)
                .map_err(|error| usage_error(format!("invalid capture request: {error}")))?;
            (
                &args.name,
                &args.snapshot,
                CampaignSavepointAction::Status { request },
            )
        }
        CampaignCommand::SelectCapture(args) => {
            let command = CampaignCommandId::parse(&args.command)
                .map_err(|error| usage_error(format!("invalid selection command: {error}")))?;
            let request = CampaignFactId::parse(&args.request)
                .map_err(|error| usage_error(format!("invalid capture request: {error}")))?;
            let stop = parse_campaign_stop_condition(&args.stop)?;
            (
                &args.name,
                &args.snapshot,
                CampaignSavepointAction::Select {
                    command,
                    request,
                    stop,
                },
            )
        }
        _ => {
            return Err(backend_error(
                "non-savepoint command reached savepoint validation",
            ));
        }
    };
    let campaign = campaign_name(name)?;
    let snapshot = CampaignSnapshotId::parse(snapshot)
        .map_err(|error| usage_error(format!("invalid savepoint snapshot: {error}")))?;
    CampaignSavepointRequest::new(principal.clone(), campaign, snapshot, action)
        .map_err(|error| usage_error(format!("invalid savepoint request: {error}")))
}

pub(super) fn query_campaign_savepoint<S>(
    client: &CampaignClient<S>,
    request: &CampaignSavepointRequest,
) -> Result<CampaignSavepointReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let response = client
        .campaign_savepoint(request)
        .map_err(|error| backend_error(format!("campaign savepoint action failed: {error}")))?;
    let campaign = request.campaign().as_str().to_owned();

    let report = match response.result() {
        CampaignSavepointResult::Captured {
            snapshot,
            request,
            replayed,
        } => CampaignSavepointReport {
            schema: CAMPAIGN_SAVEPOINT_REPORT_SCHEMA,
            operation: "capture-attempt",
            campaign,
            snapshot: snapshot.to_string(),
            request: Some(request.to_string()),
            attempt: None,
            outcome: None,
            checkpoint: None,
            source_observation: None,
            reached_configuration: None,
            replayed: Some(*replayed),
        },
        CampaignSavepointResult::Status {
            capture,
            resolution,
            runtime,
            source_observation,
            reached_configuration,
        } => CampaignSavepointReport {
            schema: CAMPAIGN_SAVEPOINT_REPORT_SCHEMA,
            operation: "capture-status",
            campaign,
            snapshot: request.snapshot().to_string(),
            request: match request.action() {
                CampaignSavepointAction::Status { request } => Some(request.to_string()),
                _ => None,
            },
            attempt: Some(capture.attempt.to_string()),
            outcome: Some(match resolution.as_ref().map(|value| value.outcome) {
                None => "pending",
                Some(SavepointCaptureOutcome::Ready) => "ready",
                Some(SavepointCaptureOutcome::Canceled) => "canceled",
                Some(SavepointCaptureOutcome::Failed) => "failed",
            }),
            checkpoint: runtime
                .as_ref()
                .and_then(|state| state.checkpoint())
                .map(|value| value.to_string()),
            source_observation: Some(source_observation.to_string()),
            reached_configuration: Some(reached_configuration.to_string()),
            replayed: None,
        },
        CampaignSavepointResult::Selected {
            snapshot,
            attempt,
            replayed,
        } => CampaignSavepointReport {
            schema: CAMPAIGN_SAVEPOINT_REPORT_SCHEMA,
            operation: "select-capture",
            campaign,
            snapshot: snapshot.to_string(),
            request: match request.action() {
                CampaignSavepointAction::Select { request, .. } => Some(request.to_string()),
                _ => None,
            },
            attempt: Some(attempt.to_string()),
            outcome: None,
            checkpoint: None,
            source_observation: None,
            reached_configuration: None,
            replayed: Some(*replayed),
        },
    };
    Ok(report)
}

pub(super) fn render_campaign_savepoint(
    report: &CampaignSavepointReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("savepoint JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("savepoint JSON encoding failed: {error}"))),
        OutputFormat::Table | OutputFormat::Markdown => {
            let mut fields = vec![
                format!("operation: {}", report.operation),
                format!("campaign: {}", report.campaign),
                format!("snapshot: {}", report.snapshot),
            ];
            if let Some(value) = &report.request {
                fields.push(format!("request: {value}"));
            }
            if let Some(value) = &report.attempt {
                fields.push(format!("attempt: {value}"));
            }
            if let Some(value) = report.outcome {
                fields.push(format!("outcome: {value}"));
            }
            if let Some(value) = &report.checkpoint {
                fields.push(format!("checkpoint: {value}"));
            }
            Ok(fields.join("\n"))
        }
    }
}
