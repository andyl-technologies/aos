//! Offline policy and connected named-campaign validation.

use super::*;

use crucible_campaign::CampaignMode;
use serde::Serialize;

pub(super) const CAMPAIGN_VALIDATION_REPORT_SCHEMA: &str = "crucible.cli.campaign-validation.v1";

/// Successful validation of one canonical policy or authenticated campaign.
#[derive(Debug, Serialize)]
#[serde(tag = "subject", rename_all = "kebab-case")]
pub(super) enum CampaignValidationReport {
    /// One offline canonical policy record.
    Policy {
        schema: &'static str,
        input: String,
        policy: String,
        scenario: String,
        mode: &'static str,
        encoded_bytes: usize,
        choice_policies: usize,
        objectives: usize,
        guidance_signals: usize,
        stop_conditions: usize,
    },
    /// One authenticated current named-campaign head.
    Campaign {
        schema: &'static str,
        campaign: String,
        snapshot: String,
        lineage: String,
        policy: String,
        state: &'static str,
    },
}

/// Validates one bounded canonical campaign policy without repository access.
pub(super) fn validate_campaign_policy_file(
    input: &Path,
) -> Result<CampaignValidationReport, CliError> {
    let bytes = read_campaign_record(input, "campaign policy")?;
    let policy = CampaignPolicy::from_canonical_bytes(&bytes)
        .map_err(|error| usage_error(format!("invalid campaign policy record: {error}")))?;
    if policy.canonical_bytes() != bytes {
        return Err(usage_error("campaign policy record is not byte-canonical"));
    }
    let id = policy
        .id()
        .map_err(|error| usage_error(format!("could not address campaign policy: {error}")))?;

    Ok(CampaignValidationReport::Policy {
        schema: CAMPAIGN_VALIDATION_REPORT_SCHEMA,
        input: input.display().to_string(),
        policy: id.to_string(),
        scenario: policy.scenario().to_string(),
        mode: campaign_mode_label(policy.mode()),
        encoded_bytes: bytes.len(),
        choice_policies: policy.choice_policies().len(),
        objectives: policy.objectives().len(),
        guidance_signals: policy.guidance().len(),
        stop_conditions: policy.stop_conditions().len(),
    })
}

/// Authenticates one named campaign's exact current head and lifecycle state.
pub(super) fn query_campaign_validation<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    validate: &CampaignValidateArgs,
) -> Result<CampaignValidationReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let name = validate.name.as_deref().ok_or_else(|| {
        backend_error("offline policy validation reached the connected campaign path")
    })?;
    if validate.policy.is_some() {
        return Err(backend_error(
            "campaign validation contains both connected and offline targets",
        ));
    }
    let campaign = campaign_name(name)?;
    let request = GetCampaignRequest::new(principal, campaign.clone())
        .map_err(|error| usage_error(format!("invalid campaign validation request: {error}")))?;
    let response = client
        .get_campaign(&request)
        .map_err(|error| backend_error(format!("campaign validation failed: {error}")))?;

    Ok(CampaignValidationReport::Campaign {
        schema: CAMPAIGN_VALIDATION_REPORT_SCHEMA,
        campaign: campaign.as_str().to_owned(),
        snapshot: response.snapshot().to_string(),
        lineage: response.lineage().to_string(),
        policy: response.policy().to_string(),
        state: campaign_state_label(response.state()),
    })
}

/// Renders one successful policy or campaign validation report.
pub(super) fn render_campaign_validation(
    report: &CampaignValidationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!("campaign validation JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!("campaign validation JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => Ok(render_campaign_validation_table(report)),
        OutputFormat::Markdown => Ok(render_campaign_validation_markdown(report)),
    }
}

fn render_campaign_validation_table(report: &CampaignValidationReport) -> String {
    match report {
        CampaignValidationReport::Policy {
            input,
            policy,
            scenario,
            mode,
            encoded_bytes,
            choice_policies,
            objectives,
            guidance_signals,
            stop_conditions,
            ..
        } => [
            format!("{:<20} {}", "subject", "policy"),
            format!("{:<20} {input}", "input"),
            format!("{:<20} {policy}", "policy"),
            format!("{:<20} {scenario}", "scenario"),
            format!("{:<20} {mode}", "mode"),
            format!("{:<20} {encoded_bytes}", "encoded_bytes"),
            format!("{:<20} {choice_policies}", "choice_policies"),
            format!("{:<20} {objectives}", "objectives"),
            format!("{:<20} {guidance_signals}", "guidance_signals"),
            format!("{:<20} {stop_conditions}", "stop_conditions"),
        ]
        .join("\n"),
        CampaignValidationReport::Campaign {
            campaign,
            snapshot,
            lineage,
            policy,
            state,
            ..
        } => [
            format!("{:<20} {}", "subject", "campaign"),
            format!("{:<20} {campaign}", "campaign"),
            format!("{:<20} {snapshot}", "snapshot"),
            format!("{:<20} {lineage}", "lineage"),
            format!("{:<20} {policy}", "policy"),
            format!("{:<20} {state}", "state"),
        ]
        .join("\n"),
    }
}

fn render_campaign_validation_markdown(report: &CampaignValidationReport) -> String {
    let rows = match report {
        CampaignValidationReport::Policy {
            input,
            policy,
            scenario,
            mode,
            encoded_bytes,
            choice_policies,
            objectives,
            guidance_signals,
            stop_conditions,
            ..
        } => vec![
            ("subject", String::from("policy")),
            ("input", input.clone()),
            ("policy", policy.clone()),
            ("scenario", scenario.clone()),
            ("mode", String::from(*mode)),
            ("encoded bytes", encoded_bytes.to_string()),
            ("choice policies", choice_policies.to_string()),
            ("objectives", objectives.to_string()),
            ("guidance signals", guidance_signals.to_string()),
            ("stop conditions", stop_conditions.to_string()),
        ],
        CampaignValidationReport::Campaign {
            campaign,
            snapshot,
            lineage,
            policy,
            state,
            ..
        } => vec![
            ("subject", String::from("campaign")),
            ("campaign", campaign.clone()),
            ("snapshot", snapshot.clone()),
            ("lineage", lineage.clone()),
            ("policy", policy.clone()),
            ("state", String::from(*state)),
        ],
    };
    let mut lines = vec![
        String::from("| Field | Value |"),
        String::from("| --- | --- |"),
    ];
    lines.extend(
        rows.into_iter()
            .map(|(field, value)| format!("| {field} | {value} |")),
    );
    lines.join("\n")
}

const fn campaign_mode_label(mode: CampaignMode) -> &'static str {
    match mode {
        CampaignMode::Strict => "strict",
        CampaignMode::Streaming => "streaming",
        CampaignMode::Statistical => "statistical",
    }
}
