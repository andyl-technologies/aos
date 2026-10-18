//! Renders authenticated campaign explanation reports.

use super::*;

pub(in crate::cli_campaign) fn render_campaign_explanation(
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

pub(in crate::cli_campaign) fn render_campaign_finding_explanation(
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

pub(in crate::cli_campaign) fn render_campaign_attempt_explanation(
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
