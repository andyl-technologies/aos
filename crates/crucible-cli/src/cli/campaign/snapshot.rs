//! Authenticated historical campaign-snapshot inspection and comparison.

use super::*;

use crucible_campaign::{CampaignRoots, CampaignSnapshot, GetCampaignSnapshotRequest};

const CAMPAIGN_SNAPSHOT_REPORT_SCHEMA: &str = "crucible.cli.campaign-snapshot.v1";
const CAMPAIGN_COMPARE_REPORT_SCHEMA: &str = "crucible.cli.campaign-compare.v1";

#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub(super) enum CampaignSnapshotReport {
    Snapshot {
        schema: &'static str,
        campaign: String,
        snapshot: CampaignSnapshotView,
    },
    Compare {
        schema: &'static str,
        campaign: String,
        direct_relationship: &'static str,
        left: CampaignSnapshotView,
        right: Box<CampaignSnapshotView>,
        changed: CampaignSnapshotChanges,
    },
}

#[derive(Serialize)]
pub(super) struct CampaignSnapshotView {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    lineage: String,
    active_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    transition: Option<String>,
    roots: CampaignRootsView,
}

#[derive(Serialize)]
struct CampaignRootsView {
    graph: String,
    exploration: String,
    observations: String,
    corpus: String,
    coverage: String,
    findings: String,
    pins: String,
    accounting: String,
    coordination: String,
}

#[derive(Serialize)]
pub(super) struct CampaignSnapshotChanges {
    lineage: bool,
    active_policy: bool,
    parent: bool,
    transition: bool,
    roots: CampaignRootChanges,
}

#[derive(Serialize)]
struct CampaignRootChanges {
    graph: bool,
    exploration: bool,
    observations: bool,
    corpus: bool,
    coverage: bool,
    findings: bool,
    pins: bool,
    accounting: bool,
    coordination: bool,
}

pub(super) fn validate_campaign_snapshot_command(
    command: &CampaignCommand,
) -> Result<(), CliError> {
    match command {
        CampaignCommand::Snapshot(args) => {
            campaign_name(&args.name)?;
            parse_snapshot(&args.snapshot, "campaign snapshot")?;
            Ok(())
        }
        CampaignCommand::Compare(args) => {
            campaign_name(&args.name)?;
            parse_snapshot(&args.left, "left campaign snapshot")?;
            parse_snapshot(&args.right, "right campaign snapshot")?;
            Ok(())
        }
        _ => Err(backend_error(
            "non-snapshot campaign command reached snapshot validation",
        )),
    }
}

pub(super) fn query_campaign_snapshot<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignSnapshotReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    match command {
        CampaignCommand::Snapshot(args) => {
            let campaign = campaign_name(&args.name)?;
            let snapshot_id = parse_snapshot(&args.snapshot, "campaign snapshot")?;
            let snapshot = load_snapshot(client, principal, campaign.clone(), snapshot_id)?;
            Ok(CampaignSnapshotReport::Snapshot {
                schema: CAMPAIGN_SNAPSHOT_REPORT_SCHEMA,
                campaign: campaign.as_str().to_owned(),
                snapshot: campaign_snapshot_view(snapshot_id, &snapshot),
            })
        }
        CampaignCommand::Compare(args) => {
            let campaign = campaign_name(&args.name)?;
            let left_id = parse_snapshot(&args.left, "left campaign snapshot")?;
            let right_id = parse_snapshot(&args.right, "right campaign snapshot")?;
            let left = load_snapshot(client, principal.clone(), campaign.clone(), left_id)?;
            let right = load_snapshot(client, principal, campaign.clone(), right_id)?;
            let direct_relationship =
                direct_snapshot_relationship(left_id, &left, right_id, &right);
            let changed = campaign_snapshot_changes(&left, &right);
            Ok(CampaignSnapshotReport::Compare {
                schema: CAMPAIGN_COMPARE_REPORT_SCHEMA,
                campaign: campaign.as_str().to_owned(),
                direct_relationship,
                left: campaign_snapshot_view(left_id, &left),
                right: Box::new(campaign_snapshot_view(right_id, &right)),
                changed,
            })
        }
        _ => Err(backend_error(
            "non-snapshot campaign command reached snapshot query",
        )),
    }
}

fn load_snapshot<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
) -> Result<CampaignSnapshot, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let request = GetCampaignSnapshotRequest::new(principal, campaign, snapshot)
        .map_err(|error| usage_error(format!("invalid campaign snapshot query: {error}")))?;
    client
        .get_campaign_snapshot(&request)
        .map(|response| response.snapshot_body().clone())
        .map_err(|error| backend_error(format!("campaign snapshot query failed: {error}")))
}

fn parse_snapshot(value: &str, field: &str) -> Result<CampaignSnapshotId, CliError> {
    CampaignSnapshotId::parse(value)
        .map_err(|error| usage_error(format!("invalid {field}: {error}")))
}

fn campaign_snapshot_view(
    id: CampaignSnapshotId,
    snapshot: &CampaignSnapshot,
) -> CampaignSnapshotView {
    CampaignSnapshotView {
        id: id.to_string(),
        parent: snapshot.parent().map(|value| value.to_string()),
        lineage: snapshot.lineage().to_string(),
        active_policy: snapshot.active_policy().to_string(),
        transition: snapshot.transition().map(|value| value.to_string()),
        roots: campaign_roots_view(snapshot.roots()),
    }
}

fn campaign_roots_view(roots: CampaignRoots) -> CampaignRootsView {
    CampaignRootsView {
        graph: roots.graph.to_string(),
        exploration: roots.exploration.to_string(),
        observations: roots.observations.to_string(),
        corpus: roots.corpus.to_string(),
        coverage: roots.coverage.to_string(),
        findings: roots.findings.to_string(),
        pins: roots.pins.to_string(),
        accounting: roots.accounting.to_string(),
        coordination: roots.coordination.to_string(),
    }
}

fn direct_snapshot_relationship(
    left_id: CampaignSnapshotId,
    left: &CampaignSnapshot,
    right_id: CampaignSnapshotId,
    right: &CampaignSnapshot,
) -> &'static str {
    if left_id == right_id {
        "same"
    } else if right.parent() == Some(left_id) {
        "left-parent-of-right"
    } else if left.parent() == Some(right_id) {
        "right-parent-of-left"
    } else {
        "not-directly-adjacent"
    }
}

fn campaign_snapshot_changes(
    left: &CampaignSnapshot,
    right: &CampaignSnapshot,
) -> CampaignSnapshotChanges {
    let left_roots = left.roots();
    let right_roots = right.roots();
    CampaignSnapshotChanges {
        lineage: left.lineage() != right.lineage(),
        active_policy: left.active_policy() != right.active_policy(),
        parent: left.parent() != right.parent(),
        transition: left.transition() != right.transition(),
        roots: CampaignRootChanges {
            graph: left_roots.graph != right_roots.graph,
            exploration: left_roots.exploration != right_roots.exploration,
            observations: left_roots.observations != right_roots.observations,
            corpus: left_roots.corpus != right_roots.corpus,
            coverage: left_roots.coverage != right_roots.coverage,
            findings: left_roots.findings != right_roots.findings,
            pins: left_roots.pins != right_roots.pins,
            accounting: left_roots.accounting != right_roots.accounting,
            coordination: left_roots.coordination != right_roots.coordination,
        },
    }
}

pub(super) fn render_campaign_snapshot(
    report: &CampaignSnapshotReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(snapshot_report_fields(report)?
            .into_iter()
            .map(|(field, value)| format!("{field:<30} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in snapshot_report_fields(report)? {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

fn snapshot_report_fields(
    report: &CampaignSnapshotReport,
) -> Result<Vec<(String, String)>, CliError> {
    let value = serde_json::to_value(report)
        .map_err(|error| backend_error(format!("campaign snapshot encoding failed: {error}")))?;
    let mut fields = Vec::new();
    flatten_snapshot_value(None, &value, &mut fields)?;
    Ok(fields)
}

fn flatten_snapshot_value(
    prefix: Option<&str>,
    value: &serde_json::Value,
    fields: &mut Vec<(String, String)>,
) -> Result<(), CliError> {
    if let serde_json::Value::Object(object) = value {
        for (key, value) in object {
            let field = prefix.map_or_else(|| key.clone(), |prefix| format!("{prefix}.{key}"));
            flatten_snapshot_value(Some(&field), value, fields)?;
        }
        return Ok(());
    }
    let field = prefix
        .ok_or_else(|| backend_error("campaign snapshot report has no field name"))?
        .to_owned();
    let rendered = match value {
        serde_json::Value::Null => String::from("-"),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Array(_) => serde_json::to_string(value).map_err(|error| {
            backend_error(format!("campaign snapshot array encoding failed: {error}"))
        })?,
        serde_json::Value::Object(_) => {
            return Err(backend_error(
                "campaign snapshot report retained an unflattened object",
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
    fn compare_reports_render_exact_changes_in_machine_and_human_forms() {
        let report = CampaignSnapshotReport::Compare {
            schema: CAMPAIGN_COMPARE_REPORT_SCHEMA,
            campaign: String::from("example"),
            direct_relationship: "left-parent-of-right",
            left: fixture_view("left", "policy-a", "root-a"),
            right: Box::new(fixture_view("right", "policy-b", "root-b")),
            changed: CampaignSnapshotChanges {
                lineage: false,
                active_policy: true,
                parent: true,
                transition: true,
                roots: CampaignRootChanges {
                    graph: true,
                    exploration: false,
                    observations: false,
                    corpus: false,
                    coverage: false,
                    findings: false,
                    pins: false,
                    accounting: false,
                    coordination: false,
                },
            },
        };

        let json = render_campaign_snapshot(&report, OutputFormat::Json).expect("JSON report");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_COMPARE_REPORT_SCHEMA);
        assert_eq!(decoded["operation"], "compare");
        assert_eq!(decoded["changed"]["roots"]["graph"], true);

        let table = render_campaign_snapshot(&report, OutputFormat::Table).expect("table report");
        assert!(table.contains("changed.roots.graph"));
        let markdown =
            render_campaign_snapshot(&report, OutputFormat::Markdown).expect("Markdown report");
        assert!(markdown.contains("| direct_relationship | left-parent-of-right |"));
    }

    fn fixture_view(id: &str, policy: &str, root: &str) -> CampaignSnapshotView {
        CampaignSnapshotView {
            id: id.to_owned(),
            parent: None,
            lineage: String::from("lineage"),
            active_policy: policy.to_owned(),
            transition: None,
            roots: CampaignRootsView {
                graph: root.to_owned(),
                exploration: String::from("root"),
                observations: String::from("root"),
                corpus: String::from("root"),
                coverage: String::from("root"),
                findings: String::from("root"),
                pins: String::from("root"),
                accounting: String::from("root"),
                coordination: String::from("root"),
            },
        }
    }
}
