//! Renders campaign query and mutation reports.

use super::*;

pub(super) fn render_campaign_list(
    report: &CampaignListReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => {
            let mut lines = vec![
                format!(
                    "{:<12} {}",
                    "start_after",
                    report.start_after.as_deref().unwrap_or("-")
                ),
                format!("{:<12} {}", "page_limit", report.page_limit),
                format!("{:<12} {}", "page_budget", report.page_budget),
                format!("{:<12} {}", "pages", report.pages_scanned),
                format!("{:<12} {}", "bytes", report.response_bytes),
                format!("{:<12} {}", "complete", report.complete),
                format!(
                    "{:<12} {}",
                    "next_after",
                    report.next_after.as_deref().unwrap_or("-")
                ),
                format!("{:<12} {}", "entries", report.entries.len()),
                String::new(),
                String::from("campaign\tsnapshot\tlineage\tpolicy\tstate"),
            ];
            lines.extend(report.entries.iter().map(|entry| {
                format!(
                    "{}\t{}\t{}\t{}\t{}",
                    entry.campaign, entry.snapshot, entry.lineage, entry.policy, entry.state
                )
            }));
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut output = format!(
                "| Field | Value |\n| --- | --- |\n| start_after | {} |\n| page_limit | {} |\n| page_budget | {} |\n| pages | {} |\n| response_bytes | {} |\n| complete | {} |\n| next_after | {} |\n| entries | {} |\n\n| Campaign | Snapshot | Lineage | Policy | State |\n| --- | --- | --- | --- | --- |\n",
                report.start_after.as_deref().unwrap_or("-"),
                report.page_limit,
                report.page_budget,
                report.pages_scanned,
                report.response_bytes,
                report.complete,
                report.next_after.as_deref().unwrap_or("-"),
                report.entries.len(),
            );
            for entry in &report.entries {
                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    entry.campaign, entry.snapshot, entry.lineage, entry.policy, entry.state
                ));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

pub(super) fn render_campaign_runtime_attachment(
    report: &CampaignRuntimeAttachmentReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!(
                "campaign runtime-attachment JSON encoding failed: {error}"
            ))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!(
                "campaign runtime-attachment JSON encoding failed: {error}"
            ))
        }),
        OutputFormat::Table => Ok([
            format!("{:<18} {}", "campaign", report.campaign),
            format!("{:<18} {}", "operation", report.operation),
            format!("{:<18} {}", "request_digest", report.request_digest),
            format!("{:<18} {}", "disposition", report.disposition),
            format!(
                "{:<18} {}",
                "attached_runtimes", report.attached_runtime_count
            ),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| campaign | {} |\n| operation | {} |\n| request_digest | {} |\n| disposition | {} |\n| attached_runtimes | {} |",
            report.campaign,
            report.operation,
            report.request_digest,
            report.disposition,
            report.attached_runtime_count,
        )),
    }
}

pub(super) fn render_campaign_head(
    report: &CampaignHeadReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(campaign_head_rows(report)
            .into_iter()
            .map(|(field, value)| format!("{field:<10} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in campaign_head_rows(report) {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

fn campaign_head_rows(report: &CampaignHeadReport) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("campaign", report.campaign.clone()),
        ("snapshot", report.snapshot.clone()),
        ("lineage", report.lineage.clone()),
        ("policy", report.policy.clone()),
        ("state", report.state.to_owned()),
    ];
    if let Some(advanced) = report.advanced {
        rows.push(("advanced", advanced.to_string()));
    }
    if let Some(semantic) = &report.semantic {
        rows.extend([
            (
                "latent_or_open_continuations",
                semantic.latent_or_open_continuations.to_string(),
            ),
            (
                "ready_continuations",
                semantic.ready_continuations.to_string(),
            ),
            (
                "waiting_for_feedback_continuations",
                semantic.waiting_for_feedback_continuations.to_string(),
            ),
            (
                "open_continuations",
                semantic.open_continuations.to_string(),
            ),
            (
                "exhausted_continuations",
                semantic.exhausted_continuations.to_string(),
            ),
            (
                "closed_continuations",
                semantic.closed_continuations.to_string(),
            ),
            ("admitted_attempts", semantic.admitted_attempts.to_string()),
            (
                "stored_graph_nodes",
                semantic.stored_graph_nodes.to_string(),
            ),
            (
                "continuation_records_scanned",
                semantic.continuation_records_scanned.to_string(),
            ),
            (
                "continuation_bytes_scanned",
                semantic.continuation_bytes_scanned.to_string(),
            ),
        ]);
    }
    match report.operational.as_ref() {
        None => {}
        Some(CampaignOperationalStatusReport::Unavailable) => {
            rows.push(("operational", String::from("unavailable")));
        }
        Some(CampaignOperationalStatusReport::Observed {
            daemon_epoch,
            inventory_generation,
            preparing_worlds,
            running_worlds,
            checkpointing_worlds,
            publishing_worlds,
            canceling_worlds,
            paused_worlds,
            retained_checkpoint_roots,
            materialized_checkpoints,
        }) => rows.extend([
            ("operational", String::from("observed")),
            ("daemon_epoch", daemon_epoch.clone()),
            ("inventory_generation", inventory_generation.clone()),
            ("preparing_worlds", preparing_worlds.to_string()),
            ("running_worlds", running_worlds.to_string()),
            ("checkpointing_worlds", checkpointing_worlds.to_string()),
            ("publishing_worlds", publishing_worlds.to_string()),
            ("canceling_worlds", canceling_worlds.to_string()),
            ("paused_worlds", paused_worlds.to_string()),
            (
                "retained_checkpoint_roots",
                retained_checkpoint_roots.to_string(),
            ),
            (
                "materialized_checkpoints",
                materialized_checkpoints.to_string(),
            ),
        ]),
    }
    rows
}

pub(super) fn render_campaign_mutation(
    report: &CampaignMutationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok([
            format!("{:<15} {}", "campaign", report.campaign),
            format!("{:<15} {}", "operation", report.operation),
            format!("{:<15} {}", "command", report.command),
            format!("{:<15} {}", "prior_snapshot", report.prior_snapshot),
            format!("{:<15} {}", "new_snapshot", report.new_snapshot),
            format!("{:<15} {}", "replayed", report.replayed),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| campaign | {} |\n| operation | {} |\n| command | {} |\n| prior_snapshot | {} |\n| new_snapshot | {} |\n| replayed | {} |",
            report.campaign,
            report.operation,
            report.command,
            report.prior_snapshot,
            report.new_snapshot,
            report.replayed
        )),
    }
}

pub(super) fn render_campaign_acceptance(
    report: &CampaignAcceptanceReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(campaign_acceptance_fields(report)
            .into_iter()
            .map(|(field, value)| format!("{field:<16} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in campaign_acceptance_fields(report) {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

fn campaign_acceptance_fields(report: &CampaignAcceptanceReport) -> Vec<(&'static str, String)> {
    match report {
        CampaignAcceptanceReport::Create {
            campaign,
            snapshot,
            lineage,
            active_policy,
            replayed,
            start,
            ..
        } => {
            let mut fields = vec![
                ("operation", "create".to_owned()),
                ("campaign", campaign.clone()),
                ("snapshot", snapshot.clone()),
                ("lineage", lineage.clone()),
                ("active_policy", active_policy.clone()),
                ("replayed", replayed.to_string()),
            ];
            if let Some(start) = start {
                fields.extend([
                    ("start_command", start.command.clone()),
                    ("start_prior_snapshot", start.prior_snapshot.clone()),
                    ("start_snapshot", start.new_snapshot.clone()),
                    ("start_replayed", start.replayed.to_string()),
                ]);
            }
            fields
        }
        CampaignAcceptanceReport::Derive {
            source_campaign,
            source_snapshot,
            campaign,
            new_snapshot,
            active_policy,
            replayed,
            ..
        } => vec![
            ("operation", "derive".to_owned()),
            ("source_campaign", source_campaign.clone()),
            ("source_snapshot", source_snapshot.clone()),
            ("campaign", campaign.clone()),
            ("new_snapshot", new_snapshot.clone()),
            ("active_policy", active_policy.clone()),
            ("replayed", replayed.to_string()),
        ],
        CampaignAcceptanceReport::Branch {
            campaign,
            request,
            prior_snapshot,
            new_snapshot,
            summary,
            replayed,
            ..
        } => {
            let mut fields = vec![
                ("operation", "branch".to_owned()),
                ("campaign", campaign.clone()),
                ("request", request.clone()),
                ("prior_snapshot", prior_snapshot.clone()),
                ("new_snapshot", new_snapshot.clone()),
            ];
            fields.extend(summary.human_fields());
            fields.push(("replayed", replayed.to_string()));
            fields
        }
    }
}

pub(super) fn render_campaign_page(
    report: &CampaignPageReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => render_campaign_page_table(report),
        OutputFormat::Markdown => Ok(render_campaign_page_markdown(report)),
    }
}

fn render_campaign_page_table(report: &CampaignPageReport) -> Result<String, CliError> {
    let mut lines = vec![
        format!("{:<11} {}", "campaign", report.campaign),
        format!("{:<11} {}", "snapshot", report.snapshot),
        format!(
            "{:<11} {}",
            "start_after",
            report.start_after.as_deref().unwrap_or("-")
        ),
        format!("{:<11} {}", "page_limit", report.page_limit),
        format!("{:<11} {}", "page_budget", report.page_budget),
        format!("{:<11} {}", "pages", report.pages_scanned),
        format!("{:<11} {}", "bytes", report.response_bytes),
        format!("{:<11} {}", "complete", report.complete),
        format!(
            "{:<11} {}",
            "next_after",
            report.next_after.as_deref().unwrap_or("-")
        ),
        format!("{:<11} {}", "entries", report.entries.len()),
        String::new(),
    ];
    match report.operation {
        "graph" => lines.push(String::from("key\tobject")),
        "choices" => lines.push(String::from("opportunity")),
        "frontier" => lines.push(String::from(
            "request\tbranch_point\tstate\tcompleted_visits\trequired_visits",
        )),
        "findings" => lines.push(String::from(
            "finding\tcluster\tkind\tfingerprint\tproperty\tfailure_class\tobservation\toccurrences\treproduction\tminimized",
        )),
        _ => return Err(backend_error("unknown campaign page report operation")),
    }
    for entry in &report.entries {
        lines.push(campaign_page_entry_row(entry, "\t"));
    }
    Ok(lines.join("\n"))
}

fn render_campaign_page_markdown(report: &CampaignPageReport) -> String {
    let mut output = format!(
        "| Field | Value |\n| --- | --- |\n| campaign | {} |\n| snapshot | {} |\n| start_after | {} |\n| page_limit | {} |\n| page_budget | {} |\n| pages | {} |\n| response_bytes | {} |\n| complete | {} |\n| next_after | {} |\n| entries | {} |\n\n",
        report.campaign,
        report.snapshot,
        report.start_after.as_deref().unwrap_or("-"),
        report.page_limit,
        report.page_budget,
        report.pages_scanned,
        report.response_bytes,
        report.complete,
        report.next_after.as_deref().unwrap_or("-"),
        report.entries.len()
    );
    match report.operation {
        "graph" => output.push_str("| Key | Object |\n| --- | --- |\n"),
        "choices" => output.push_str("| Opportunity |\n| --- |\n"),
        "frontier" => output.push_str(
            "| Request | Branch point | State | Completed visits | Required visits |\n| --- | --- | --- | --- | --- |\n",
        ),
        "findings" => output.push_str(
            "| Finding | Cluster | Kind | Fingerprint | Property | Failure class | Observation | Occurrences | Reproduction | Minimized |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
        ),
        _ => {}
    }
    for entry in &report.entries {
        output.push_str("| ");
        output.push_str(&campaign_page_entry_row(entry, " | "));
        output.push_str(" |\n");
    }
    output.trim_end().to_owned()
}

pub(super) fn campaign_page_entry_row(entry: &CampaignPageEntry, separator: &str) -> String {
    match entry {
        CampaignPageEntry::Graph { key, object } => format!("{key}{separator}{object}"),
        CampaignPageEntry::Choice { opportunity } => opportunity.clone(),
        CampaignPageEntry::Frontier {
            request,
            branch_point,
            state,
            completed_visits,
            required_visits,
        } => format!(
            "{request}{separator}{branch_point}{separator}{state}{separator}{}{separator}{}",
            completed_visits.map_or_else(|| "-".to_owned(), |value| value.to_string()),
            required_visits.map_or_else(|| "-".to_owned(), |value| value.to_string())
        ),
        CampaignPageEntry::Finding {
            finding,
            cluster,
            finding_kind,
            fingerprint,
            property,
            failure_class,
            observation,
            occurrences,
            reproduction,
            minimized,
        } => format!(
            "{finding}{separator}{cluster}{separator}{finding_kind}{separator}{fingerprint}{separator}{}{separator}{failure_class}{separator}{observation}{separator}{occurrences}{separator}{reproduction}{separator}{}",
            property.as_deref().unwrap_or("-"),
            minimized.as_deref().unwrap_or("-")
        ),
    }
}

pub(super) const fn finding_kind_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::PropertyViolation => "property-violation",
        FindingKind::Divergence => "divergence",
        FindingKind::Timeout => "timeout",
    }
}
