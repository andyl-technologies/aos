//! Offline verification of one finding's authenticated native replay evidence.
//!
//! The existing campaign finding ledger carries snapshot and occurrence proofs,
//! exact canonical dependency responses, and four segmented triage replays. A
//! portable bundle wraps one such ledger in an atomically installed directory.
//!
//! ```text
//! manifest    crucible.campaign.finding-bundle.v1
//! ledger      crucible.failure-triage.findings-ledger.v4
//! ```

use std::collections::BTreeSet;
use std::path::Path;

use crucible_campaign::{
    CampaignClient, CampaignFindingOccurrenceService, CampaignPrincipal,
    CampaignServiceFailureSource, CampaignSnapshotId, FindingId,
};
use serde::Serialize;

use super::authoring::{read_bounded_bytes, write_new_bundle, write_new_record};
use super::replay::{CampaignReplayReport, render_campaign_replay, replay_finding_object};
use super::*;

const MANIFEST: &[u8] = b"crucible.campaign.finding-bundle.v1\n";
const MAX_LEDGER_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Serialize)]
struct FindingBundleExportReport {
    schema: &'static str,
    operation: &'static str,
    output: String,
    campaign: String,
    snapshot: String,
    finding: String,
    minimized: bool,
    native_signature_verified: bool,
}

#[derive(Serialize)]
struct FindingBundleVerificationReport {
    schema: &'static str,
    operation: &'static str,
    native_signature_verified: bool,
    occurrence_count: usize,
    model_replay: CampaignReplayReport,
}

/// Verifies an exported finding's native signature and pure model reproduction.
///
/// This command consumes only the bundle directory. The temporary DAG store is
/// private to this process and holds decoded evidence while the existing ledger
/// verifier checks every snapshot, occurrence, and triage replay binding.
///
/// # Errors
///
/// Returns an error for missing, extra, malformed, or unauthenticated bundle
/// material, signature drift, or an invalid pure model replay.
pub(crate) fn verify_exported_finding(
    args: &CampaignFindingBundleVerifyArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    validate_bundle_entries(&args.input)?;
    let manifest =
        read_bounded_bytes(&args.input.join("manifest"), "finding bundle manifest", 128)?;
    if manifest != MANIFEST {
        return Err(usage_error("unsupported finding bundle manifest"));
    }
    let bytes = read_bounded_bytes(
        &args.input.join("ledger"),
        "finding bundle ledger",
        MAX_LEDGER_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| usage_error("finding bundle ledger is not valid UTF-8"))?;
    let temporary = tempfile::tempdir().map_err(CliError::Io)?;
    let store = crucible::LocalDagStore::new(temporary.path().join("evidence"));
    let loaded = crate::cli_triage_debug::campaign_evidence::parse_campaign_findings_ledger_bytes(
        &store, &bytes, text,
    )?;
    let [finding] = loaded.campaign_evidence.as_slice() else {
        return Err(backend_error(
            "finding bundle must contain exactly one finding",
        ));
    };
    let finding_id = finding
        .finding
        .id()
        .map_err(|error| backend_error(format!("verified finding identity is invalid: {error}")))?;
    let reproduction = if args.minimized {
        finding.minimized_reproduction.as_ref().ok_or_else(|| {
            usage_error("finding bundle has no authenticated minimized reproduction")
        })?
    } else {
        &finding.reproduction
    };
    let model_replay = replay_finding_object(
        &finding.campaign,
        finding.snapshot,
        finding_id,
        args.minimized,
        reproduction,
    )?;
    let report = FindingBundleVerificationReport {
        schema: "crucible.cli.campaign-finding-bundle-verification.v1",
        operation: "verify-finding-bundle",
        native_signature_verified: true,
        occurrence_count: finding.occurrence_proofs.len(),
        model_replay,
    };
    render_verification(&report, format)
}

/// Exports one retained finding through the existing authenticated triage ledger.
///
/// # Errors
///
/// Returns an error when the service evidence lacks a valid native signature,
/// its pure model reproduction cannot replay, or the new output cannot be
/// installed atomically.
pub(crate) fn export_finding_bundle<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    args: &CampaignFindingBundleExportArgs,
    format: OutputFormat,
) -> Result<String, CliError>
where
    S: CampaignFindingOccurrenceService,
    S::Error: CampaignServiceFailureSource,
{
    let campaign = campaign_name(&args.name)?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid finding bundle snapshot: {error}")))?;
    let finding = FindingId::parse(&args.finding)
        .map_err(|error| usage_error(format!("invalid finding bundle finding: {error}")))?;
    let evidence =
        crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding_from_service(
            client,
            principal,
            campaign.clone(),
            snapshot,
            finding,
        )?;
    replay_finding_object(&campaign, snapshot, finding, false, &evidence.reproduction)?;
    if let Some(minimized) = &evidence.minimized_reproduction {
        replay_finding_object(&campaign, snapshot, finding, true, minimized)?;
    }
    let ledger = crate::cli_triage_debug::campaign_evidence::campaign_findings_ledger_bytes(
        std::slice::from_ref(&evidence),
    )?;
    let (output, ()) = write_new_bundle(&args.output, "finding bundle", |staged, _| {
        write_new_record(
            &staged.join("manifest"),
            "finding bundle manifest",
            MANIFEST,
        )?;
        write_new_record(&staged.join("ledger"), "finding bundle ledger", &ledger)?;
        Ok(())
    })?;

    let report = FindingBundleExportReport {
        schema: "crucible.cli.campaign-finding-bundle-export.v1",
        operation: "export-finding-bundle",
        output: output.display().to_string(),
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        finding: finding.to_string(),
        minimized: evidence.minimized_reproduction.is_some(),
        native_signature_verified: true,
    };
    render_export(&report, format)
}

fn validate_bundle_entries(directory: &Path) -> Result<(), CliError> {
    let allowed = BTreeSet::from(["manifest", "ledger"]);
    let entries = std::fs::read_dir(directory).map_err(CliError::Io)?;
    let mut found = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(CliError::Io)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| usage_error("finding bundle contains an entry with a non-UTF-8 name"))?;
        if !allowed.contains(name) || !entry.file_type().map_err(CliError::Io)?.is_file() {
            return Err(usage_error("finding bundle contains an unexpected entry"));
        }
        found.insert(name.to_owned());
    }
    if found != allowed.into_iter().map(str::to_owned).collect() {
        return Err(usage_error("finding bundle is incomplete"));
    }
    Ok(())
}

fn render_export(
    report: &FindingBundleExportReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            serde_json::to_string(report).map_err(|error| {
                backend_error(format!(
                    "finding bundle export report encoding failed: {error}"
                ))
            })
        }
        OutputFormat::Table => Ok(format!(
            "output={} campaign={} snapshot={} finding={} minimized={} native-signature-verified=true",
            report.output, report.campaign, report.snapshot, report.finding, report.minimized
        )),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| output | `{}` |\n| campaign | `{}` |\n| snapshot | `{}` |\n| finding | `{}` |\n| minimized | {} |\n| native signature verified | true |",
            report.output, report.campaign, report.snapshot, report.finding, report.minimized
        )),
    }
}

fn render_verification(
    report: &FindingBundleVerificationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            serde_json::to_string(report).map_err(|error| {
                backend_error(format!(
                    "finding bundle verification report encoding failed: {error}"
                ))
            })
        }
        OutputFormat::Table => Ok(format!(
            "native-signature-verified=true occurrence-count={} {}",
            report.occurrence_count,
            render_campaign_replay(&report.model_replay, format)?
        )),
        OutputFormat::Markdown => Ok(format!(
            "{}\n| native signature verified | true |\n| occurrence count | {} |",
            render_campaign_replay(&report.model_replay, format)?,
            report.occurrence_count
        )),
    }
}
