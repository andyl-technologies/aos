//! Offline verification of one finding's authenticated native replay evidence.
//!
//! The existing campaign finding ledger carries snapshot and occurrence proofs,
//! exact canonical dependency responses, and four segmented triage replays. A
//! portable bundle wraps one ledger and its executable archive in an atomically
//! installed directory.
//!
//! ```text
//! manifest    crucible.campaign.finding-bundle.v2 and archive ID
//! ledger      crucible.failure-triage.findings-ledger.v4
//! archive/    directory-backed campaign object and reference store
//! ```

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use crucible_campaign::{
    CampaignArchiveManifestId, CampaignArchivePolicy, CampaignClient, CampaignRepository,
    CampaignSnapshotId, FindingId, MAX_ARCHIVE_INVENTORY_ENTRIES,
};
use crucible_daemon::campaign_store_composition::{
    DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement, ImmutableBlobBackend,
};
use crucible_daemon::{CampaignLocalServiceMode, ExactCheckpointStore};
use serde::Serialize;

use super::authoring::{read_bounded_bytes, write_new_bundle, write_new_record};
use super::replay::{CampaignReplayReport, render_campaign_replay, replay_finding_object};
use super::*;

#[path = "finding_bundle/exact.rs"]
mod exact;
use exact::{ExactFindingReplayReport, replay_exact_finding};
#[path = "finding_bundle/midpoint.rs"]
mod midpoint;
pub(crate) use midpoint::run_finding_bundle_midpoint;
#[path = "finding_bundle/noncanonical.rs"]
mod noncanonical;
pub(crate) use noncanonical::run_finding_bundle_fork_write;

const MANIFEST_HEADER: &str = "crucible.campaign.finding-bundle.v2";
const MAX_LEDGER_BYTES: usize = 1024 * 1024 * 1024;
// One loose object contributes at most four path components; the margin
// covers archive metadata and directory administration entries.
const MAX_ARCHIVE_TREE_ENTRIES: usize = MAX_ARCHIVE_INVENTORY_ENTRIES.saturating_mul(5) + 1024;
const LOCAL_EXPORT_ENDPOINT: &str = "/tmp/crucible-finding-bundle-export.sock";

#[derive(Serialize)]
struct FindingBundleExportReport {
    schema: &'static str,
    operation: &'static str,
    output: String,
    campaign: String,
    snapshot: String,
    finding: String,
    archive_manifest: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    exact_replay: Option<ExactFindingReplayReport>,
}

struct AuthenticatedFindingBundle {
    archive: CampaignRepository,
    archive_id: CampaignArchiveManifestId,
    evidence: crate::cli_report::CampaignTriageFindingEvidence,
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
    cli: &Cli,
    args: &CampaignFindingBundleVerifyArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    let bundle = load_authenticated_bundle(&args.input)?;
    let finding = &bundle.evidence;
    let finding_id = finding
        .finding
        .id()
        .map_err(|error| backend_error(format!("verified finding identity is invalid: {error}")))?;
    let minimized = args.role.is_selected();
    let reproduction = if minimized {
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
        minimized,
        reproduction,
    )?;
    let exact_replay = args
        .exact
        .then(|| {
            replay_exact_finding(
                cli,
                &bundle.archive,
                bundle.archive_id,
                finding_id,
                args.role,
            )
        })
        .transpose()?;
    let report = FindingBundleVerificationReport {
        schema: "crucible.cli.campaign-finding-bundle-verification.v2",
        operation: "verify-finding-bundle",
        native_signature_verified: true,
        occurrence_count: finding.occurrence_proofs.len(),
        model_replay,
        exact_replay,
    };
    render_verification(&report, format)
}

fn load_authenticated_bundle(input: &Path) -> Result<AuthenticatedFindingBundle, CliError> {
    validate_bundle_entries(input)?;
    let manifest = read_bounded_bytes(&input.join("manifest"), "finding bundle manifest", 512)?;
    let archive_id = parse_manifest(&manifest)?;
    let bytes = read_bounded_bytes(
        &input.join("ledger"),
        "finding bundle ledger",
        MAX_LEDGER_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| usage_error("finding bundle ledger is not valid UTF-8"))?;
    let temporary = private_bundle_tempdir()?;
    let store = crucible::LocalDagStore::new(temporary.path().join("evidence"));
    let mut loaded =
        crate::cli_triage_debug::campaign_evidence::parse_campaign_findings_ledger_bytes(
            &store, &bytes, text,
        )?;
    let [finding] = loaded.campaign_evidence.as_mut_slice() else {
        return Err(backend_error(
            "finding bundle must contain exactly one finding",
        ));
    };
    let finding_id = finding
        .finding
        .id()
        .map_err(|error| backend_error(format!("verified finding identity is invalid: {error}")))?;
    let archive = archive_repository(&input.join("archive"));
    let inspection = archive
        .inspect_campaign_archive(archive_id)
        .map_err(|error| backend_error(format!("finding archive is invalid: {error}")))?;
    if inspection.manifest().source_snapshot() != finding.snapshot {
        return Err(backend_error(
            "finding ledger and archive snapshot disagree",
        ));
    }
    let archived_finding = archive
        .inspect_archived_finding(archive_id, finding_id)
        .map_err(|error| backend_error(format!("finding archive lacks finding: {error}")))?;
    if archived_finding != finding.finding {
        return Err(backend_error("finding ledger and archive record disagree"));
    }
    let evidence = loaded
        .campaign_evidence
        .pop()
        .ok_or_else(|| backend_error("finding bundle lost its authenticated finding"))?;
    Ok(AuthenticatedFindingBundle {
        archive,
        archive_id,
        evidence,
    })
}

fn private_bundle_tempdir() -> Result<tempfile::TempDir, CliError> {
    let directory = tempfile::tempdir().map_err(CliError::Io)?;
    // Tempdir mode follows host defaults; clamp it before writing guest assets or keys.
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .map_err(CliError::Io)?;
    Ok(directory)
}

/// Exports one retained finding through the existing authenticated triage ledger.
///
/// # Errors
///
/// Returns an error when the service evidence lacks a valid native signature,
/// its pure model reproduction cannot replay, or the new output cannot be
/// installed atomically.
pub(crate) fn export_finding_bundle(
    args: &CampaignFindingBundleExportArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    let campaign = campaign_name(&args.name)?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid finding bundle snapshot: {error}")))?;
    let finding = FindingId::parse(&args.finding)
        .map_err(|error| usage_error(format!("invalid finding bundle finding: {error}")))?;
    let source_graph =
        super::super::cli_campaign_store::load_campaign_store_graph(&args.source_store)?;
    let source_checkpoint_backend: Arc<dyn ImmutableBlobBackend> = source_graph;
    let checkpoints =
        ExactCheckpointStore::new(source_checkpoint_backend, args.maximum_checkpoint_bytes)
            .map_err(|error| {
                backend_error(format!("source checkpoint store is invalid: {error}"))
            })?;
    let source = super::archive::prepare_owner(
        &args.source_state,
        &args.source_policy,
        &args.source_store,
        LOCAL_EXPORT_ENDPOINT,
        CampaignLocalServiceMode::ReadWrite,
    )?;
    let mut exact_pins = super::archive::open_exact_pins(&args.source_state)?;
    let plan = source
        .plan_campaign_archive_with_exact_pins(
            campaign.clone(),
            snapshot,
            CampaignArchivePolicy::Executable,
            [],
            &checkpoints,
            &mut exact_pins,
        )
        .map_err(|error| backend_error(format!("finding archive planning failed: {error}")))?;
    let principal = source.campaign_export_principal().map_err(|error| {
        backend_error(format!("local finding principal is unauthorized: {error}"))
    })?;
    let service = source
        .campaign_read_service()
        .map_err(|error| backend_error(format!("local finding reader is unauthorized: {error}")))?;
    let client = CampaignClient::new(service);
    let evidence =
        crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding_from_service(
            &client,
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
    let manifest = format!(
        "{MANIFEST_HEADER}\narchive_manifest={}\n",
        plan.manifest_id()
    );
    let (output, ()) = write_new_bundle(&args.output, "finding bundle", |staged, _| {
        std::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o700))
            .map_err(CliError::Io)?;
        let archive = archive_repository(&staged.join("archive"));
        source
            .export_campaign_archive_to_repository(
                &plan,
                &archive,
                DurabilityRequirement::new(1, false).map_err(|error| {
                    backend_error(format!("private archive durability is invalid: {error}"))
                })?,
            )
            .map_err(|error| backend_error(format!("finding archive transfer failed: {error}")))?;
        archive
            .inspect_archived_finding(plan.manifest_id(), finding)
            .map_err(|error| backend_error(format!("transferred finding is invalid: {error}")))?;
        write_new_record(
            &staged.join("manifest"),
            "finding bundle manifest",
            manifest.as_bytes(),
        )?;
        write_new_record(&staged.join("ledger"), "finding bundle ledger", &ledger)?;
        Ok(())
    })?;

    let report = FindingBundleExportReport {
        schema: "crucible.cli.campaign-finding-bundle-export.v2",
        operation: "export-finding-bundle",
        output: output.display().to_string(),
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        finding: finding.to_string(),
        archive_manifest: plan.manifest_id().to_string(),
        minimized: evidence.minimized_reproduction.is_some(),
        native_signature_verified: true,
    };
    render_export(&report, format)
}

fn validate_bundle_entries(directory: &Path) -> Result<(), CliError> {
    let allowed = BTreeSet::from(["manifest", "ledger", "archive"]);
    let entries = std::fs::read_dir(directory).map_err(CliError::Io)?;
    let mut found = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(CliError::Io)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| usage_error("finding bundle contains an entry with a non-UTF-8 name"))?;
        let expected_directory = name == "archive";
        let file_type = entry.file_type().map_err(CliError::Io)?;
        if !allowed.contains(name)
            || (expected_directory && !file_type.is_dir())
            || (!expected_directory && !file_type.is_file())
        {
            return Err(usage_error("finding bundle contains an unexpected entry"));
        }
        found.insert(name.to_owned());
    }
    if found != allowed.into_iter().map(str::to_owned).collect() {
        return Err(usage_error("finding bundle is incomplete"));
    }
    validate_archive_tree(&directory.join("archive"))?;
    Ok(())
}

fn validate_archive_tree(root: &Path) -> Result<(), CliError> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries_seen = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).map_err(CliError::Io)? {
            let entry = entry.map_err(CliError::Io)?;
            entries_seen += 1;
            if entries_seen > MAX_ARCHIVE_TREE_ENTRIES {
                return Err(usage_error(
                    "finding bundle archive tree exceeds its entry limit",
                ));
            }
            let kind = entry.file_type().map_err(CliError::Io)?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if !kind.is_file() {
                return Err(usage_error(
                    "finding bundle archive contains a symlink or special file",
                ));
            }
        }
    }
    Ok(())
}

fn parse_manifest(bytes: &[u8]) -> Result<CampaignArchiveManifestId, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| usage_error("finding bundle manifest is not valid UTF-8"))?;
    let archive = text
        .strip_prefix(MANIFEST_HEADER)
        .and_then(|value| value.strip_prefix("\narchive_manifest="))
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| usage_error("unsupported finding bundle manifest"))?;
    CampaignArchiveManifestId::parse(archive)
        .map_err(|error| usage_error(format!("invalid finding archive identity: {error}")))
}

fn archive_repository(root: &Path) -> CampaignRepository {
    CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "finding-bundle",
            root.join("objects"),
        )),
        Arc::new(DirectoryRefBackend::new(root.join("refs"))),
    )
}

impl CampaignFindingBundleRole {
    const fn is_selected(self) -> bool {
        matches!(
            self,
            Self::MinimizationSelected | Self::VerificationSelected
        )
    }

    const fn campaign_role(self) -> crucible_campaign::CampaignFindingTriageReplayRole {
        use crucible_campaign::CampaignFindingTriageReplayRole as Role;
        match self {
            Self::MinimizationOriginal => Role::MinimizationOriginal,
            Self::MinimizationSelected => Role::MinimizationSelected,
            Self::VerificationOriginal => Role::VerificationOriginal,
            Self::VerificationSelected => Role::VerificationSelected,
        }
    }
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
            "output={} campaign={} snapshot={} finding={} archive={} minimized={} native-signature-verified=true",
            report.output,
            report.campaign,
            report.snapshot,
            report.finding,
            report.archive_manifest,
            report.minimized
        )),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| output | `{}` |\n| campaign | `{}` |\n| snapshot | `{}` |\n| finding | `{}` |\n| archive manifest | `{}` |\n| minimized | {} |\n| native signature verified | true |",
            report.output,
            report.campaign,
            report.snapshot,
            report.finding,
            report.archive_manifest,
            report.minimized
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
            "native-signature-verified=true occurrence-count={} {}{}",
            report.occurrence_count,
            render_campaign_replay(&report.model_replay, format)?,
            report.exact_replay.as_ref().map_or(String::new(), |exact| format!(
                " exact-role={} exact-reproduced={} quanta={} frontier={}",
                exact.role, exact.reproduced, exact.completed_quanta, exact.frontier_ticks
            ))
        )),
        OutputFormat::Markdown => Ok(format!(
            "{}\n| native signature verified | true |\n| occurrence count | {} |{}",
            render_campaign_replay(&report.model_replay, format)?,
            report.occurrence_count,
            report.exact_replay.as_ref().map_or(String::new(), |exact| format!(
                "\n| exact role | `{}` |\n| exact reproduced | {} |\n| exact quanta | {} |\n| exact frontier | {} |",
                exact.role, exact.reproduced, exact.completed_quanta, exact.frontier_ticks
            ))
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_manifest_accepts_only_current_executable_archive_format() {
        let old = b"crucible.campaign.finding-bundle.v1\n";
        assert!(parse_manifest(old).is_err());
        assert!(parse_manifest(b"crucible.campaign.finding-bundle.v2\n").is_err());
        assert!(
            parse_manifest(b"crucible.campaign.finding-bundle.v2\narchive_manifest=bad\n").is_err()
        );
    }
}
