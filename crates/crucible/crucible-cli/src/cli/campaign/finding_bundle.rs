//! Offline verification of one finding's authenticated native replay evidence.
//!
//! A portable bundle wraps a one-finding campaign findings ledger, the
//! content-addressed evidence it names, and the finding's executable archive
//! in an atomically installed directory. The evidence holds the snapshot and
//! occurrence proofs, exact canonical dependency responses, and four segmented
//! triage replays per occurrence, each as its own blob.
//!
//! ```text
//! manifest    crucible.campaign.finding-bundle.v3, archive ID, ledger hash
//! ledger      crucible.failure-triage.findings-ledger.v5 naming one finding
//! evidence/   content-addressed evidence records, chunks, and exchanges
//! archive/    directory-backed campaign object and reference store
//! ```
//!
//! The manifest text is:
//!
//! ```text
//! crucible.campaign.finding-bundle.v3
//! archive_manifest=<archive manifest ID>
//! ledger=<blake3 hex of the ledger file>
//! ```
//!
//! Verification reads the ledger under a small bound and authenticates the
//! finding as a fold over its occurrences, so its memory does not grow with
//! the occurrence count.

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
#[path = "finding_bundle/branch.rs"]
mod branch;
pub(crate) use branch::run_finding_bundle_branch;
#[path = "finding_bundle/minimization.rs"]
mod minimization;
use minimization::{FindingBundleMinimizationReport, finding_bundle_minimization_report};

const MANIFEST_HEADER: &str = "crucible.campaign.finding-bundle.v3";
/// A one-finding ledger manifest is a few hundred bytes.
const MAX_LEDGER_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: usize = 512;
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
    minimization: FindingBundleMinimizationReport,
    native_signature_verified: bool,
}

#[derive(Serialize)]
struct FindingBundleVerificationReport {
    schema: &'static str,
    operation: &'static str,
    native_signature_verified: bool,
    occurrence_count: u64,
    model_replay: CampaignReplayReport,
    minimization: FindingBundleMinimizationReport,
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
/// This command consumes only the bundle directory. The ledger loader checks
/// every snapshot, occurrence, and triage replay binding against the bundle's
/// evidence store; a temporary DAG store private to this process receives the
/// reproduction artifacts it derives.
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
    let (reproduction, artifact) = if minimized {
        finding
            .minimized_reproduction
            .as_ref()
            .zip(finding.minimized_artifact.as_ref())
            .ok_or_else(|| {
                usage_error("finding bundle has no authenticated minimized reproduction")
            })?
    } else {
        (&finding.reproduction, &finding.report.finding.artifact)
    };
    let model_replay = replay_finding_object(
        &finding.campaign,
        finding.snapshot,
        finding_id,
        minimized,
        reproduction,
        artifact,
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
        occurrence_count: finding.occurrence_count,
        model_replay,
        minimization: finding_bundle_minimization_report(finding)?,
        exact_replay,
    };
    render_verification(&report, format)
}

fn load_authenticated_bundle(input: &Path) -> Result<AuthenticatedFindingBundle, CliError> {
    validate_bundle_entries(input)?;
    let manifest = read_bounded_bytes(
        &input.join("manifest"),
        "finding bundle manifest",
        MAX_MANIFEST_BYTES,
    )?;
    let manifest = parse_manifest(&manifest)?;
    let ledger = read_bounded_bytes(
        &input.join("ledger"),
        "finding bundle ledger",
        MAX_LEDGER_BYTES,
    )?;
    if crucible_engine::ContentHash::from_bytes(&ledger) != manifest.ledger {
        return Err(usage_error(
            "finding bundle ledger differs from its manifest",
        ));
    }

    let temporary = private_bundle_tempdir()?;
    let artifacts = crucible_engine::LocalDagStore::new(temporary.path().join("artifacts"));
    let loaded = crate::cli_triage_debug::campaign_evidence::load_campaign_findings_ledger_bytes(
        &evidence_store(input),
        &artifacts,
        &ledger,
    )?;
    if loaded.evidence.finding_count() != 1 {
        return Err(backend_error(
            "finding bundle must contain exactly one finding",
        ));
    }
    let evidence = loaded.evidence.finding(0)?;
    let finding_id = evidence
        .finding
        .id()
        .map_err(|error| backend_error(format!("verified finding identity is invalid: {error}")))?;

    let archive_id = manifest.archive;
    let archive = archive_repository(&input.join("archive"));
    let inspection = archive
        .inspect_campaign_archive(archive_id)
        .map_err(|error| backend_error(format!("finding archive is invalid: {error}")))?;
    if inspection.manifest().source_snapshot() != evidence.snapshot {
        return Err(backend_error(
            "finding ledger and archive snapshot disagree",
        ));
    }
    let archived_finding = archive
        .inspect_archived_finding(archive_id, finding_id)
        .map_err(|error| backend_error(format!("finding archive lacks finding: {error}")))?;
    if archived_finding != evidence.finding {
        return Err(backend_error("finding ledger and archive record disagree"));
    }
    Ok(AuthenticatedFindingBundle {
        archive,
        archive_id,
        evidence,
    })
}

fn evidence_store(bundle: &Path) -> crucible_engine::LocalDagStore {
    crucible_engine::LocalDagStore::new(bundle.join("evidence"))
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
    let scope = crate::cli_triage_debug::campaign_evidence::CampaignFindingCaptureScope {
        principal,
        campaign: campaign.clone(),
        snapshot,
        finding,
    };
    let membership = crate::cli_triage_debug::campaign_evidence::find_campaign_finding_membership(
        &client, &scope,
    )?;
    let (output, minimization) = write_new_bundle(&args.output, "finding bundle", |staged, _| {
        std::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o700))
            .map_err(CliError::Io)?;

        // Capture straight into the staged evidence store, then authenticate
        // the staged bytes exactly as `verify` will before anything installs.
        let evidence = evidence_store(staged);
        let record =
            crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding_from_service(
                &client,
                &scope,
                &membership,
                &evidence,
            )?;
        let ledger = crate::cli_triage_debug::campaign_evidence::campaign_findings_ledger_bytes(
            &[(finding, record)],
        )?;
        let temporary = private_bundle_tempdir()?;
        let artifacts = crucible_engine::LocalDagStore::new(temporary.path().join("artifacts"));
        let loaded =
            crate::cli_triage_debug::campaign_evidence::load_campaign_findings_ledger_bytes(
                &evidence, &artifacts, &ledger,
            )?;
        let verified = loaded.evidence.finding(0)?;
        replay_finding_object(
            &campaign,
            snapshot,
            finding,
            false,
            &verified.reproduction,
            &verified.report.finding.artifact,
        )?;
        if let Some((minimized, artifact)) = verified
            .minimized_reproduction
            .as_ref()
            .zip(verified.minimized_artifact.as_ref())
        {
            replay_finding_object(&campaign, snapshot, finding, true, minimized, artifact)?;
        }
        crate::cli_triage_debug::campaign_evidence::sync_evidence_store(evidence.root())?;

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
        let manifest = format!(
            "{MANIFEST_HEADER}\narchive_manifest={}\nledger={}\n",
            plan.manifest_id(),
            crucible_engine::ContentHash::from_bytes(&ledger).to_hex()
        );
        write_new_record(
            &staged.join("manifest"),
            "finding bundle manifest",
            manifest.as_bytes(),
        )?;
        write_new_record(&staged.join("ledger"), "finding bundle ledger", &ledger)?;
        finding_bundle_minimization_report(&verified)
    })?;

    let report = FindingBundleExportReport {
        schema: "crucible.cli.campaign-finding-bundle-export.v2",
        operation: "export-finding-bundle",
        output: output.display().to_string(),
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        finding: finding.to_string(),
        archive_manifest: plan.manifest_id().to_string(),
        minimization,
        native_signature_verified: true,
    };
    render_export(&report, format)
}

fn validate_bundle_entries(directory: &Path) -> Result<(), CliError> {
    let allowed = BTreeSet::from(["manifest", "ledger", "evidence", "archive"]);
    let entries = std::fs::read_dir(directory).map_err(CliError::Io)?;
    let mut found = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(CliError::Io)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| usage_error("finding bundle contains an entry with a non-UTF-8 name"))?;
        let expected_directory = matches!(name, "archive" | "evidence");
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

/// Archive identity and ledger content address named by a bundle manifest.
struct FindingBundleManifest {
    archive: CampaignArchiveManifestId,
    ledger: crucible_engine::ContentHash,
}

fn parse_manifest(bytes: &[u8]) -> Result<FindingBundleManifest, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| usage_error("finding bundle manifest is not valid UTF-8"))?;
    let (archive, ledger) = text
        .strip_prefix(MANIFEST_HEADER)
        .and_then(|value| value.strip_prefix("\narchive_manifest="))
        .and_then(|value| value.strip_suffix('\n'))
        .and_then(|value| value.split_once("\nledger="))
        .ok_or_else(|| usage_error("unsupported finding bundle manifest"))?;
    let archive = CampaignArchiveManifestId::parse(archive)
        .map_err(|error| usage_error(format!("invalid finding archive identity: {error}")))?;
    let ledger = crucible_engine::ContentAddressedBlobRef::parse(
        "finding bundle ledger",
        &format!("blake3:{ledger}"),
    )
    .map(crucible_engine::ContentAddressedBlobRef::hash)
    .map_err(|error| usage_error(format!("invalid finding bundle ledger hash: {error}")))?;
    Ok(FindingBundleManifest { archive, ledger })
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
            "output={} campaign={} snapshot={} finding={} archive={} {} native-signature-verified=true",
            report.output,
            report.campaign,
            report.snapshot,
            report.finding,
            report.archive_manifest,
            report.minimization.table_summary()
        )),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| output | `{}` |\n| campaign | `{}` |\n| snapshot | `{}` |\n| finding | `{}` |\n| archive manifest | `{}` |{}\n| native signature verified | true |",
            report.output,
            report.campaign,
            report.snapshot,
            report.finding,
            report.archive_manifest,
            report.minimization.markdown_rows()
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
            "native-signature-verified=true occurrence-count={} {} {}{}",
            report.occurrence_count,
            render_campaign_replay(&report.model_replay, format)?,
            report.minimization.table_summary(),
            report.exact_replay.as_ref().map_or(String::new(), |exact| format!(
                " exact-role={} exact-reproduced={} quanta={} frontier={}",
                exact.role, exact.reproduced, exact.completed_quanta, exact.frontier_ticks
            ))
        )),
        OutputFormat::Markdown => Ok(format!(
            "{}\n| native signature verified | true |\n| occurrence count | {} |{}{}",
            render_campaign_replay(&report.model_replay, format)?,
            report.occurrence_count,
            report.minimization.markdown_rows(),
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
        let ledger = crucible_engine::ContentHash::from_bytes(b"ledger").to_hex();
        for rejected in [
            String::from("crucible.campaign.finding-bundle.v1\n"),
            String::from("crucible.campaign.finding-bundle.v2\narchive_manifest=bad\n"),
            String::from("crucible.campaign.finding-bundle.v3\n"),
            format!("crucible.campaign.finding-bundle.v3\narchive_manifest=bad\nledger={ledger}\n"),
            String::from("crucible.campaign.finding-bundle.v3\narchive_manifest=bad\nledger=bad\n"),
        ] {
            assert!(parse_manifest(rejected.as_bytes()).is_err(), "{rejected:?}");
        }
    }
}
