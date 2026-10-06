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
    CampaignSnapshotId, FindingId,
};
use crucible_daemon::CampaignLocalServiceMode;
use crucible_daemon::campaign_store_composition::{
    DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement,
};
use serde::Serialize;

use super::authoring::{read_bounded_bytes, write_new_bundle_with_boundary, write_new_record};
use super::replay::{CampaignReplayReport, render_campaign_replay, replay_finding_object};
use super::*;

#[path = "finding_bundle/exact.rs"]
mod exact;
use exact::{ExactFindingReplayReport, replay_exact_finding};
#[path = "finding_bundle/source_authentication.rs"]
mod source_authentication;
pub(crate) use source_authentication::FindingSourceAuthentication;
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

const MANIFEST_HEADER: &str = "crucible.campaign.finding-bundle.v2";
const MAX_LEDGER_BYTES: usize = 1024 * 1024 * 1024;
const MAX_ARCHIVE_DIRECTORY_DEPTH: usize = 8;
const MAX_ARCHIVE_DIRECTORIES: u64 = 4096;

#[derive(Clone, Copy)]
struct ArchivePhysicalLimits {
    files: u64,
    bytes: u64,
    directories: u64,
    depth: usize,
}

impl Default for ArchivePhysicalLimits {
    fn default() -> Self {
        Self {
            // Physical RAM descendants are separate from the compact archive
            // inventory. This is the same finite graph bound used by marking.
            files: crucible_campaign::MAX_CAMPAIGN_CLOSURE_OBJECTS as u64 + 1024,
            bytes: crucible_daemon::campaign_store_composition::CampaignArchiveRamLimits::default()
                .maximum_io_bytes,
            directories: MAX_ARCHIVE_DIRECTORIES,
            depth: MAX_ARCHIVE_DIRECTORY_DEPTH,
        }
    }
}

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
    occurrence_count: usize,
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

fn retain_materialized_guest_assets(
    assets: crucible_daemon::MaterializedFindingReplayGuestAssets,
) -> Result<Arc<crucible_daemon::MaterializedFindingReplayGuestAssets>, CliError> {
    let bytes = std::mem::size_of::<crucible_daemon::MaterializedFindingReplayGuestAssets>()
        + 2 * std::mem::size_of::<usize>();
    crucible_session::engine::owned_decode::charge_bytes(bytes as u64).map_err(|error| {
        backend_error(format!("finding asset custody admission failed: {error}"))
    })?;
    Ok(Arc::new(assets))
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
    let source = args
        .exact
        .then(|| FindingSourceAuthentication::open(cli, &args.input))
        .transpose()?;
    let _scope = source.as_ref().map(|source| source.decoding.enter());
    let bundle = match &source {
        Some(source) => {
            load_authenticated_bundle_in_workspace(&args.input, &source.workspace, &mut || Ok(()))?
        }
        None => load_authenticated_bundle(&args.input)?,
    };
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
    let exact_replay = source
        .map(|source| {
            replay_exact_finding(
                source,
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
        minimization: finding_bundle_minimization_report(finding)?,
        exact_replay,
    };
    render_verification(&report, format)
}

fn load_authenticated_bundle(input: &Path) -> Result<AuthenticatedFindingBundle, CliError> {
    load_authenticated_bundle_with_boundary(input, &mut || Ok(()))
}

fn load_authenticated_bundle_with_boundary(
    input: &Path,
    boundary: &mut dyn FnMut() -> Result<
        (),
        crucible_daemon::campaign_store_composition::CampaignArchiveBoundaryError,
    >,
) -> Result<AuthenticatedFindingBundle, CliError> {
    let temporary = private_bundle_tempdir()?;
    load_authenticated_bundle_in_workspace(input, temporary.path(), boundary)
}

fn load_authenticated_bundle_in_workspace(
    input: &Path,
    workspace: &Path,
    boundary: &mut dyn FnMut() -> Result<
        (),
        crucible_daemon::campaign_store_composition::CampaignArchiveBoundaryError,
    >,
) -> Result<AuthenticatedFindingBundle, CliError> {
    boundary()
        .map_err(|error| backend_error(format!("finding bundle preparation canceled: {error}")))?;
    validate_bundle_entries_with_boundary(input, boundary)?;
    let manifest = read_bounded_bytes(&input.join("manifest"), "finding bundle manifest", 512)?;
    let archive_id = parse_manifest(&manifest)?;
    let bytes = read_bounded_bytes(
        &input.join("ledger"),
        "finding bundle ledger",
        MAX_LEDGER_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| usage_error("finding bundle ledger is not valid UTF-8"))?;
    let store = crucible::LocalDagStore::new(workspace.join("evidence"));
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
        .inspect_campaign_archive_with_boundary(archive_id, boundary)
        .map_err(|error| backend_error(format!("finding archive is invalid: {error}")))?;
    if inspection.manifest().source_snapshot() != finding.snapshot {
        return Err(backend_error(
            "finding ledger and archive snapshot disagree",
        ));
    }
    let archived_finding = archive
        .inspect_archived_finding_with_boundary(archive_id, finding_id, boundary)
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
    let supervision = super::transfer_supervision::StandaloneArchiveOperation::start(
        crucible_api::host_operational::HostOperationClass::Transfer,
        args.host_transfer_timeout_ms,
    )?;
    let mut boundary = || supervision.boundary();
    let campaign = campaign_name(&args.name)?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid finding bundle snapshot: {error}")))?;
    let finding = FindingId::parse(&args.finding)
        .map_err(|error| usage_error(format!("invalid finding bundle finding: {error}")))?;
    let source = super::archive::prepare_owner(
        &args.source_state,
        &args.source_policy,
        &args.source_store,
        LOCAL_EXPORT_ENDPOINT,
        CampaignLocalServiceMode::ReadWrite,
    )?;
    let checkpoints = source
        .exact_checkpoint_store(args.maximum_checkpoint_bytes)
        .map_err(|error| backend_error(format!("source checkpoint store is invalid: {error}")))?;
    let mut exact_pins = super::archive::open_exact_pins(&args.source_state)?;
    let plan = source
        .plan_campaign_archive_with_exact_pins_with_boundary(
            campaign.clone(),
            snapshot,
            CampaignArchivePolicy::Executable,
            [],
            (&checkpoints, &mut exact_pins),
            &mut boundary,
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
    let mut publication_boundary = || {
        supervision
            .boundary()
            .map_err(|error| backend_error(format!("finding bundle publication canceled: {error}")))
    };
    let (output, ()) = write_new_bundle_with_boundary(
        &args.output,
        "finding bundle",
        |staged, _| {
            std::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o700))
                .map_err(CliError::Io)?;
            let archive = archive_repository(&staged.join("archive"));
            source
                .export_campaign_archive_to_repository_with_boundary(
                    &plan,
                    &archive,
                    DurabilityRequirement::new(1, false).map_err(|error| {
                        backend_error(format!("private archive durability is invalid: {error}"))
                    })?,
                    &mut boundary,
                )
                .map_err(|error| {
                    backend_error(format!("finding archive transfer failed: {error}"))
                })?;
            archive
                .inspect_archived_finding_with_boundary(plan.manifest_id(), finding, &mut boundary)
                .map_err(|error| {
                    backend_error(format!("transferred finding is invalid: {error}"))
                })?;
            write_new_record(
                &staged.join("manifest"),
                "finding bundle manifest",
                manifest.as_bytes(),
            )?;
            write_new_record(&staged.join("ledger"), "finding bundle ledger", &ledger)?;
            Ok(())
        },
        &mut publication_boundary,
    )?;
    supervision.complete()?;

    let report = FindingBundleExportReport {
        schema: "crucible.cli.campaign-finding-bundle-export.v2",
        operation: "export-finding-bundle",
        output: output.display().to_string(),
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        finding: finding.to_string(),
        archive_manifest: plan.manifest_id().to_string(),
        minimization: finding_bundle_minimization_report(&evidence)?,
        native_signature_verified: true,
    };
    render_export(&report, format)
}

fn validate_bundle_entries_with_boundary(
    directory: &Path,
    boundary: &mut dyn FnMut() -> Result<
        (),
        crucible_daemon::campaign_store_composition::CampaignArchiveBoundaryError,
    >,
) -> Result<(), CliError> {
    let allowed = BTreeSet::from(["manifest", "ledger", "archive"]);
    let entries = std::fs::read_dir(directory).map_err(CliError::Io)?;
    let mut found = BTreeSet::new();
    for entry in entries {
        boundary().map_err(|error| {
            backend_error(format!("finding bundle inspection canceled: {error}"))
        })?;
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
    validate_archive_tree_with_limits(
        &directory.join("archive"),
        ArchivePhysicalLimits::default(),
        boundary,
    )?;
    Ok(())
}

fn validate_archive_tree_with_limits(
    root: &Path,
    limits: ArchivePhysicalLimits,
    boundary: &mut dyn FnMut() -> Result<
        (),
        crucible_daemon::campaign_store_composition::CampaignArchiveBoundaryError,
    >,
) -> Result<(), CliError> {
    let mut stack = vec![std::fs::read_dir(root).map_err(CliError::Io)?];
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    let mut directories = 0_u64;
    while let Some(entries) = stack.last_mut() {
        boundary().map_err(|error| {
            backend_error(format!("finding bundle tree inspection canceled: {error}"))
        })?;
        let Some(entry) = entries.next() else {
            stack.pop();
            continue;
        };
        let entry = entry.map_err(CliError::Io)?;
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(CliError::Io)?;
        if metadata.is_dir() {
            directories = directories
                .checked_add(1)
                .ok_or_else(|| usage_error("finding bundle directory count overflowed"))?;
            if directories > limits.directories || stack.len() >= limits.depth {
                return Err(usage_error(
                    "finding bundle archive exceeds its directory/depth bound",
                ));
            }
            // One iterator per ancestor bounds discovery memory independently
            // of directory fanout and the number of RAM page objects.
            stack.push(std::fs::read_dir(entry.path()).map_err(CliError::Io)?);
        } else if metadata.is_file() {
            files = files
                .checked_add(1)
                .ok_or_else(|| usage_error("finding bundle file count overflowed"))?;
            bytes = bytes
                .checked_add(metadata.len())
                .ok_or_else(|| usage_error("finding bundle byte count overflowed"))?;
            if files > limits.files || bytes > limits.bytes {
                return Err(usage_error(
                    "finding bundle archive exceeds its physical object/byte budget",
                ));
            }
        } else {
            return Err(usage_error(
                "finding bundle archive contains a symlink or special file",
            ));
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

    fn physical_limits() -> ArchivePhysicalLimits {
        ArchivePhysicalLimits {
            files: 16,
            bytes: 128,
            directories: 4,
            depth: 4,
        }
    }

    #[test]
    fn physical_ram_objects_have_an_independent_finite_admission_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let defaults = ArchivePhysicalLimits::default();
        assert!(defaults.files > crucible_campaign::MAX_ARCHIVE_INVENTORY_ENTRIES as u64);
        assert_eq!(defaults.depth, 8);
        assert_eq!(defaults.directories, 4096);

        let directory = tempfile::tempdir()?;
        for index in 0..16 {
            std::fs::write(directory.path().join(index.to_string()), [index])?;
        }
        validate_archive_tree_with_limits(directory.path(), physical_limits(), &mut || Ok(()))?;

        let mut limits = physical_limits();
        limits.files = 15;
        assert!(
            validate_archive_tree_with_limits(directory.path(), limits, &mut || Ok(())).is_err()
        );
        limits.files = 16;
        limits.bytes = 15;
        assert!(
            validate_archive_tree_with_limits(directory.path(), limits, &mut || Ok(())).is_err()
        );
        Ok(())
    }

    #[test]
    fn directory_discovery_refuses_excess_depth_fanout_and_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::create_dir_all(directory.path().join("one/two"))?;
        std::fs::create_dir(directory.path().join("three"))?;

        let mut limits = physical_limits();
        limits.directories = 2;
        assert!(
            validate_archive_tree_with_limits(directory.path(), limits, &mut || Ok(())).is_err()
        );
        limits.directories = 4;
        limits.depth = 2;
        assert!(
            validate_archive_tree_with_limits(directory.path(), limits, &mut || Ok(())).is_err()
        );

        std::os::unix::fs::symlink("one", directory.path().join("link"))?;
        assert!(
            validate_archive_tree_with_limits(directory.path(), physical_limits(), &mut || Ok(()))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn physical_archive_inspection_observes_the_original_cancellation_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for index in 0..16 {
            std::fs::write(directory.path().join(index.to_string()), [])?;
        }
        let mut polls = 0;
        let result = validate_archive_tree_with_limits(
            directory.path(),
            physical_limits(),
            &mut || {
                polls += 1;
                if polls == 3 {
                    Err(crucible_daemon::campaign_store_composition::CampaignArchiveBoundaryError::Canceled)
                } else {
                    Ok(())
                }
            },
        );

        assert!(result.is_err());
        assert_eq!(polls, 3);
        Ok(())
    }

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
