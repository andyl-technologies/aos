//! Offline campaign archive planning, transfer, and inspection.
//!
//! A transfer emits the authenticated plan on stderr before copying and the
//! completion record on stdout. Physical bytes remain `null` when the composed
//! store does not expose per-object packed, compressed, or deduplicated size:
//!
//! ```json
//! {"schema":"crucible.cli.campaign-archive-plan.v1","phase":"pre-transfer","classes":[{"class":"exact-ram","logical_bytes":4096,"logical_replication_obligation_bytes":8192,"physical_bytes":null,"sensitive":true}],"sensitive_classes":["exact-ram"]}
//! ```

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use crucible_campaign::{
    ArchiveObjectEntry, CampaignArchiveInspection, CampaignArchivePlan, CampaignArchivePolicy,
    CampaignName, CampaignSnapshotId,
};
use crucible_daemon::campaign_store_composition::{
    ContentId, DurabilityRequirement, ImmutableBlobBackend, ObjectKind, RefName, SensitivityClass,
};
use crucible_daemon::{
    CampaignLocalServiceConfig, CampaignLocalServiceMode, CampaignLoopbackEndpointConfig,
    CampaignLoopbackServerConfig, DirectoryExactPinMaterializationStore,
    EXACT_PIN_MATERIALIZATION_DIRECTORY, ExactCheckpointStore, transfer_campaign_archive_durably,
};
use serde::Serialize;

use super::super::cli_campaign_store::{load_campaign_repository_store, load_campaign_store_graph};
use super::*;

const CAMPAIGN_ARCHIVE_PLAN_SCHEMA: &str = "crucible.cli.campaign-archive-plan.v1";
const CAMPAIGN_ARCHIVE_TRANSFER_SCHEMA: &str = "crucible.cli.campaign-archive-transfer.v1";
const CAMPAIGN_ARCHIVE_INSPECTION_SCHEMA: &str = "crucible.cli.campaign-archive-inspection.v1";
const UNUSED_SOURCE_ENDPOINT: &str = "/tmp/crucible-campaign-archive-source.sock";
const UNUSED_DESTINATION_ENDPOINT: &str = "/tmp/crucible-campaign-archive-destination.sock";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ArchiveByteClass {
    Metadata,
    Reproduction,
    ExactRam,
    ExactDisk,
    Log,
    Trace,
}

impl ArchiveByteClass {
    const ALL: [Self; 6] = [
        Self::Metadata,
        Self::Reproduction,
        Self::ExactRam,
        Self::ExactDisk,
        Self::Log,
        Self::Trace,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Reproduction => "reproduction",
            Self::ExactRam => "exact-ram",
            Self::ExactDisk => "exact-disk",
            Self::Log => "log",
            Self::Trace => "trace",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ArchiveByteAccumulator {
    objects: u64,
    logical_bytes: u64,
    sensitive: bool,
}

#[derive(Clone, Debug, Serialize)]
struct ArchiveByteReport {
    class: &'static str,
    objects: u64,
    logical_bytes: u64,
    logical_replication_obligation_bytes: u64,
    physical_bytes: Option<u64>,
    sensitive: bool,
}

#[derive(Clone, Debug, Serialize)]
struct CampaignArchivePlanReport {
    schema: &'static str,
    phase: &'static str,
    source_campaign: String,
    source_snapshot: String,
    manifest: String,
    policy: &'static str,
    archive: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    campaign: Option<String>,
    selected_objects: usize,
    omitted_objects: usize,
    transfer_objects: usize,
    minimum_durable_placements: u16,
    allow_deferred_write: bool,
    classes: Vec<ArchiveByteReport>,
    sensitive_classes: Vec<&'static str>,
}

#[derive(Serialize)]
struct CampaignArchiveTransferCompletionReport {
    schema: &'static str,
    phase: &'static str,
    manifest: String,
    archive: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    campaign: Option<String>,
    copied_objects: u64,
    copied_logical_bytes: u64,
    existing_objects: u64,
    authenticated: bool,
}

#[derive(Serialize)]
struct CampaignArchiveInspectionReport {
    schema: &'static str,
    phase: &'static str,
    manifest: String,
    source_snapshot: String,
    policy: &'static str,
    selected_objects: usize,
    omitted_objects: usize,
    omitted_inventory_verified: bool,
    classes: Vec<ArchiveByteReport>,
    sensitive_classes: Vec<&'static str>,
    authenticated: bool,
}

struct PreparedArchiveTransferBasis {
    source_campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    policy: CampaignArchivePolicy,
    retained_roots: Vec<ContentId>,
    destination_campaign: Option<CampaignName>,
    durability: DurabilityRequirement,
}

pub(super) fn run_campaign_archive(
    args: &CampaignArchiveArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    match &args.command {
        CampaignArchiveCommand::Transfer(transfer) => run_archive_transfer(transfer, format),
        CampaignArchiveCommand::Inspect(inspect) => run_archive_inspection(inspect, format),
    }
}

fn run_archive_transfer(
    args: &CampaignArchiveTransferArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    let basis = prepare_archive_transfer_basis(args)?;
    validate_distinct_owner_roots(&args.source_state, &args.destination_state)?;

    let source_graph = load_campaign_store_graph(&args.source_store)?;
    let source_checkpoint_backend: Arc<dyn ImmutableBlobBackend> = source_graph;
    let source_checkpoints =
        ExactCheckpointStore::new(source_checkpoint_backend, args.maximum_checkpoint_bytes)
            .map_err(|error| {
                archive_error(format!("source checkpoint store is invalid: {error}"))
            })?;
    let destination_graph = load_campaign_store_graph(&args.destination_store)?;
    let destination_checkpoint_backend: Arc<dyn ImmutableBlobBackend> = destination_graph;
    let destination_checkpoints = ExactCheckpointStore::new(
        destination_checkpoint_backend,
        args.maximum_checkpoint_bytes,
    )
    .map_err(|error| archive_error(format!("destination checkpoint store is invalid: {error}")))?;

    let mut source = prepare_owner(
        &args.source_state,
        &args.source_policy,
        &args.source_store,
        UNUSED_SOURCE_ENDPOINT,
        CampaignLocalServiceMode::ReadWrite,
    )?;
    let mut destination = prepare_owner(
        &args.destination_state,
        &args.destination_policy,
        &args.destination_store,
        UNUSED_DESTINATION_ENDPOINT,
        CampaignLocalServiceMode::ReadWrite,
    )?;
    let mut source_exact_pins = open_exact_pins(&args.source_state)?;
    let mut destination_exact_pins = open_exact_pins(&args.destination_state)?;
    let plan = source
        .plan_campaign_archive_with_exact_pins(
            basis.source_campaign.clone(),
            basis.snapshot,
            basis.policy,
            basis.retained_roots,
            &source_checkpoints,
            &mut source_exact_pins,
        )
        .map_err(|error| archive_error(format!("archive planning failed: {error}")))?;
    let plan_report = plan_report(
        &plan,
        &basis.source_campaign,
        &args.archive,
        basis.destination_campaign.as_ref(),
        basis.durability,
    )?;

    // This disclosure is emitted before transfer journals or destination bytes
    // are created, so an operator sees sensitive closure classes before copy.
    eprintln!("{}", render_plan_report(&plan_report, format)?);

    let mut source_endpoint = source.archive_transfer_endpoint();
    let mut destination_endpoint = destination
        .archive_transfer_endpoint_with_operational_checkpoints(
            &destination_checkpoints,
            &mut destination_exact_pins,
        );
    let transfer = transfer_campaign_archive_durably(
        &mut source_endpoint,
        &mut destination_endpoint,
        &plan,
        &args.archive,
        basis
            .destination_campaign
            .as_ref()
            .map(CampaignName::as_str),
        basis.durability,
    )
    .map_err(|error| archive_error(format!("archive transfer failed: {error}")))?;
    let completion = CampaignArchiveTransferCompletionReport {
        schema: CAMPAIGN_ARCHIVE_TRANSFER_SCHEMA,
        phase: "complete",
        manifest: plan.manifest_id().to_string(),
        archive: args.archive.clone(),
        campaign: basis
            .destination_campaign
            .as_ref()
            .map(|campaign| campaign.as_str().to_owned()),
        copied_objects: transfer.copied_objects,
        copied_logical_bytes: transfer.copied_bytes,
        existing_objects: transfer.existing_objects,
        authenticated: true,
    };
    render_transfer_completion(&completion, format)
}

fn run_archive_inspection(
    args: &CampaignArchiveInspectArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    validate_archive_name(&args.archive)?;
    let prepared = prepare_owner(
        &args.state,
        &args.policy,
        &args.store,
        UNUSED_DESTINATION_ENDPOINT,
        CampaignLocalServiceMode::ReadOnly,
    )?;
    let inspection = prepared
        .inspect_campaign_archive_ref(&args.archive)
        .map_err(|error| archive_error(format!("archive inspection failed: {error}")))?;
    render_inspection_report(&inspection_report(&inspection)?, format)
}

fn prepare_archive_transfer_basis(
    args: &CampaignArchiveTransferArgs,
) -> Result<PreparedArchiveTransferBasis, CliError> {
    let source_campaign = CampaignName::new(args.source_campaign.clone())
        .map_err(|error| usage_error(format!("invalid source campaign name: {error}")))?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid source snapshot ID: {error}")))?;
    validate_archive_name(&args.archive)?;
    let destination_campaign = args
        .campaign
        .as_ref()
        .map(|campaign| CampaignName::new(campaign.clone()))
        .transpose()
        .map_err(|error| usage_error(format!("invalid destination campaign name: {error}")))?;
    let policy = archive_policy(args.mode);
    if !args.retained_roots.is_empty() && policy != CampaignArchivePolicy::Mirror {
        return Err(usage_error("--retain is valid only with --mode mirror"));
    }
    if destination_campaign.is_some()
        && !matches!(
            policy,
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        )
    {
        return Err(usage_error(
            "--campaign requires --mode executable or --mode mirror",
        ));
    }
    let retained_roots = args
        .retained_roots
        .iter()
        .map(|content| {
            ContentId::parse(content)
                .map_err(|error| usage_error(format!("invalid retained content ID: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let durability =
        DurabilityRequirement::new(args.minimum_durable_placements, args.allow_deferred_write)
            .map_err(|error| usage_error(format!("invalid destination durability: {error}")))?;
    if args.maximum_checkpoint_bytes == 0 {
        return Err(usage_error(
            "--maximum-checkpoint-bytes must be greater than zero",
        ));
    }
    Ok(PreparedArchiveTransferBasis {
        source_campaign,
        snapshot,
        policy,
        retained_roots,
        destination_campaign,
        durability,
    })
}

fn prepare_owner(
    state: &Path,
    policy: &Path,
    store: &Path,
    endpoint_path: &str,
    mode: CampaignLocalServiceMode,
) -> Result<crucible_daemon::PreparedCampaignLocalService, CliError> {
    let endpoint = CampaignLoopbackEndpointConfig::new(
        endpoint_path,
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        0o600,
    )
    .map_err(|error| archive_error(format!("invalid internal owner endpoint: {error}")))?;
    let config = CampaignLocalServiceConfig::new(
        endpoint,
        state,
        policy,
        mode,
        CampaignLoopbackServerConfig::default(),
    )
    .map_err(|error| archive_error(format!("invalid campaign owner profile: {error}")))?;
    let repository_store = load_campaign_repository_store(store)?;
    config
        .prepare_with_store(repository_store)
        .map_err(|error| archive_error(format!("campaign owner acquisition failed: {error}")))
}

fn open_exact_pins(state: &Path) -> Result<DirectoryExactPinMaterializationStore, CliError> {
    DirectoryExactPinMaterializationStore::open(state.join(EXACT_PIN_MATERIALIZATION_DIRECTORY))
        .map_err(|error| archive_error(format!("exact-pin catalog open failed: {error}")))
}

fn plan_report(
    plan: &CampaignArchivePlan,
    source_campaign: &CampaignName,
    archive: &str,
    campaign: Option<&CampaignName>,
    durability: DurabilityRequirement,
) -> Result<CampaignArchivePlanReport, CliError> {
    let selected_bytes = plan
        .selected()
        .iter()
        .try_fold(0_u64, |total, entry| {
            total.checked_add(entry.logical_length())
        })
        .ok_or_else(|| archive_error("archive selected-byte total overflow"))?;
    let transfer_objects = plan.transfer_objects();
    let transfer_bytes = transfer_objects
        .iter()
        .try_fold(0_u64, |total, (_, bytes)| total.checked_add(*bytes))
        .ok_or_else(|| archive_error("archive transfer-byte total overflow"))?;
    let metadata_overhead = transfer_bytes
        .checked_sub(selected_bytes)
        .ok_or_else(|| archive_error("archive transfer-byte accounting is inconsistent"))?;
    let metadata_overhead_objects = transfer_objects
        .len()
        .checked_sub(plan.selected().len())
        .ok_or_else(|| archive_error("archive transfer-object accounting is inconsistent"))?;
    let classes = classify_entries(
        plan.selected(),
        metadata_overhead_objects,
        metadata_overhead,
        durability.minimum_durable_placements(),
    )?;
    let sensitive_classes = classes
        .iter()
        .filter(|class| class.sensitive && class.logical_bytes != 0)
        .map(|class| class.class)
        .collect();
    Ok(CampaignArchivePlanReport {
        schema: CAMPAIGN_ARCHIVE_PLAN_SCHEMA,
        phase: "pre-transfer",
        source_campaign: source_campaign.as_str().to_owned(),
        source_snapshot: plan.manifest().source_snapshot().to_string(),
        manifest: plan.manifest_id().to_string(),
        policy: policy_name(plan.manifest().policy()),
        archive: archive.to_owned(),
        campaign: campaign.map(|campaign| campaign.as_str().to_owned()),
        selected_objects: plan.selected().len(),
        omitted_objects: plan.omitted().len(),
        transfer_objects: transfer_objects.len(),
        minimum_durable_placements: durability.minimum_durable_placements(),
        allow_deferred_write: durability.allows_deferred_write(),
        classes,
        sensitive_classes,
    })
}

fn inspection_report(
    inspection: &CampaignArchiveInspection,
) -> Result<CampaignArchiveInspectionReport, CliError> {
    let classes = classify_entries(inspection.selected(), 0, 0, 1)?;
    let sensitive_classes = classes
        .iter()
        .filter(|class| class.sensitive && class.logical_bytes != 0)
        .map(|class| class.class)
        .collect();
    Ok(CampaignArchiveInspectionReport {
        schema: CAMPAIGN_ARCHIVE_INSPECTION_SCHEMA,
        phase: "inspection",
        manifest: inspection.manifest_id().to_string(),
        source_snapshot: inspection.manifest().source_snapshot().to_string(),
        policy: policy_name(inspection.manifest().policy()),
        selected_objects: inspection.selected().len(),
        omitted_objects: inspection.omitted().len(),
        omitted_inventory_verified: inspection.omitted_inventory_verified(),
        classes,
        sensitive_classes,
        authenticated: true,
    })
}

fn classify_entries(
    entries: &[ArchiveObjectEntry],
    metadata_overhead_objects: usize,
    metadata_overhead: u64,
    placements: u16,
) -> Result<Vec<ArchiveByteReport>, CliError> {
    let mut classes = BTreeMap::<ArchiveByteClass, ArchiveByteAccumulator>::new();
    for class in ArchiveByteClass::ALL {
        classes.insert(class, ArchiveByteAccumulator::default());
    }
    if metadata_overhead != 0 || metadata_overhead_objects != 0 {
        let metadata = classes
            .get_mut(&ArchiveByteClass::Metadata)
            .ok_or_else(|| archive_error("archive metadata class is unavailable"))?;
        metadata.objects = u64::try_from(metadata_overhead_objects)
            .map_err(|_| archive_error("archive metadata object count is unrepresentable"))?;
        metadata.logical_bytes = metadata_overhead;
    }
    for entry in entries {
        let class = entry_class(*entry);
        let aggregate = classes
            .get_mut(&class)
            .ok_or_else(|| archive_error("archive byte class is unavailable"))?;
        aggregate.objects = aggregate
            .objects
            .checked_add(1)
            .ok_or_else(|| archive_error("archive class object count overflow"))?;
        aggregate.logical_bytes = aggregate
            .logical_bytes
            .checked_add(entry.logical_length())
            .ok_or_else(|| archive_error("archive class byte count overflow"))?;
        aggregate.sensitive |= entry.sensitivity() != SensitivityClass::Metadata;
    }
    ArchiveByteClass::ALL
        .into_iter()
        .map(|class| {
            let aggregate = classes
                .remove(&class)
                .ok_or_else(|| archive_error("archive byte class is unavailable"))?;
            let logical_replication_obligation_bytes = aggregate
                .logical_bytes
                .checked_mul(u64::from(placements))
                .ok_or_else(|| archive_error("archive logical replication-byte count overflow"))?;
            Ok(ArchiveByteReport {
                class: class.name(),
                objects: aggregate.objects,
                logical_bytes: aggregate.logical_bytes,
                logical_replication_obligation_bytes,
                // Compressed, encrypted, deduplicated, or packed placements do
                // not expose per-object physical storage through transfer receipts.
                physical_bytes: None,
                sensitive: aggregate.sensitive,
            })
        })
        .collect()
}

const fn entry_class(entry: ArchiveObjectEntry) -> ArchiveByteClass {
    match entry.id().kind() {
        ObjectKind::RamExtent => ArchiveByteClass::ExactRam,
        ObjectKind::DiskExtent => ArchiveByteClass::ExactDisk,
        ObjectKind::Observation | ObjectKind::Finding => ArchiveByteClass::Log,
        ObjectKind::Trace => ArchiveByteClass::Trace,
        ObjectKind::Projection => ArchiveByteClass::Reproduction,
        _ => ArchiveByteClass::Metadata,
    }
}

fn validate_archive_name(name: &str) -> Result<(), CliError> {
    RefName::new(format!("archives/{name}"))
        .map(|_| ())
        .map_err(|error| usage_error(format!("invalid archive name: {error}")))
}

fn validate_distinct_owner_roots(source: &Path, destination: &Path) -> Result<(), CliError> {
    if source == destination {
        return Err(usage_error(
            "source and destination campaign state directories must differ",
        ));
    }
    Ok(())
}

const fn archive_policy(mode: CampaignArchiveMode) -> CampaignArchivePolicy {
    match mode {
        CampaignArchiveMode::Metadata => CampaignArchivePolicy::Metadata,
        CampaignArchiveMode::Findings => CampaignArchivePolicy::Findings,
        CampaignArchiveMode::Debug => CampaignArchivePolicy::Debug,
        CampaignArchiveMode::Executable => CampaignArchivePolicy::Executable,
        CampaignArchiveMode::Mirror => CampaignArchivePolicy::Mirror,
    }
}

const fn policy_name(policy: CampaignArchivePolicy) -> &'static str {
    match policy {
        CampaignArchivePolicy::Metadata => "metadata",
        CampaignArchivePolicy::Findings => "findings",
        CampaignArchivePolicy::Debug => "debug",
        CampaignArchivePolicy::Executable => "executable",
        CampaignArchivePolicy::Mirror => "mirror",
    }
}

fn render_plan_report(
    report: &CampaignArchivePlanReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl | OutputFormat::Json => {
            render_archive_json(report, format, "campaign archive plan")
        }
        OutputFormat::Table => {
            let mut lines = vec![
                format!("{:<32} {}", "phase", report.phase),
                format!("{:<32} {}", "source-campaign", report.source_campaign),
                format!("{:<32} {}", "source-snapshot", report.source_snapshot),
                format!("{:<32} {}", "manifest", report.manifest),
                format!("{:<32} {}", "policy", report.policy),
                format!("{:<32} {}", "archive", report.archive),
                format!(
                    "{:<32} {}",
                    "campaign",
                    report.campaign.as_deref().unwrap_or("-")
                ),
                format!(
                    "{:<32} {}",
                    "minimum-durable-placements", report.minimum_durable_placements
                ),
                format!(
                    "{:<32} {}",
                    "sensitive-classes",
                    report.sensitive_classes.join(",")
                ),
            ];
            lines.extend(report.classes.iter().map(render_class_table));
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut lines = vec![
                String::from("| field | value |"),
                String::from("|---|---|"),
                format!("| phase | `{}` |", report.phase),
                format!("| source campaign | `{}` |", report.source_campaign),
                format!("| source snapshot | `{}` |", report.source_snapshot),
                format!("| manifest | `{}` |", report.manifest),
                format!("| policy | `{}` |", report.policy),
                format!("| archive | `{}` |", report.archive),
                format!(
                    "| campaign | {} |",
                    report.campaign.as_deref().unwrap_or("-")
                ),
                format!(
                    "| sensitive classes | {} |",
                    report.sensitive_classes.join(", ")
                ),
            ];
            lines.extend(report.classes.iter().map(render_class_markdown));
            Ok(lines.join("\n"))
        }
    }
}

fn render_transfer_completion(
    report: &CampaignArchiveTransferCompletionReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl | OutputFormat::Json => {
            render_archive_json(report, format, "campaign archive transfer")
        }
        OutputFormat::Table => Ok([
            format!("{:<24} {}", "phase", report.phase),
            format!("{:<24} {}", "manifest", report.manifest),
            format!("{:<24} {}", "archive", report.archive),
            format!(
                "{:<24} {}",
                "campaign",
                report.campaign.as_deref().unwrap_or("-")
            ),
            format!("{:<24} {}", "copied-objects", report.copied_objects),
            format!(
                "{:<24} {}",
                "copied-logical-bytes", report.copied_logical_bytes
            ),
            format!("{:<24} {}", "existing-objects", report.existing_objects),
            format!("{:<24} {}", "authenticated", report.authenticated),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok([
            String::from("| field | value |"),
            String::from("|---|---|"),
            format!("| phase | `{}` |", report.phase),
            format!("| manifest | `{}` |", report.manifest),
            format!("| archive | `{}` |", report.archive),
            format!(
                "| campaign | {} |",
                report.campaign.as_deref().unwrap_or("-")
            ),
            format!("| copied objects | {} |", report.copied_objects),
            format!("| copied logical bytes | {} |", report.copied_logical_bytes),
            format!("| existing objects | {} |", report.existing_objects),
            format!("| authenticated | {} |", report.authenticated),
        ]
        .join("\n")),
    }
}

fn render_inspection_report(
    report: &CampaignArchiveInspectionReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl | OutputFormat::Json => {
            render_archive_json(report, format, "campaign archive inspection")
        }
        OutputFormat::Table => {
            let mut lines = vec![
                format!("{:<32} {}", "phase", report.phase),
                format!("{:<32} {}", "manifest", report.manifest),
                format!("{:<32} {}", "source-snapshot", report.source_snapshot),
                format!("{:<32} {}", "policy", report.policy),
                format!("{:<32} {}", "selected-objects", report.selected_objects),
                format!("{:<32} {}", "omitted-objects", report.omitted_objects),
                format!(
                    "{:<32} {}",
                    "omitted-inventory-verified", report.omitted_inventory_verified
                ),
                format!(
                    "{:<32} {}",
                    "sensitive-classes",
                    report.sensitive_classes.join(",")
                ),
                format!("{:<32} {}", "authenticated", report.authenticated),
            ];
            lines.extend(report.classes.iter().map(render_class_table));
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut lines = vec![
                String::from("| field | value |"),
                String::from("|---|---|"),
                format!("| phase | `{}` |", report.phase),
                format!("| manifest | `{}` |", report.manifest),
                format!("| source snapshot | `{}` |", report.source_snapshot),
                format!("| policy | `{}` |", report.policy),
                format!("| selected objects | {} |", report.selected_objects),
                format!("| omitted objects | {} |", report.omitted_objects),
                format!(
                    "| omitted inventory verified | {} |",
                    report.omitted_inventory_verified
                ),
                format!(
                    "| sensitive classes | {} |",
                    report.sensitive_classes.join(", ")
                ),
                format!("| authenticated | {} |", report.authenticated),
            ];
            lines.extend(report.classes.iter().map(render_class_markdown));
            Ok(lines.join("\n"))
        }
    }
}

fn render_archive_json(
    report: &impl Serialize,
    format: OutputFormat,
    label: &str,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| archive_error(format!("{label} JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| archive_error(format!("{label} JSON encoding failed: {error}"))),
        OutputFormat::Table | OutputFormat::Markdown => Err(archive_error(format!(
            "{label} JSON renderer received a human output format"
        ))),
    }
}

fn render_class_table(class: &ArchiveByteReport) -> String {
    format!(
        "{:<32} objects={} logical-bytes={} logical-replication-obligation-bytes={} physical-bytes={} sensitive={}",
        format!("class:{}", class.class),
        class.objects,
        class.logical_bytes,
        class.logical_replication_obligation_bytes,
        class
            .physical_bytes
            .map_or_else(|| String::from("unknown"), |bytes| bytes.to_string()),
        class.sensitive,
    )
}

fn render_class_markdown(class: &ArchiveByteReport) -> String {
    format!(
        "| class `{}` | objects={} / logical bytes={} / logical replication obligation bytes={} / physical bytes={} / sensitive={} |",
        class.class,
        class.objects,
        class.logical_bytes,
        class.logical_replication_obligation_bytes,
        class
            .physical_bytes
            .map_or_else(|| String::from("unknown"), |bytes| bytes.to_string()),
        class.sensitive,
    )
}

fn archive_error(message: impl Into<String>) -> CliError {
    backend_error(message.into())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- assertions localize failures in compact rendering fixtures.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn transfer_args() -> CampaignArchiveTransferArgs {
        let snapshot_content =
            ContentId::for_bytes(ObjectKind::CampaignSnapshot, 3, b"archive-cli-snapshot");
        CampaignArchiveTransferArgs {
            source_state: "/tmp/source-state".into(),
            source_policy: "/tmp/source-policy".into(),
            source_store: "/tmp/source-store".into(),
            source_campaign: "source".to_owned(),
            snapshot: format!("crucible.campaign.snapshot@{}", snapshot_content.encode()),
            mode: CampaignArchiveMode::Metadata,
            retained_roots: Vec::new(),
            destination_state: "/tmp/destination-state".into(),
            destination_policy: "/tmp/destination-policy".into(),
            destination_store: "/tmp/destination-store".into(),
            archive: "archive".to_owned(),
            campaign: None,
            minimum_durable_placements: 1,
            allow_deferred_write: false,
            maximum_checkpoint_bytes: 1024,
        }
    }

    #[test]
    fn archive_names_and_policy_relationships_fail_before_deployment_io() {
        let mut args = transfer_args();
        args.archive = "../escape".to_owned();
        assert!(prepare_archive_transfer_basis(&args).is_err());

        let mut args = transfer_args();
        args.retained_roots.push(String::from("invalid"));
        assert!(prepare_archive_transfer_basis(&args).is_err());

        let mut args = transfer_args();
        args.campaign = Some("imported".to_owned());
        assert!(prepare_archive_transfer_basis(&args).is_err());
    }

    #[test]
    fn archive_mode_parser_rejects_unknown_policy_without_deployment_io() {
        let parsed = Cli::try_parse_from([
            "crucible",
            "campaign",
            "archive",
            "transfer",
            "--source-state",
            "/tmp/source-state",
            "--source-policy",
            "/tmp/source-policy",
            "--source-store",
            "/tmp/source-store",
            "--source-campaign",
            "source",
            "--snapshot",
            "invalid-but-not-read",
            "--mode",
            "complete",
            "--destination-state",
            "/tmp/destination-state",
            "--destination-policy",
            "/tmp/destination-policy",
            "--destination-store",
            "/tmp/destination-store",
            "--archive",
            "archive",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn pre_transfer_report_discloses_unknown_physical_bytes_and_sensitive_classes() {
        let report = CampaignArchivePlanReport {
            schema: CAMPAIGN_ARCHIVE_PLAN_SCHEMA,
            phase: "pre-transfer",
            source_campaign: "source".to_owned(),
            source_snapshot: "snapshot".to_owned(),
            manifest: "manifest".to_owned(),
            policy: "executable",
            archive: "archive".to_owned(),
            campaign: Some("imported".to_owned()),
            selected_objects: 2,
            omitted_objects: 0,
            transfer_objects: 4,
            minimum_durable_placements: 2,
            allow_deferred_write: false,
            classes: vec![ArchiveByteReport {
                class: "exact-ram",
                objects: 1,
                logical_bytes: 4096,
                logical_replication_obligation_bytes: 8192,
                physical_bytes: None,
                sensitive: true,
            }],
            sensitive_classes: vec!["exact-ram"],
        };
        let rendered =
            render_plan_report(&report, OutputFormat::Jsonl).expect("render pre-transfer report");
        let value: serde_json::Value =
            serde_json::from_str(&rendered).expect("decode pre-transfer report");

        assert_eq!(value["phase"], "pre-transfer");
        assert_eq!(value["classes"][0]["logical_bytes"], 4096);
        assert_eq!(
            value["classes"][0]["logical_replication_obligation_bytes"],
            8192
        );
        assert!(value["classes"][0]["physical_bytes"].is_null());
        assert_eq!(value["sensitive_classes"][0], "exact-ram");
    }
}
