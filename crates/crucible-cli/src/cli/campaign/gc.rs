//! Authenticated inspection and stopped-owner campaign-store maintenance.

use super::*;

use std::path::{Component, Path};

use crucible_cas::content_store::{
    BackendCapabilities, ContentId, ImmutableBlobBackend, StoreGraph, StoreNodeKind,
};
use crucible_daemon::{
    CampaignGcApplyStatus, CampaignGcJournalCreateDisposition, CampaignGcJournalPhase,
    CampaignLocalServiceConfig, CampaignLocalServiceMode, CampaignLoopbackEndpointConfig,
    CampaignLoopbackServerConfig, DirectoryAssignmentLedger, DirectoryCampaignGcJournal,
};
use serde::Serialize;

use crate::cli_campaign_store::{
    MAX_STORE_VERIFY_LOGICAL_BYTES, MAX_STORE_VERIFY_PLACEMENTS, load_campaign_repository_store,
    load_campaign_store_graph, verify_campaign_store_inventory,
};

const CAMPAIGN_GC_REPORT_SCHEMA: &str = "crucible.cli.campaign-store-gc.v1";
const STORE_STATUS_REPORT_SCHEMA: &str = "crucible.cli.store-status.v1";
const STORE_ENSURE_REPORT_SCHEMA: &str = "crucible.cli.store-ensure.v1";
const STORE_VERIFY_REPORT_SCHEMA: &str = "crucible.cli.store-verify.v1";
const MAXIMUM_OWNER_PATH_BYTES: usize = 4_095;
const UNUSED_GC_ENDPOINT: &str = "/tmp/crucible-campaign-gc-owner.sock";

#[derive(Serialize)]
pub(super) struct CampaignStoreGcReport {
    schema: &'static str,
    operation: &'static str,
    plan: String,
    journal: String,
    journal_disposition: &'static str,
    phase: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    apply_status: Option<&'static str>,
    roots: usize,
    reachable_objects: Option<u64>,
    candidates: u64,
    candidate_logical_bytes: u64,
    physical: Vec<CampaignStoreGcPhysicalReport>,
}

pub(super) fn run_store_invocation(cli: &Cli, args: &StoreArgs) -> Result<(), CliError> {
    let rendered = match &args.command {
        StoreCommand::Status(status) => run_store_status(status, cli.output_format())?,
        StoreCommand::Ensure(ensure) => run_store_ensure(ensure, cli.output_format())?,
        StoreCommand::Verify(verify) => run_store_verify(verify, cli.output_format())?,
        StoreCommand::Gc(gc) => run_campaign_store_gc(gc, cli.output_format())?,
    };
    println!("{rendered}");
    Ok(())
}

#[derive(Serialize)]
struct StoreStatusReport {
    schema: &'static str,
    configuration: String,
    root: String,
    admitted_kinds: Vec<String>,
    nodes: Vec<StoreStatusNode>,
}

#[derive(Serialize)]
struct StoreStatusNode {
    id: String,
    kind: &'static str,
    capabilities: StoreStatusCapabilities,
}

#[derive(Clone, Copy, Serialize)]
struct StoreStatusCapabilities {
    durable: bool,
    deferred_write: bool,
    range_read: bool,
    streaming_read: bool,
    conditional_create: bool,
    streaming_put: bool,
    repair_inventory: bool,
    planned_delete: bool,
}

impl From<BackendCapabilities> for StoreStatusCapabilities {
    fn from(capabilities: BackendCapabilities) -> Self {
        Self {
            durable: capabilities.durable,
            deferred_write: capabilities.deferred_write,
            range_read: capabilities.range_read,
            streaming_read: capabilities.streaming_read,
            conditional_create: capabilities.conditional_create,
            streaming_put: capabilities.streaming_put,
            repair_inventory: capabilities.repair_inventory,
            planned_delete: capabilities.planned_delete,
        }
    }
}

#[derive(Serialize)]
struct StoreEnsureReport {
    schema: &'static str,
    configuration: String,
    content: String,
    logical_bytes: u64,
    authenticated: bool,
}

#[derive(Serialize)]
struct StoreVerifyReport {
    schema: &'static str,
    configuration: String,
    maximum_placements: u64,
    maximum_logical_bytes: u64,
    placements: u64,
    logical_bytes: u64,
    physical: Vec<StoreVerifyPhysicalReport>,
    authenticated: bool,
}

#[derive(Serialize)]
struct StoreVerifyPhysicalReport {
    backend: String,
    generation: String,
    placements: u64,
    logical_bytes: u64,
}

fn run_store_status(args: &StoreStatusArgs, format: OutputFormat) -> Result<String, CliError> {
    let graph = load_campaign_store_graph(&args.deployment)?;
    let report = store_status_report(&graph);
    render_store_status(&report, format)
}

fn run_store_ensure(args: &StoreEnsureArgs, format: OutputFormat) -> Result<String, CliError> {
    let content = ContentId::parse(&args.content)
        .map_err(|error| usage_error(format!("invalid content ID: {error}")))?;
    let graph = load_campaign_store_graph(&args.deployment)?;
    let handle = graph
        .read(content, None)
        .map_err(|error| maintenance_error(format!("store ensure read failed: {error}")))?;
    let logical_bytes = handle.logical_length();
    handle.copy_to(&mut std::io::sink()).map_err(|error| {
        maintenance_error(format!("store ensure authentication failed: {error}"))
    })?;
    let report = StoreEnsureReport {
        schema: STORE_ENSURE_REPORT_SCHEMA,
        configuration: store_configuration(&graph),
        content: content.encode(),
        logical_bytes,
        authenticated: true,
    };
    render_store_ensure(&report, format)
}

fn run_store_verify(args: &StoreVerifyArgs, format: OutputFormat) -> Result<String, CliError> {
    let verified = verify_campaign_store_inventory(&args.deployment)?;
    let report = StoreVerifyReport {
        schema: STORE_VERIFY_REPORT_SCHEMA,
        configuration: encode_bytes(&verified.configuration),
        maximum_placements: MAX_STORE_VERIFY_PLACEMENTS,
        maximum_logical_bytes: MAX_STORE_VERIFY_LOGICAL_BYTES,
        placements: verified.placements,
        logical_bytes: verified.logical_bytes,
        physical: verified
            .physical
            .into_iter()
            .map(|physical| StoreVerifyPhysicalReport {
                backend: physical.backend,
                generation: physical.generation,
                placements: physical.placements,
                logical_bytes: physical.logical_bytes,
            })
            .collect(),
        authenticated: true,
    };
    render_store_verify(&report, format)
}

fn store_status_report(graph: &StoreGraph) -> StoreStatusReport {
    StoreStatusReport {
        schema: STORE_STATUS_REPORT_SCHEMA,
        configuration: store_configuration(graph),
        root: graph.root_id().as_str().to_owned(),
        admitted_kinds: graph
            .admitted_kinds()
            .iter()
            .map(|kind| kind.as_str().to_owned())
            .collect(),
        nodes: graph
            .describe()
            .iter()
            .map(|node| StoreStatusNode {
                id: node.id.as_str().to_owned(),
                kind: store_node_kind(node.kind),
                capabilities: node.capabilities.into(),
            })
            .collect(),
    }
}

fn store_configuration(graph: &StoreGraph) -> String {
    encode_bytes(&graph.configuration_id().as_bytes())
}

fn encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn store_node_kind(kind: StoreNodeKind) -> &'static str {
    match kind {
        StoreNodeKind::Memory => "memory",
        StoreNodeKind::Directory => "directory",
        StoreNodeKind::CompressedDirectory => "compressed-directory",
        StoreNodeKind::EncryptedDirectory => "encrypted-directory",
        StoreNodeKind::CompressedEncryptedDirectory => "compressed-encrypted-directory",
        StoreNodeKind::Packed => "packed",
        StoreNodeKind::S3 => "s3",
        StoreNodeKind::Verified => "verified",
        StoreNodeKind::Routed => "routed",
        StoreNodeKind::Tiered => "tiered",
        StoreNodeKind::ReadThrough => "read-through",
        StoreNodeKind::WriteThrough => "write-through",
        StoreNodeKind::WriteBack => "write-back",
        StoreNodeKind::DurabilityPolicy => "durability-policy",
        StoreNodeKind::LogicalQuota => "logical-quota",
        StoreNodeKind::PhysicalQuota => "physical-quota",
        StoreNodeKind::Metrics => "metrics",
        StoreNodeKind::Namespaced => "namespaced",
        StoreNodeKind::ProfileValidated => "profile-validated",
    }
}

#[derive(Serialize)]
struct CampaignStoreGcPhysicalReport {
    backend: String,
    objects: u64,
    logical_bytes: u64,
}

pub(super) fn run_campaign_store_gc(
    args: &CampaignStoreGcArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    validate_gc_paths(args)?;

    let endpoint = CampaignLoopbackEndpointConfig::new(
        UNUSED_GC_ENDPOINT,
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        0o600,
    )
    .map_err(|error| maintenance_error(format!("invalid internal owner endpoint: {error}")))?;
    let config = CampaignLocalServiceConfig::new(
        endpoint,
        &args.state,
        &args.policy,
        CampaignLocalServiceMode::ReadWrite,
        CampaignLoopbackServerConfig::default(),
    )
    .map_err(|error| maintenance_error(format!("invalid campaign owner profile: {error}")))?;
    let store = load_campaign_repository_store(&args.store)?;
    let prepared = config.prepare_with_store(store).map_err(|error| {
        maintenance_error(format!("campaign owner acquisition failed: {error}"))
    })?;
    let authority = prepared.store_gc_authority().map_err(|error| {
        maintenance_error(format!("campaign GC authority unavailable: {error}"))
    })?;
    let ledger_path = args.state.join("executor-ledger");
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_path)
        .map_err(|error| maintenance_error(format!("assignment ledger open failed: {error}")))?;

    let report = match args.operation {
        CampaignStoreGcCommand::Plan => {
            let planned = authority.plan(&mut ledger, None).map_err(|error| {
                maintenance_error(format!("campaign GC planning failed: {error}"))
            })?;
            let plan_id = planned.plan().id().map_err(|error| {
                maintenance_error(format!("campaign GC plan identity failed: {error}"))
            })?;
            let (journal, disposition) =
                DirectoryCampaignGcJournal::create(&args.journal, &planned).map_err(|error| {
                    maintenance_error(format!("campaign GC journal creation failed: {error}"))
                })?;
            CampaignStoreGcReport {
                schema: CAMPAIGN_GC_REPORT_SCHEMA,
                operation: "plan",
                plan: plan_id.to_hex(),
                journal: journal.root().display().to_string(),
                journal_disposition: match disposition {
                    CampaignGcJournalCreateDisposition::Created => "created",
                    CampaignGcJournalCreateDisposition::Existing => "existing",
                },
                phase: journal_phase(journal.phase()),
                apply_status: None,
                roots: planned.roots().len(),
                reachable_objects: Some(planned.reachable_objects()),
                candidates: planned.candidates().summary().candidates(),
                candidate_logical_bytes: planned.candidates().logical_bytes(),
                physical: physical_report(planned.plan()),
            }
        }
        CampaignStoreGcCommand::Apply => {
            let mut journal = DirectoryCampaignGcJournal::open(&args.journal).map_err(|error| {
                maintenance_error(format!("campaign GC journal open failed: {error}"))
            })?;
            let plan_id = journal.plan().id().map_err(|error| {
                maintenance_error(format!("campaign GC plan identity failed: {error}"))
            })?;
            let roots = journal.roots().len();
            let physical = physical_report(journal.plan());
            let result = authority
                .apply(&mut journal, &mut ledger, None)
                .map_err(|error| maintenance_error(format!("campaign GC apply failed: {error}")))?;
            CampaignStoreGcReport {
                schema: CAMPAIGN_GC_REPORT_SCHEMA,
                operation: "apply",
                plan: plan_id.to_hex(),
                journal: journal.root().display().to_string(),
                journal_disposition: "opened",
                phase: journal_phase(journal.phase()),
                apply_status: Some(match result.status() {
                    CampaignGcApplyStatus::Applied => "applied",
                    CampaignGcApplyStatus::AlreadyComplete => "already-complete",
                }),
                roots,
                reachable_objects: None,
                candidates: result.candidates(),
                candidate_logical_bytes: result.logical_bytes(),
                physical,
            }
        }
    };

    render_campaign_store_gc(&report, format)
}

fn physical_report(plan: &crucible_daemon::CampaignGcPlan) -> Vec<CampaignStoreGcPhysicalReport> {
    plan.physical()
        .iter()
        .map(|physical| CampaignStoreGcPhysicalReport {
            backend: physical.backend().to_owned(),
            objects: physical.objects(),
            logical_bytes: physical.logical_bytes(),
        })
        .collect()
}

fn render_store_status(
    report: &StoreStatusReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            maintenance_error(format!("store status JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            maintenance_error(format!("store status JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => {
            let mut lines = vec![
                format!("{:<20} {}", "configuration", report.configuration),
                format!("{:<20} {}", "root", report.root),
                format!(
                    "{:<20} {}",
                    "admitted-kinds",
                    report.admitted_kinds.join(",")
                ),
            ];
            lines.extend(report.nodes.iter().map(|node| {
                let capabilities = node.capabilities;
                format!(
                    "{:<20} {} kind={} durable={} deferred-write={} range-read={} streaming-read={} conditional-create={} streaming-put={} repair-inventory={} planned-delete={}",
                    "node",
                    node.id,
                    node.kind,
                    capabilities.durable,
                    capabilities.deferred_write,
                    capabilities.range_read,
                    capabilities.streaming_read,
                    capabilities.conditional_create,
                    capabilities.streaming_put,
                    capabilities.repair_inventory,
                    capabilities.planned_delete,
                )
            }));
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut lines = vec![
                String::from("| field | value |"),
                String::from("|---|---|"),
                format!("| configuration | `{}` |", report.configuration),
                format!("| root | `{}` |", report.root),
                format!("| admitted kinds | {} |", report.admitted_kinds.join(", ")),
            ];
            lines.extend(report.nodes.iter().map(|node| {
                let capabilities = node.capabilities;
                format!(
                    "| node `{}` | kind={} durable={} deferred-write={} range-read={} streaming-read={} conditional-create={} streaming-put={} repair-inventory={} planned-delete={} |",
                    node.id,
                    node.kind,
                    capabilities.durable,
                    capabilities.deferred_write,
                    capabilities.range_read,
                    capabilities.streaming_read,
                    capabilities.conditional_create,
                    capabilities.streaming_put,
                    capabilities.repair_inventory,
                    capabilities.planned_delete,
                )
            }));
            Ok(lines.join("\n"))
        }
    }
}

fn render_store_ensure(
    report: &StoreEnsureReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            maintenance_error(format!("store ensure JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            maintenance_error(format!("store ensure JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => Ok([
            format!("{:<20} {}", "configuration", report.configuration),
            format!("{:<20} {}", "content", report.content),
            format!("{:<20} {}", "logical-bytes", report.logical_bytes),
            format!("{:<20} {}", "authenticated", report.authenticated),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok([
            String::from("| field | value |"),
            String::from("|---|---|"),
            format!("| configuration | `{}` |", report.configuration),
            format!("| content | `{}` |", report.content),
            format!("| logical bytes | {} |", report.logical_bytes),
            format!("| authenticated | {} |", report.authenticated),
        ]
        .join("\n")),
    }
}

fn render_store_verify(
    report: &StoreVerifyReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            maintenance_error(format!("store verify JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            maintenance_error(format!("store verify JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => {
            let mut lines = vec![
                format!("{:<24} {}", "configuration", report.configuration),
                format!("{:<24} {}", "maximum-placements", report.maximum_placements),
                format!(
                    "{:<24} {}",
                    "maximum-logical-bytes", report.maximum_logical_bytes
                ),
                format!("{:<24} {}", "placements", report.placements),
                format!("{:<24} {}", "logical-bytes", report.logical_bytes),
                format!("{:<24} {}", "authenticated", report.authenticated),
            ];
            lines.extend(report.physical.iter().map(|physical| {
                format!(
                    "{:<24} {} generation={} placements={} logical-bytes={}",
                    "physical",
                    physical.backend,
                    physical.generation,
                    physical.placements,
                    physical.logical_bytes,
                )
            }));
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut lines = vec![
                String::from("| field | value |"),
                String::from("|---|---|"),
                format!("| configuration | `{}` |", report.configuration),
                format!("| maximum placements | {} |", report.maximum_placements),
                format!(
                    "| maximum logical bytes | {} |",
                    report.maximum_logical_bytes
                ),
                format!("| placements | {} |", report.placements),
                format!("| logical bytes | {} |", report.logical_bytes),
                format!("| authenticated | {} |", report.authenticated),
            ];
            lines.extend(report.physical.iter().map(|physical| {
                format!(
                    "| physical `{}` | generation `{}` / {} placements / {} logical bytes |",
                    physical.backend,
                    physical.generation,
                    physical.placements,
                    physical.logical_bytes,
                )
            }));
            Ok(lines.join("\n"))
        }
    }
}

const fn journal_phase(phase: CampaignGcJournalPhase) -> &'static str {
    match phase {
        CampaignGcJournalPhase::Planned => "planned",
        CampaignGcJournalPhase::Applying => "applying",
        CampaignGcJournalPhase::Complete => "complete",
    }
}

fn render_campaign_store_gc(
    report: &CampaignStoreGcReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            maintenance_error(format!("campaign GC JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            maintenance_error(format!("campaign GC JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => {
            let mut lines = vec![
                format!("{:<24} {}", "operation", report.operation),
                format!("{:<24} {}", "plan", report.plan),
                format!("{:<24} {}", "journal", report.journal),
                format!(
                    "{:<24} {}",
                    "journal-disposition", report.journal_disposition
                ),
                format!("{:<24} {}", "phase", report.phase),
                format!("{:<24} {}", "roots", report.roots),
                format!("{:<24} {}", "candidates", report.candidates),
                format!(
                    "{:<24} {}",
                    "candidate-logical-bytes", report.candidate_logical_bytes
                ),
            ];
            if let Some(status) = report.apply_status {
                lines.push(format!("{:<24} {status}", "apply-status"));
            }
            if let Some(reachable) = report.reachable_objects {
                lines.push(format!("{:<24} {reachable}", "reachable-objects"));
            }
            lines.extend(report.physical.iter().map(|physical| {
                format!(
                    "{:<24} {} objects={} logical-bytes={}",
                    "physical", physical.backend, physical.objects, physical.logical_bytes
                )
            }));
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut lines = vec![
                String::from("| field | value |"),
                String::from("|---|---|"),
                format!("| operation | {} |", report.operation),
                format!("| plan | `{}` |", report.plan),
                format!("| journal | `{}` |", report.journal),
                format!("| journal disposition | {} |", report.journal_disposition),
                format!("| phase | {} |", report.phase),
                format!("| roots | {} |", report.roots),
                format!("| candidates | {} |", report.candidates),
                format!(
                    "| candidate logical bytes | {} |",
                    report.candidate_logical_bytes
                ),
            ];
            if let Some(status) = report.apply_status {
                lines.push(format!("| apply status | {status} |"));
            }
            if let Some(reachable) = report.reachable_objects {
                lines.push(format!("| reachable objects | {reachable} |"));
            }
            lines.extend(report.physical.iter().map(|physical| {
                format!(
                    "| physical `{}` | {} objects / {} logical bytes |",
                    physical.backend, physical.objects, physical.logical_bytes
                )
            }));
            Ok(lines.join("\n"))
        }
    }
}

fn validate_gc_paths(args: &CampaignStoreGcArgs) -> Result<(), CliError> {
    let ledger = args.state.join("executor-ledger");
    let paths = vec![
        ("state", args.state.as_path()),
        ("policy", args.policy.as_path()),
        ("store", args.store.as_path()),
        ("journal", args.journal.as_path()),
        ("derived-ledger", ledger.as_path()),
    ];
    for (label, path) in &paths {
        validate_owner_path(label, path)?;
    }
    for (index, (left_label, left)) in paths.iter().enumerate() {
        for (right_label, right) in paths.iter().skip(index + 1) {
            if left == right {
                return Err(usage_error(format!(
                    "campaign GC {left_label} and {right_label} paths must be distinct"
                )));
            }
        }
    }
    Ok(())
}

fn validate_owner_path(label: &str, path: &Path) -> Result<(), CliError> {
    let canonical = path
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if !path.is_absolute()
        || !canonical
        || path.as_os_str().as_encoded_bytes().contains(&0)
        || path.as_os_str().as_encoded_bytes().len() > MAXIMUM_OWNER_PATH_BYTES
    {
        return Err(usage_error(format!(
            "campaign GC {label} path must be absolute, canonical, and at most 4095 bytes"
        )));
    }
    Ok(())
}

fn maintenance_error(message: impl Into<String>) -> CliError {
    backend_error(message.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::BTreeSet;
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use crucible_cas::content_store::{BlobHandle, ObjectKind};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn store_status_ensure_and_verify_authenticate_one_graph_and_inventory() {
        let fixture = GcFixture::new();
        let graph = load_campaign_store_graph(&fixture.store).expect("load inspection graph");
        let bytes = b"authenticated store ensure fixture";
        let content = ContentId::for_bytes(ObjectKind::Scenario, 1, bytes);
        graph
            .put_if_absent(content, &BlobHandle::from_bytes(bytes.to_vec()))
            .expect("publish ensure fixture");
        drop(graph);

        let status = run_store_status(
            &StoreStatusArgs {
                deployment: fixture.store.clone(),
            },
            OutputFormat::Jsonl,
        )
        .expect("render store status");
        let status: serde_json::Value = serde_json::from_str(&status).expect("decode status");
        assert_eq!(status["schema"], STORE_STATUS_REPORT_SCHEMA);
        assert_eq!(status["root"], "primary");
        assert_eq!(status["nodes"][0]["kind"], "directory");
        assert_eq!(status["nodes"][0]["capabilities"]["durable"], true);

        let ensured = run_store_ensure(
            &StoreEnsureArgs {
                content: content.encode(),
                deployment: fixture.store.clone(),
            },
            OutputFormat::Jsonl,
        )
        .expect("authenticate stored object");
        let ensured: serde_json::Value =
            serde_json::from_str(&ensured).expect("decode ensure report");
        assert_eq!(ensured["schema"], STORE_ENSURE_REPORT_SCHEMA);
        assert_eq!(ensured["content"], content.encode());
        assert_eq!(ensured["logical_bytes"], bytes.len());
        assert_eq!(ensured["authenticated"], true);

        let verified = run_store_verify(
            &StoreVerifyArgs {
                deployment: fixture.store.clone(),
            },
            OutputFormat::Jsonl,
        )
        .expect("authenticate stable physical inventory");
        let verified: serde_json::Value =
            serde_json::from_str(&verified).expect("decode verify report");
        assert_eq!(verified["schema"], STORE_VERIFY_REPORT_SCHEMA);
        assert_eq!(verified["maximum_placements"], MAX_STORE_VERIFY_PLACEMENTS);
        assert_eq!(
            verified["maximum_logical_bytes"],
            MAX_STORE_VERIFY_LOGICAL_BYTES
        );
        assert_eq!(verified["placements"], 1);
        assert_eq!(verified["logical_bytes"], bytes.len());
        assert_eq!(verified["physical"][0]["backend"], "primary");
        assert_eq!(
            verified["physical"][0]["generation"]
                .as_str()
                .expect("physical generation")
                .len(),
            64
        );
        assert_eq!(verified["authenticated"], true);

        let encoded = content.encode();
        let digest = encoded.rsplit('.').next().expect("content digest");
        let object = fixture
            .objects
            .join("scenario")
            .join("1")
            .join(&digest[..2])
            .join(digest);
        fs::write(object, b"corrupt replacement").expect("corrupt stored object");
        let error = run_store_ensure(
            &StoreEnsureArgs {
                content: content.encode(),
                deployment: fixture.store.clone(),
            },
            OutputFormat::Jsonl,
        )
        .expect_err("corrupt object must fail at authenticated EOF");
        assert!(error.to_string().contains("authentication failed"));

        let error = run_store_verify(
            &StoreVerifyArgs {
                deployment: fixture.store.clone(),
            },
            OutputFormat::Jsonl,
        )
        .expect_err("whole-inventory verification must reject corrupt placement bytes");
        assert!(error.to_string().contains("authenticate physical node"));
    }

    #[test]
    fn store_ensure_rejects_a_noncanonical_id_before_deployment_io() {
        let fixture = GcFixture::new();
        let missing = fixture.root.join("missing-store.toml");
        let error = run_store_ensure(
            &StoreEnsureArgs {
                content: String::from("not-a-content-id"),
                deployment: missing,
            },
            OutputFormat::Jsonl,
        )
        .expect_err("invalid ID must fail before deployment read");
        assert!(matches!(error, CliError::Usage(_)));
    }

    #[test]
    fn offline_gc_plans_reopens_and_applies_one_exact_empty_store() {
        let fixture = GcFixture::new();
        let mut args = fixture.args(CampaignStoreGcCommand::Plan);
        let planned =
            run_campaign_store_gc(&args, OutputFormat::Jsonl).expect("plan empty repository GC");
        let planned: serde_json::Value =
            serde_json::from_str(&planned).expect("decode planning report");
        assert_eq!(planned["operation"], "plan");
        assert_eq!(planned["journal_disposition"], "created");
        assert_eq!(planned["phase"], "planned");
        assert_eq!(planned["candidates"], 0);

        let replay = run_campaign_store_gc(&args, OutputFormat::Jsonl)
            .expect("reopen exact planning journal");
        let replay: serde_json::Value =
            serde_json::from_str(&replay).expect("decode replay report");
        assert_eq!(replay["plan"], planned["plan"]);
        assert_eq!(replay["journal_disposition"], "existing");

        args.operation = CampaignStoreGcCommand::Apply;
        let applied =
            run_campaign_store_gc(&args, OutputFormat::Jsonl).expect("apply empty repository GC");
        let applied: serde_json::Value =
            serde_json::from_str(&applied).expect("decode apply report");
        assert_eq!(applied["plan"], planned["plan"]);
        assert_eq!(applied["phase"], "complete");
        assert_eq!(applied["apply_status"], "applied");

        let replayed =
            run_campaign_store_gc(&args, OutputFormat::Jsonl).expect("replay completed GC apply");
        let replayed: serde_json::Value =
            serde_json::from_str(&replayed).expect("decode apply replay report");
        assert_eq!(replayed["apply_status"], "already-complete");
    }

    #[test]
    fn offline_gc_rejects_every_path_before_deployment_io() {
        let fixture = GcFixture::new();
        let mut args = fixture.args(CampaignStoreGcCommand::Plan);
        args.state = PathBuf::from("relative-state");
        args.store = fixture.root.join("missing-store.toml");
        assert!(matches!(
            run_campaign_store_gc(&args, OutputFormat::Jsonl),
            Err(CliError::Usage(_))
        ));

        let mut args = fixture.args(CampaignStoreGcCommand::Plan);
        args.journal = args.state.join("executor-ledger");
        assert!(matches!(
            run_campaign_store_gc(&args, OutputFormat::Jsonl),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn offline_gc_rejects_a_live_packaged_executor_before_journaling() {
        let fixture = GcFixture::new();
        let ledger_path = fixture.state.join("executor-ledger");
        let _live_ledger = DirectoryAssignmentLedger::open(&ledger_path)
            .expect("retain live packaged-executor ledger");
        let args = fixture.args(CampaignStoreGcCommand::Plan);

        let error = run_campaign_store_gc(&args, OutputFormat::Jsonl)
            .expect_err("live executor ledger must exclude GC");
        assert!(error.to_string().contains("assignment ledger open failed"));
        assert!(!fixture.journal.exists());
    }

    #[test]
    fn offline_gc_surface_has_no_substitutable_ledger_or_pin_path() {
        let mut command = Cli::command();
        command.build();
        let store = command.find_subcommand("store").expect("store command");
        let gc = store.find_subcommand("gc").expect("store GC command");
        let ids = gc
            .get_arguments()
            .filter(|argument| !argument.is_global_set())
            .map(|argument| argument.get_id().as_str())
            .filter(|id| *id != "help")
            .collect::<BTreeSet<_>>();
        assert_eq!(ids, BTreeSet::from(["state", "policy", "store", "journal"]));
        assert!(store.find_subcommand("status").is_some());
        assert!(store.find_subcommand("ensure").is_some());
        assert!(store.find_subcommand("verify").is_some());
        assert!(gc.find_subcommand("plan").is_some());
        assert!(gc.find_subcommand("apply").is_some());
    }

    struct GcFixture {
        _directory: TempDir,
        root: PathBuf,
        state: PathBuf,
        objects: PathBuf,
        policy: PathBuf,
        store: PathBuf,
        journal: PathBuf,
    }

    impl GcFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("GC fixture");
            let root = directory.path().to_owned();
            fs::set_permissions(&root, Permissions::from_mode(0o700)).expect("secure GC fixture");
            let state = secure_directory(&root, "state");
            let objects = secure_directory(&root, "objects");
            let refs = secure_directory(&root, "refs");
            let metadata = fs::metadata(&root).expect("GC fixture metadata");
            let policy = root.join("policy.toml");
            fs::write(
                &policy,
                format!(
                    r#"schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = {}
group_id = {}
principal = "operator"

[[grants]]
principal = "operator"
operation = "get-campaign"
campaign = "*"
"#,
                    metadata.uid(),
                    metadata.gid()
                ),
            )
            .expect("write GC policy");
            fs::set_permissions(&policy, Permissions::from_mode(0o600)).expect("secure GC policy");
            let store = root.join("store.toml");
            fs::write(
                &store,
                format!(
                    r#"schema = "crucible.campaign-repository-store"
version = 1
root = "primary"
admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
ref_directory = {refs:?}

[[nodes]]
id = "primary"
[nodes.spec]
kind = "directory"
root = {objects:?}
"#
                ),
            )
            .expect("write GC store deployment");
            fs::set_permissions(&store, Permissions::from_mode(0o600))
                .expect("secure GC store deployment");
            Self {
                journal: root.join("journal"),
                _directory: directory,
                root,
                state,
                objects,
                policy,
                store,
            }
        }

        fn args(&self, operation: CampaignStoreGcCommand) -> CampaignStoreGcArgs {
            CampaignStoreGcArgs {
                state: self.state.clone(),
                policy: self.policy.clone(),
                store: self.store.clone(),
                journal: self.journal.clone(),
                operation,
            }
        }
    }

    fn secure_directory(root: &Path, name: &str) -> PathBuf {
        let path = root.join(name);
        fs::create_dir(&path).expect("create secure GC directory");
        fs::set_permissions(&path, Permissions::from_mode(0o700))
            .expect("set secure GC directory mode");
        path
    }
}
