//! Generation-bound repair for one physical campaign-store placement.
//!
//! Repair runs only while the durable campaign owner is stopped. It inventories
//! the exact source and target leaves, rejects aliased physical namespaces,
//! authenticates bounded source bytes, and applies the replacement only if the
//! target inventory still matches the observed generation.

use super::*;

use crucible_daemon::campaign_store_composition::{
    ContentId, InventoryGeneration, PhysicalStorageIdentity, StoreGraphAdmin,
    StoreGraphPhysicalAdmin, StoreGraphPhysicalRepairDisposition, StoreNodeId,
};
use crucible_daemon::{
    CampaignLocalServiceConfig, CampaignLocalServiceMode, CampaignLoopbackEndpointConfig,
    CampaignLoopbackServerConfig,
};
use serde::Serialize;

use crate::cli_campaign_store::load_campaign_store_maintenance_observational;

const STORE_REPAIR_REPORT_SCHEMA: &str = "crucible.cli.store-repair.v1";
const UNUSED_REPAIR_ENDPOINT: &str = "/tmp/crucible-campaign-store-repair-owner.sock";

#[derive(Clone, Copy)]
struct PhysicalSnapshot<'a> {
    capability: StoreGraphPhysicalAdmin<'a>,
    identity: PhysicalStorageIdentity,
    generation: InventoryGeneration,
}

#[derive(Serialize)]
struct StoreRepairReport {
    schema: &'static str,
    configuration: String,
    content: String,
    source: String,
    source_storage_identity: String,
    source_generation: String,
    target: String,
    target_storage_identity: String,
    target_generation: String,
    logical_bytes: u64,
    disposition: &'static str,
    authenticated: bool,
}

pub(super) fn run_store_repair(
    args: &StoreRepairArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    match &args.command {
        StoreRepairCommand::Placement(args) => run_store_placement_repair(args, format),
        StoreRepairCommand::OperationalState(args) => run_operational_state_repair(args, format),
    }
}

fn run_store_placement_repair(
    args: &StorePlacementRepairArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    if args.maximum_bytes == 0 {
        return Err(usage_error("store repair maximum bytes must be nonzero"));
    }

    let content = ContentId::parse(&args.content)
        .map_err(|error| usage_error(format!("invalid content ID: {error}")))?;
    let source = StoreNodeId::new(args.source.clone())
        .map_err(|error| usage_error(format!("invalid source node ID: {error}")))?;
    let target = StoreNodeId::new(args.target.clone())
        .map_err(|error| usage_error(format!("invalid target node ID: {error}")))?;
    if source == target {
        return Err(usage_error(
            "store repair source and target must be distinct",
        ));
    }

    let _owner = acquire_stopped_owner(&args.state, &args.policy)?;
    let (graph, maintenance) = load_campaign_store_maintenance_observational(&args.deployment)?;
    let source_snapshot = physical_snapshot(&maintenance, &source, "source")?;
    let target_snapshot = physical_snapshot(&maintenance, &target, "target")?;
    if source_snapshot.identity == target_snapshot.identity {
        return Err(repair_error(
            "store repair source and target resolve to the same physical storage identity",
        ));
    }

    let source_handle = source_snapshot
        .capability
        .read(content)
        .map_err(|error| repair_error(format!("store repair source read failed: {error}")))?;
    let source_bytes = source_handle
        .read_all(args.maximum_bytes)
        .map_err(|error| {
            repair_error(format!(
                "store repair source authentication failed: {error}"
            ))
        })?;
    let logical_bytes = source_bytes.len() as u64;
    let result = target_snapshot
        .capability
        .repair_with_authenticated_bytes(content, source_bytes, target_snapshot.generation)
        .map_err(|error| repair_error(format!("store repair apply failed: {error}")))?;

    let report = StoreRepairReport {
        schema: STORE_REPAIR_REPORT_SCHEMA,
        configuration: encode_bytes(&graph.configuration_id().as_bytes()),
        content: content.encode(),
        source: source.as_str().to_owned(),
        source_storage_identity: source_snapshot.identity.to_hex(),
        source_generation: source_snapshot.generation.to_hex(),
        target: target.as_str().to_owned(),
        target_storage_identity: target_snapshot.identity.to_hex(),
        target_generation: target_snapshot.generation.to_hex(),
        logical_bytes,
        disposition: match result {
            StoreGraphPhysicalRepairDisposition::AlreadyAuthenticated => "already-authenticated",
            StoreGraphPhysicalRepairDisposition::ReplacedMissing => "replaced-missing",
            StoreGraphPhysicalRepairDisposition::ReplacedCorrupt => "replaced-corrupt",
        },
        authenticated: true,
    };
    render_store_repair(&report, format)
}

#[derive(Serialize)]
struct OperationalStateRepairReport {
    schema: &'static str,
    assignment_records: usize,
    assignments_migrated: usize,
    prepared_journals: usize,
    prepared_journals_migrated: usize,
    receipt: String,
    receipt_id: String,
    authenticated: bool,
}

fn run_operational_state_repair(
    args: &StoreOperationalStateRepairArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    let _owner = acquire_stopped_owner(&args.state, &args.policy)?;
    let config = crucible_daemon::OperationalStateMigrationConfig {
        assignment_ledger: args.ledger.clone(),
        prepared_results: args.prepared_results.clone(),
        receipt: args.receipt.clone(),
        maximum_assignment_entries: args.maximum_assignment_entries,
        maximum_assignment_bytes: args.maximum_assignment_bytes,
        maximum_prepared_result_entries: args.maximum_prepared_result_entries,
        maximum_prepared_result_bytes: args.maximum_prepared_result_bytes,
    };
    let summary = crucible_daemon::migrate_operational_state(&config)
        .map_err(|error| repair_error(format!("operational-state migration failed: {error}")))?;
    let report = OperationalStateRepairReport {
        schema: "crucible.cli.store-operational-state-repair.v1",
        assignment_records: summary.assignment_records,
        assignments_migrated: summary.assignments_migrated,
        prepared_journals: summary.prepared_journals,
        prepared_journals_migrated: summary.prepared_journals_migrated,
        receipt: args.receipt.display().to_string(),
        receipt_id: summary.receipt_id,
        authenticated: true,
    };
    match format {
        OutputFormat::Jsonl => serde_json::to_string(&report)
            .map(|mut output| {
                output.push('\n');
                output
            })
            .map_err(|error| repair_error(format!("encode migration report: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(&report)
            .map(|mut output| {
                output.push('\n');
                output
            })
            .map_err(|error| repair_error(format!("encode migration report: {error}"))),
        OutputFormat::Table | OutputFormat::Markdown => Ok(format!(
            "authenticated operational state: {} assignment records ({} migrated), {} prepared journals ({} migrated); receipt {} at {}\n",
            report.assignment_records,
            report.assignments_migrated,
            report.prepared_journals,
            report.prepared_journals_migrated,
            report.receipt_id,
            report.receipt,
        )),
    }
}

fn acquire_stopped_owner(
    state: &Path,
    policy: &Path,
) -> Result<crucible_daemon::PreparedCampaignStoppedOwner, CliError> {
    let endpoint = CampaignLoopbackEndpointConfig::new(
        UNUSED_REPAIR_ENDPOINT,
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        0o600,
    )
    .map_err(|error| repair_error(format!("invalid repair owner endpoint: {error}")))?;
    let config = CampaignLocalServiceConfig::new(
        endpoint,
        state,
        policy,
        CampaignLocalServiceMode::ReadWrite,
        CampaignLoopbackServerConfig::default(),
    )
    .map_err(|error| repair_error(format!("invalid campaign owner profile: {error}")))?;

    config
        .acquire_existing_owner()
        .map_err(|error| repair_error(format!("campaign owner acquisition failed: {error}")))
}

fn physical_snapshot<'a>(
    maintenance: &'a StoreGraphAdmin,
    node: &StoreNodeId,
    role: &str,
) -> Result<PhysicalSnapshot<'a>, CliError> {
    let capability = maintenance
        .physical()
        .into_iter()
        .find(|capability| capability.node() == node)
        .ok_or_else(|| {
            repair_error(format!(
                "configured store {role} node `{}` is not a physical repair boundary",
                node.as_str()
            ))
        })?;
    let mut fence = capability
        .admin()
        .acquire_inventory_fence()
        .map_err(|error| {
            repair_error(format!(
                "store repair {role} inventory acquisition failed: {error}"
            ))
        })?;
    let summary = fence.visit_inventory(&mut |_| Ok(())).map_err(|error| {
        repair_error(format!(
            "store repair {role} inventory authentication failed: {error}"
        ))
    })?;

    Ok(PhysicalSnapshot {
        capability,
        identity: summary.storage_identity(),
        generation: summary.generation(),
    })
}

fn render_store_repair(
    report: &StoreRepairReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| repair_error(format!("store repair JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| repair_error(format!("store repair JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(render_fields(report)
            .into_iter()
            .map(|(field, value)| format!("{field:<24} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut lines = vec![String::from("| field | value |"), String::from("|---|---|")];
            lines.extend(
                render_fields(report)
                    .into_iter()
                    .map(|(field, value)| format!("| {field} | `{value}` |")),
            );
            Ok(lines.join("\n"))
        }
    }
}

fn render_fields(report: &StoreRepairReport) -> [(&'static str, String); 12] {
    [
        ("configuration", report.configuration.clone()),
        ("content", report.content.clone()),
        ("source", report.source.clone()),
        (
            "source-storage-identity",
            report.source_storage_identity.clone(),
        ),
        ("source-generation", report.source_generation.clone()),
        ("target", report.target.clone()),
        (
            "target-storage-identity",
            report.target_storage_identity.clone(),
        ),
        ("target-generation", report.target_generation.clone()),
        ("logical-bytes", report.logical_bytes.to_string()),
        ("disposition", report.disposition.to_owned()),
        ("authenticated", report.authenticated.to_string()),
        ("schema", report.schema.to_owned()),
    ]
}

fn encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn repair_error(message: impl Into<String>) -> CliError {
    backend_error(message.into())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture failures must identify their exact step.
    #![allow(clippy::expect_used)]

    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    use crucible_daemon::campaign_store_composition::{
        DirectoryBlobBackend, ImmutableBlobBackend, ObjectKind,
    };
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn repair_restores_missing_and_corrupt_copies_only_while_stopped() {
        let directory = tempdir().expect("repair fixture");
        let root = directory.path();
        fs::set_permissions(root, Permissions::from_mode(0o700)).expect("secure fixture");
        let state = secure_directory(root, "state");
        let refs = secure_directory(root, "refs");
        let source_root = secure_directory(root, "source");
        let target_root = secure_directory(root, "target");
        let policy = root.join("policy.toml");
        let store = root.join("store.toml");
        write_policy(&policy, root);
        write_store(&store, &refs, &source_root, &target_root);

        let config = service_config(&state, &policy);
        let repository = crate::cli_campaign_store::load_campaign_repository_store(&store)
            .expect("load fixture store");
        drop(
            config
                .prepare_with_store(repository)
                .expect("initialize stopped owner state"),
        );

        let bytes = b"authenticated public repair";
        let content = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        DirectoryBlobBackend::new("source", &source_root)
            .put_if_absent(
                content,
                &crucible_cas::content_store::BlobHandle::from_bytes(bytes.to_vec()),
            )
            .expect("seed repair source");
        DirectoryBlobBackend::new("target", &target_root)
            .put_if_absent(
                content,
                &crucible_cas::content_store::BlobHandle::from_bytes(bytes.to_vec()),
            )
            .expect("seed repair target");
        fs::remove_file(object_path(&target_root, content)).expect("remove target placement");
        let placement = StorePlacementRepairArgs {
            content: content.encode(),
            deployment: store,
            source: String::from("source"),
            target: String::from("target"),
            maximum_bytes: 1_024,
            state,
            policy,
        };
        let args = StoreRepairArgs {
            command: StoreRepairCommand::Placement(placement),
        };

        let missing = run_store_repair(&args, OutputFormat::Jsonl).expect("repair missing target");
        let missing: serde_json::Value = serde_json::from_str(&missing).expect("decode report");
        assert_eq!(missing["schema"], STORE_REPAIR_REPORT_SCHEMA);
        assert_eq!(missing["disposition"], "replaced-missing");
        assert_eq!(missing["authenticated"], true);
        assert_ne!(
            missing["source_storage_identity"],
            missing["target_storage_identity"]
        );

        fs::write(object_path(&target_root, content), b"corrupt target")
            .expect("corrupt target placement");
        let corrupt = run_store_repair(&args, OutputFormat::Jsonl).expect("repair corrupt target");
        let corrupt: serde_json::Value = serde_json::from_str(&corrupt).expect("decode report");
        assert_eq!(corrupt["disposition"], "replaced-corrupt");
        assert_eq!(corrupt["logical_bytes"], bytes.len());

        let StoreRepairCommand::Placement(placement) = &args.command else {
            panic!("placement fixture command");
        };
        let owner = service_config(&placement.state, &placement.policy)
            .acquire_existing_owner()
            .expect("hold live owner lock");
        let error = run_store_repair(&args, OutputFormat::Jsonl)
            .expect_err("repair must reject a live owner");
        assert!(error.to_string().contains("repository is already in use"));
        drop(owner);

        write_store(&placement.deployment, &refs, &source_root, &source_root);
        let error = run_store_repair(&args, OutputFormat::Jsonl)
            .expect_err("repair must reject aliased physical storage");
        assert!(error.to_string().contains("same physical storage identity"));
    }

    #[test]
    fn operational_state_repair_uses_stopped_owner_and_assignment_writer_locks() {
        let directory = tempdir().expect("migration fixture");
        let root = directory.path();
        fs::set_permissions(root, Permissions::from_mode(0o700)).expect("secure fixture");
        let state = secure_directory(root, "state");
        let ledger_root = secure_directory(root, "ledger");
        let prepared_results = secure_directory(root, "prepared-results");
        let policy = root.join("policy.toml");
        write_policy(&policy, root);
        drop(
            service_config(&state, &policy)
                .prepare()
                .expect("initialize stopped owner"),
        );
        drop(
            crucible_daemon::DirectoryAssignmentLedger::open(&ledger_root)
                .expect("initialize assignment ledger"),
        );
        let args = StoreRepairArgs {
            command: StoreRepairCommand::OperationalState(StoreOperationalStateRepairArgs {
                state,
                policy,
                ledger: ledger_root.clone(),
                prepared_results,
                receipt: root.join("migration-receipt"),
                maximum_assignment_entries: 10,
                maximum_assignment_bytes: 1_024,
                maximum_prepared_result_entries: 10,
                maximum_prepared_result_bytes: 1_024,
            }),
        };

        let output = run_store_repair(&args, OutputFormat::Jsonl).expect("migrate empty state");
        let report: serde_json::Value = serde_json::from_str(&output).expect("migration report");
        assert_eq!(
            report["schema"],
            "crucible.cli.store-operational-state-repair.v1"
        );
        assert_eq!(report["assignment_records"], 0);
        assert_eq!(report["prepared_journals"], 0);
        assert_eq!(report["authenticated"], true);

        let held_writer = crucible_daemon::DirectoryAssignmentLedger::open(&ledger_root)
            .expect("hold assignment writer");
        let error = run_store_repair(&args, OutputFormat::Jsonl)
            .expect_err("migration must reject live assignment writer");
        assert!(error.to_string().contains("lock-writer"));
        drop(held_writer);
    }

    fn secure_directory(root: &Path, name: &str) -> PathBuf {
        let path = root.join(name);
        fs::create_dir(&path).expect("create fixture directory");
        fs::set_permissions(&path, Permissions::from_mode(0o700))
            .expect("secure fixture directory");
        path
    }

    fn write_policy(path: &Path, root: &Path) {
        let metadata = fs::metadata(root).expect("fixture metadata");
        fs::write(
            path,
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
        .expect("write repair policy");
        fs::set_permissions(path, Permissions::from_mode(0o600)).expect("secure repair policy");
    }

    fn write_store(path: &Path, refs: &Path, source: &Path, target: &Path) {
        fs::write(
            path,
            format!(
                r#"schema = "crucible.campaign-repository-store"
version = 1
root = "mirror"
admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
ref_directory = {refs:?}

[[nodes]]
id = "mirror"
[nodes.spec]
kind = "write-through"
children = ["source", "target"]

[[nodes]]
id = "source"
[nodes.spec]
kind = "directory"
root = {source:?}

[[nodes]]
id = "target"
[nodes.spec]
kind = "directory"
root = {target:?}
"#
            ),
        )
        .expect("write repair store");
        fs::set_permissions(path, Permissions::from_mode(0o600)).expect("secure repair store");
    }

    fn service_config(state: &Path, policy: &Path) -> CampaignLocalServiceConfig {
        let endpoint = CampaignLoopbackEndpointConfig::new(
            UNUSED_REPAIR_ENDPOINT,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            0o600,
        )
        .expect("repair fixture endpoint");
        CampaignLocalServiceConfig::new(
            endpoint,
            state,
            policy,
            CampaignLocalServiceMode::ReadWrite,
            CampaignLoopbackServerConfig::default(),
        )
        .expect("repair fixture owner config")
    }

    fn object_path(root: &Path, content: ContentId) -> PathBuf {
        let encoded = content.encode();
        let digest = encoded.rsplit('.').next().expect("content digest");
        root.join("trace").join("1").join(&digest[..2]).join(digest)
    }
}
