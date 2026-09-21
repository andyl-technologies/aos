//! Generation-bound repair for one physical campaign-store placement.
//!
//! Repair runs only while the durable campaign owner is stopped. It inventories
//! the exact source and target leaves, rejects aliased physical namespaces,
//! authenticates bounded source bytes, and applies the replacement only if the
//! target inventory still matches the observed generation.

use super::*;

use crucible_daemon::campaign_store_composition::{
    ContentId, StoreNodeId, StorePhysicalRepairDisposition,
};
use crucible_daemon::{
    CampaignLocalServiceConfig, CampaignLocalServiceMode, CampaignLoopbackEndpointConfig,
    CampaignLoopbackServerConfig, PreparedCampaignLocalService,
};
use serde::Serialize;

use crate::cli_campaign_store::load_campaign_repository_store;

const STORE_REPAIR_REPORT_SCHEMA: &str = "crucible.cli.store-repair.v1";
const UNUSED_REPAIR_ENDPOINT: &str = "/tmp/crucible-campaign-store-repair-owner.sock";

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

    let owner = prepare_repair_owner(&args.state, &args.policy, &args.deployment)?;
    let authority = owner
        .store_maintenance_authority()
        .map_err(|error| repair_error(format!("store repair authority unavailable: {error}")))?;
    let receipt = authority
        .repair_physical_copy(&source, &target, content, args.maximum_bytes)
        .map_err(|error| repair_error(format!("store repair failed: {error}")))?;

    let report = StoreRepairReport {
        schema: STORE_REPAIR_REPORT_SCHEMA,
        configuration: encode_store_bytes(&receipt.configuration().as_bytes()),
        content: content.encode(),
        source: source.as_str().to_owned(),
        source_storage_identity: receipt.source_storage_identity().to_hex(),
        source_generation: receipt.source_generation().to_hex(),
        target: target.as_str().to_owned(),
        target_storage_identity: receipt.target_storage_identity().to_hex(),
        target_generation: receipt.target_generation().to_hex(),
        logical_bytes: receipt.logical_length(),
        disposition: match receipt.disposition() {
            StorePhysicalRepairDisposition::AlreadyAuthenticated => "already-authenticated",
            StorePhysicalRepairDisposition::ReplacedMissing => "replaced-missing",
            StorePhysicalRepairDisposition::ReplacedCorrupt => "replaced-corrupt",
        },
        authenticated: true,
    };
    render_store_repair(&report, format)
}

fn prepare_repair_owner(
    state: &Path,
    policy: &Path,
    deployment: &Path,
) -> Result<PreparedCampaignLocalService, CliError> {
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

    let repository = load_campaign_repository_store(deployment)?;
    config
        .prepare_with_store(repository)
        .map_err(|error| repair_error(format!("campaign owner acquisition failed: {error}")))
}

fn encode_store_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

        let StoreRepairCommand::Placement(placement) = &args.command;
        let repository =
            crate::cli_campaign_store::load_campaign_repository_store(&placement.deployment)
                .expect("reload fixture store");
        let owner = service_config(&placement.state, &placement.policy)
            .prepare_with_store(repository)
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
version = 2
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
