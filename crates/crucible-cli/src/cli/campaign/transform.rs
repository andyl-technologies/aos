//! Generation-bound physical store transformation administration.
//!
//! Packed repack uses a durable external journal. Planning records the exact
//! store-graph configuration, packed node, and canonical packed-index plan;
//! apply reopens that record and relies on the packed backend's exact-generation
//! admission before publishing a replacement index.

use super::*;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crucible_daemon::campaign_store_composition::{
    PackedRepackPlan, PackedStorageAccounting, StoreGraphAdmin, StoreGraphConfigurationId,
    StoreGraphPackedRepackAdmin, StoreNodeId,
};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};

use crate::cli_campaign_store::load_campaign_store_graph_with_admin;

const PACKED_REPACK_JOURNAL_SCHEMA: &str = "crucible.cli.packed-repack-journal";
const PACKED_REPACK_REPORT_SCHEMA: &str = "crucible.cli.packed-repack.v1";
const PACKED_REPACK_JOURNAL_VERSION: u32 = 1;
const JOURNAL_RECORD: &str = "record-v1.json";
const JOURNAL_STAGING: &str = ".record-v1.json.tmp";
const JOURNAL_LOCK: &str = "lock-v1";
const MAXIMUM_JOURNAL_RECORD_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PackedRepackJournalPhase {
    Planned,
    Applied,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PackedRepackJournalRecord {
    schema: String,
    version: u32,
    configuration: String,
    node: String,
    plan: String,
    phase: PackedRepackJournalPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    applied: Option<PackedRepackAppliedRecord>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PackedRepackAppliedRecord {
    before: PackedAccountingRecord,
    after: PackedAccountingRecord,
    removed_packs: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PackedAccountingRecord {
    generation: u64,
    logical_objects: u64,
    logical_bytes: u64,
    packs: u64,
    physical_bytes: u64,
}

impl From<PackedStorageAccounting> for PackedAccountingRecord {
    fn from(accounting: PackedStorageAccounting) -> Self {
        Self {
            generation: accounting.generation(),
            logical_objects: accounting.logical_objects(),
            logical_bytes: accounting.logical_bytes(),
            packs: accounting.packs(),
            physical_bytes: accounting.physical_bytes(),
        }
    }
}

#[derive(Serialize)]
struct PackedRepackReportView {
    schema: &'static str,
    operation: &'static str,
    phase: PackedRepackJournalPhase,
    configuration: String,
    node: String,
    plan: String,
    journal: String,
    replayed: bool,
    before: PackedAccountingRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<PackedAccountingRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    removed_packs: Option<u64>,
}

pub(super) fn run_campaign_store_transform(
    args: &CampaignStoreTransformArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    match &args.transform {
        CampaignStoreTransformCommand::Packed(packed) => run_packed_repack(packed, format),
    }
}

fn run_packed_repack(
    args: &CampaignStorePackedTransformArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    validate_journal_path(&args.journal)?;
    let journal = PackedRepackJournal::open(&args.journal)?;
    let (graph, admin) = load_campaign_store_graph_with_admin(&args.store)?;
    let packed = select_packed_admin(&admin, args.node.as_deref())?;
    let configuration = graph.configuration_id();

    let report = match args.operation {
        CampaignStorePackedTransformCommand::Plan => {
            plan_packed_repack(&journal, configuration, packed)?
        }
        CampaignStorePackedTransformCommand::Apply => {
            apply_packed_repack(&journal, configuration, packed)?
        }
    };
    render_packed_repack(&report, format)
}

fn plan_packed_repack(
    journal: &PackedRepackJournal,
    configuration: StoreGraphConfigurationId,
    packed: StoreGraphPackedRepackAdmin<'_>,
) -> Result<PackedRepackReportView, CliError> {
    let plan = packed
        .plan()
        .map_err(|error| transform_error(format!("packed repack planning failed: {error}")))?;
    let configuration = encode_bytes(&configuration.as_bytes());
    let node = packed.node().as_str().to_owned();
    let plan_id = encode_bytes(&plan.id().as_bytes());
    let canonical_plan = encode_bytes(&plan.canonical_bytes());

    if journal.record_path().exists() {
        let existing = journal.read()?;
        validate_journal_basis(&existing, &configuration, &node)?;
        if existing.plan != canonical_plan {
            return Err(transform_error(
                "packed repack journal names another exact-generation plan",
            ));
        }
        return report_from_journal(journal, existing, true);
    }

    let before = plan.before().into();
    let record = PackedRepackJournalRecord {
        schema: PACKED_REPACK_JOURNAL_SCHEMA.to_owned(),
        version: PACKED_REPACK_JOURNAL_VERSION,
        configuration: configuration.clone(),
        node: node.clone(),
        plan: canonical_plan,
        phase: PackedRepackJournalPhase::Planned,
        applied: None,
    };
    journal.publish(&record)?;

    Ok(PackedRepackReportView {
        schema: PACKED_REPACK_REPORT_SCHEMA,
        operation: "plan",
        phase: PackedRepackJournalPhase::Planned,
        configuration,
        node,
        plan: plan_id,
        journal: journal.root.display().to_string(),
        replayed: false,
        before,
        after: None,
        removed_packs: None,
    })
}

fn apply_packed_repack(
    journal: &PackedRepackJournal,
    configuration: StoreGraphConfigurationId,
    packed: StoreGraphPackedRepackAdmin<'_>,
) -> Result<PackedRepackReportView, CliError> {
    let mut record = journal.read()?;
    let configuration = encode_bytes(&configuration.as_bytes());
    let node = packed.node().as_str().to_owned();
    validate_journal_basis(&record, &configuration, &node)?;

    let plan_bytes = decode_bytes(&record.plan)?;
    let plan = PackedRepackPlan::from_canonical_bytes(&plan_bytes).map_err(|error| {
        transform_error(format!("packed repack journal plan is invalid: {error}"))
    })?;
    let applied = packed
        .apply(&plan)
        .map_err(|error| transform_error(format!("packed repack apply failed: {error}")))?;
    let observed = PackedRepackAppliedRecord {
        before: applied.before().into(),
        after: applied.after().into(),
        removed_packs: applied.removed_packs(),
    };
    if record.phase == PackedRepackJournalPhase::Applied {
        let recorded = record
            .applied
            .as_ref()
            .ok_or_else(|| transform_error("applied packed repack omitted terminal accounting"))?;
        if applied.plan() != plan.id()
            || recorded.before != observed.before
            || recorded.after != observed.after
        {
            return Err(transform_error(
                "applied packed repack journal disagrees with the current backend generation",
            ));
        }
        return report_from_journal(journal, record, true);
    }

    record.phase = PackedRepackJournalPhase::Applied;
    record.applied = Some(observed);
    journal.publish(&record)?;

    let applied_record = record
        .applied
        .as_ref()
        .ok_or_else(|| transform_error("applied packed repack omitted terminal accounting"))?;
    Ok(PackedRepackReportView {
        schema: PACKED_REPACK_REPORT_SCHEMA,
        operation: "apply",
        phase: record.phase,
        configuration,
        node,
        plan: encode_bytes(&applied.plan().as_bytes()),
        journal: journal.root.display().to_string(),
        replayed: applied.replayed(),
        before: applied_record.before,
        after: Some(applied_record.after),
        removed_packs: Some(applied_record.removed_packs),
    })
}

fn report_from_journal(
    journal: &PackedRepackJournal,
    record: PackedRepackJournalRecord,
    replayed: bool,
) -> Result<PackedRepackReportView, CliError> {
    let plan_bytes = decode_bytes(&record.plan)?;
    let plan = PackedRepackPlan::from_canonical_bytes(&plan_bytes).map_err(|error| {
        transform_error(format!("packed repack journal plan is invalid: {error}"))
    })?;
    let applied = record.applied.as_ref();
    Ok(PackedRepackReportView {
        schema: PACKED_REPACK_REPORT_SCHEMA,
        operation: match record.phase {
            PackedRepackJournalPhase::Planned => "plan",
            PackedRepackJournalPhase::Applied => "apply",
        },
        phase: record.phase,
        configuration: record.configuration,
        node: record.node,
        plan: encode_bytes(&plan.id().as_bytes()),
        journal: journal.root.display().to_string(),
        replayed,
        before: plan.before().into(),
        after: applied.map(|value| value.after),
        removed_packs: applied.map(|value| value.removed_packs),
    })
}

fn select_packed_admin<'a>(
    admin: &'a StoreGraphAdmin,
    requested: Option<&str>,
) -> Result<StoreGraphPackedRepackAdmin<'a>, CliError> {
    let packed = admin.packed_repack();
    if let Some(requested) = requested {
        let requested = StoreNodeId::new(requested.to_owned())
            .map_err(|error| usage_error(format!("invalid packed node ID: {error}")))?;
        return packed
            .into_iter()
            .find(|entry| entry.node() == &requested)
            .ok_or_else(|| transform_error("requested node is not an admitted packed leaf"));
    }
    match packed.as_slice() {
        [only] => Ok(*only),
        [] => Err(transform_error(
            "store graph contains no packed leaf eligible for repack",
        )),
        _ => Err(usage_error(
            "store graph contains multiple packed leaves; select one with --node",
        )),
    }
}

struct PackedRepackJournal {
    root: std::path::PathBuf,
    _lock: File,
}

impl PackedRepackJournal {
    fn open(root: &Path) -> Result<Self, CliError> {
        fs::create_dir(root).or_else(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists && root.is_dir() {
                Ok(())
            } else {
                Err(error)
            }
        })?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(root.join(JOURNAL_LOCK))?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            transform_error(format!("packed repack journal is already owned: {error}"))
        })?;
        discard_stale_staging(root)?;
        File::open(root)?.sync_all()?;
        Ok(Self {
            root: root.to_path_buf(),
            _lock: lock,
        })
    }

    fn record_path(&self) -> std::path::PathBuf {
        self.root.join(JOURNAL_RECORD)
    }

    fn read(&self) -> Result<PackedRepackJournalRecord, CliError> {
        let mut bytes = Vec::new();
        File::open(self.record_path())?
            .take(MAXIMUM_JOURNAL_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAXIMUM_JOURNAL_RECORD_BYTES {
            return Err(transform_error(
                "packed repack journal record exceeds its bound",
            ));
        }
        let record: PackedRepackJournalRecord =
            serde_json::from_slice(&bytes).map_err(|error| {
                transform_error(format!("packed repack journal is invalid: {error}"))
            })?;
        validate_journal_contract(&record)?;
        Ok(record)
    }

    fn publish(&self, record: &PackedRepackJournalRecord) -> Result<(), CliError> {
        let bytes = serde_json::to_vec(record)
            .map_err(|error| transform_error(format!("encode packed repack journal: {error}")))?;
        if bytes.len() as u64 > MAXIMUM_JOURNAL_RECORD_BYTES {
            return Err(transform_error(
                "packed repack journal record exceeds its bound",
            ));
        }
        let staging_path = self.root.join(JOURNAL_STAGING);
        let mut staging = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging_path)
            .map_err(|error| {
                transform_error(format!(
                    "packed repack journal has an incomplete staged record: {error}"
                ))
            })?;
        if let Err(error) = staging.write_all(&bytes).and_then(|()| staging.sync_all()) {
            return Err(transform_error(format!(
                "persist packed repack journal staging record: {error}"
            )));
        }
        fs::rename(&staging_path, self.record_path())?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

fn discard_stale_staging(root: &Path) -> Result<(), CliError> {
    let staging = root.join(JOURNAL_STAGING);
    match fs::symlink_metadata(&staging) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(&staging)?;
            File::open(root)?.sync_all()?;
            Ok(())
        }
        Ok(_) => Err(transform_error(
            "packed repack journal staging path is not a regular file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_journal_contract(record: &PackedRepackJournalRecord) -> Result<(), CliError> {
    if record.schema != PACKED_REPACK_JOURNAL_SCHEMA
        || record.version != PACKED_REPACK_JOURNAL_VERSION
        || (record.phase == PackedRepackJournalPhase::Planned && record.applied.is_some())
        || (record.phase == PackedRepackJournalPhase::Applied && record.applied.is_none())
    {
        return Err(transform_error(
            "packed repack journal has an incompatible contract",
        ));
    }
    Ok(())
}

fn validate_journal_basis(
    record: &PackedRepackJournalRecord,
    configuration: &str,
    node: &str,
) -> Result<(), CliError> {
    validate_journal_contract(record)?;
    if record.configuration != configuration || record.node != node {
        return Err(transform_error(
            "packed repack journal does not match the store configuration and node",
        ));
    }
    Ok(())
}

fn validate_journal_path(path: &Path) -> Result<(), CliError> {
    if !path.is_absolute() {
        return Err(usage_error("packed repack journal path must be absolute"));
    }
    Ok(())
}

fn render_packed_repack(
    report: &PackedRepackReportView,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| transform_error(format!("encode packed repack report: {error}"))),
        OutputFormat::Table => Ok(format!(
            "operation={} phase={:?} configuration={} node={} plan={} journal={} replayed={} before-generation={} after-generation={}",
            report.operation,
            report.phase,
            report.configuration,
            report.node,
            report.plan,
            report.journal,
            report.replayed,
            report.before.generation,
            report
                .after
                .map(|accounting| accounting.generation.to_string())
                .unwrap_or_else(|| String::from("none")),
        )),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| operation | {} |\n| phase | {:?} |\n| configuration | `{}` |\n| node | `{}` |\n| plan | `{}` |\n| journal | `{}` |\n| replayed | {} |",
            report.operation,
            report.phase,
            report.configuration,
            report.node,
            report.plan,
            report.journal,
            report.replayed,
        )),
    }
}

fn encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_bytes(encoded: &str) -> Result<Vec<u8>, CliError> {
    if !encoded.len().is_multiple_of(2) || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(transform_error(
            "packed repack journal plan encoding is malformed",
        ));
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)
                .map_err(|_| transform_error("packed repack journal plan encoding is malformed"))?;
            u8::from_str_radix(pair, 16)
                .map_err(|_| transform_error("packed repack journal plan encoding is malformed"))
        })
        .collect()
}

fn transform_error(message: impl Into<String>) -> CliError {
    backend_error(message)
}

#[cfg(test)]
mod tests {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    use crucible_cas::content_store::{BlobHandle, ContentId, ImmutableBlobBackend, ObjectKind};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn packed_transform_plan_apply_and_reopen_are_exact() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = PackedTransformFixture::new()?;
        fixture.put(b"first packed transform object")?;
        fixture.put(b"second packed transform object")?;
        let plan_args = fixture.args(CampaignStorePackedTransformCommand::Plan);

        let planned = run_packed_repack(&plan_args, OutputFormat::Jsonl)?;
        let planned: serde_json::Value = serde_json::from_str(&planned)?;
        assert_eq!(planned["operation"], "plan");
        assert_eq!(planned["phase"], "planned");
        assert_eq!(planned["replayed"], false);
        assert_eq!(planned["before"]["logical_objects"], 2);

        let replayed_plan = run_packed_repack(&plan_args, OutputFormat::Jsonl)?;
        let replayed_plan: serde_json::Value = serde_json::from_str(&replayed_plan)?;
        assert_eq!(replayed_plan["plan"], planned["plan"]);
        assert_eq!(replayed_plan["replayed"], true);

        let apply_args = fixture.args(CampaignStorePackedTransformCommand::Apply);
        let applied = run_packed_repack(&apply_args, OutputFormat::Jsonl)?;
        let applied: serde_json::Value = serde_json::from_str(&applied)?;
        assert_eq!(applied["operation"], "apply");
        assert_eq!(applied["phase"], "applied");
        assert_eq!(applied["before"]["generation"], 2);
        assert_eq!(applied["after"]["generation"], 3);

        let replayed_apply = run_packed_repack(&apply_args, OutputFormat::Jsonl)?;
        let replayed_apply: serde_json::Value = serde_json::from_str(&replayed_apply)?;
        assert_eq!(replayed_apply["plan"], planned["plan"]);
        assert_eq!(replayed_apply["replayed"], true);
        Ok(())
    }

    #[test]
    fn packed_transform_rejects_a_stale_generation() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = PackedTransformFixture::new()?;
        fixture.put(b"planned packed transform object")?;
        run_packed_repack(
            &fixture.args(CampaignStorePackedTransformCommand::Plan),
            OutputFormat::Jsonl,
        )?;

        fixture.put(b"post-plan packed transform mutation")?;
        let error = run_packed_repack(
            &fixture.args(CampaignStorePackedTransformCommand::Apply),
            OutputFormat::Jsonl,
        )
        .err()
        .ok_or("stale repack unexpectedly succeeded")?;
        assert!(error.to_string().contains("packed repack apply failed"));
        Ok(())
    }

    #[test]
    fn applied_packed_transform_reauthenticates_the_backend_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = PackedTransformFixture::new()?;
        fixture.put(b"packed transform object")?;
        run_packed_repack(
            &fixture.args(CampaignStorePackedTransformCommand::Plan),
            OutputFormat::Jsonl,
        )?;
        run_packed_repack(
            &fixture.args(CampaignStorePackedTransformCommand::Apply),
            OutputFormat::Jsonl,
        )?;

        fixture.put(b"mutation after applied packed transform")?;
        let error = run_packed_repack(
            &fixture.args(CampaignStorePackedTransformCommand::Apply),
            OutputFormat::Jsonl,
        )
        .err()
        .ok_or("applied journal trusted after a later backend mutation")?;
        assert!(error.to_string().contains("packed repack apply failed"));
        Ok(())
    }

    #[test]
    fn packed_transform_discards_interrupted_journal_staging_on_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = PackedTransformFixture::new()?;
        fixture.put(b"packed transform object")?;
        fs::create_dir(&fixture.journal)?;
        fs::write(
            fixture.journal.join(JOURNAL_STAGING),
            b"interrupted planned staging",
        )?;

        run_packed_repack(
            &fixture.args(CampaignStorePackedTransformCommand::Plan),
            OutputFormat::Jsonl,
        )?;
        assert!(!fixture.journal.join(JOURNAL_STAGING).exists());

        fs::write(
            fixture.journal.join(JOURNAL_STAGING),
            b"interrupted applied staging",
        )?;
        let applied = run_packed_repack(
            &fixture.args(CampaignStorePackedTransformCommand::Apply),
            OutputFormat::Jsonl,
        )?;
        let applied: serde_json::Value = serde_json::from_str(&applied)?;
        assert_eq!(applied["phase"], "applied");
        assert!(!fixture.journal.join(JOURNAL_STAGING).exists());

        fs::write(
            fixture.journal.join(JOURNAL_STAGING),
            b"interrupted replay staging",
        )?;
        let replayed = run_packed_repack(
            &fixture.args(CampaignStorePackedTransformCommand::Apply),
            OutputFormat::Jsonl,
        )?;
        let replayed: serde_json::Value = serde_json::from_str(&replayed)?;
        assert_eq!(replayed["replayed"], true);
        assert!(!fixture.journal.join(JOURNAL_STAGING).exists());
        Ok(())
    }

    #[test]
    fn packed_transform_requires_an_explicit_node_for_multiple_leaves()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = PackedTransformFixture::new_with_two_packed_leaves()?;
        let mut args = fixture.args(CampaignStorePackedTransformCommand::Plan);
        let error = run_packed_repack(&args, OutputFormat::Jsonl)
            .err()
            .ok_or("ambiguous packed transform unexpectedly succeeded")?;
        assert!(matches!(error, CliError::Usage(_)));

        args.node = Some(String::from("first"));
        let planned = run_packed_repack(&args, OutputFormat::Jsonl)?;
        let planned: serde_json::Value = serde_json::from_str(&planned)?;
        assert_eq!(planned["node"], "first");
        Ok(())
    }

    struct PackedTransformFixture {
        _directory: TempDir,
        store: std::path::PathBuf,
        journal: std::path::PathBuf,
    }

    impl PackedTransformFixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            Self::with_store_nodes(false)
        }

        fn new_with_two_packed_leaves() -> Result<Self, Box<dyn std::error::Error>> {
            Self::with_store_nodes(true)
        }

        fn with_store_nodes(two: bool) -> Result<Self, Box<dyn std::error::Error>> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), Permissions::from_mode(0o700))?;
            let refs = secure_directory(directory.path(), "refs")?;
            let first = secure_directory(directory.path(), "first-packed")?;
            let store = directory.path().join("store.toml");
            let (root, nodes) = if two {
                let second = secure_directory(directory.path(), "second-packed")?;
                (
                    "mirror",
                    format!(
                        r#"
[[nodes]]
id = "mirror"
[nodes.spec]
kind = "write-through"
children = ["first", "second"]

[[nodes]]
id = "first"
[nodes.spec]
kind = "packed"
root = {first:?}
target_pack_bytes = 65536

[[nodes]]
id = "second"
[nodes.spec]
kind = "packed"
root = {second:?}
target_pack_bytes = 65536
"#,
                    ),
                )
            } else {
                (
                    "packed",
                    format!(
                        r#"
[[nodes]]
id = "packed"
[nodes.spec]
kind = "packed"
root = {first:?}
target_pack_bytes = 65536
"#,
                    ),
                )
            };
            fs::write(
                &store,
                format!(
                    r#"schema = "crucible.campaign-repository-store"
version = 2
root = "{root}"
admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
ref_directory = {refs:?}
{nodes}"#,
                ),
            )?;
            fs::set_permissions(&store, Permissions::from_mode(0o600))?;
            let journal = directory.path().join("repack-journal");
            Ok(Self {
                _directory: directory,
                store,
                journal,
            })
        }

        fn args(
            &self,
            operation: CampaignStorePackedTransformCommand,
        ) -> CampaignStorePackedTransformArgs {
            CampaignStorePackedTransformArgs {
                store: self.store.clone(),
                journal: self.journal.clone(),
                node: None,
                operation,
            }
        }

        fn put(&self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
            let graph = crate::cli_campaign_store::load_campaign_store_graph(&self.store)?;
            let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
            graph.put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))?;
            Ok(())
        }
    }

    fn secure_directory(
        root: &Path,
        name: &str,
    ) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let path = root.join(name);
        fs::create_dir(&path)?;
        fs::set_permissions(&path, Permissions::from_mode(0o700))?;
        Ok(path)
    }
}
