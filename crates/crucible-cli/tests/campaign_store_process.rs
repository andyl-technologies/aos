//! Hermetic process flight for the public campaign-store porcelain.
//!
//! The flight uses only the shipped `crucible` process for fixture generation,
//! import validation, daemon ownership, campaign creation, inspection, and GC.
//! Test setup injects one authenticated orphan placement to model crash debris;
//! the public plan/apply commands must reclaim it without breaking restart.

#![cfg(target_os = "linux")]
// crucible-lint: allow clippy-disallowed-method -- this process boundary test intentionally exercises host process methods.
// crucible-lint: allow panic-shortcut -- assertions localize failures in a single hermetic operator flight.
#![allow(clippy::disallowed_methods, clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crucible_campaign::{
    CAMPAIGN_OBJECT_PROFILE_POLICY_V1, CampaignObjectProfiler, CampaignPolicy,
};
use crucible_cas::content_store::{
    BlobHandle, CompressedDirectoryBlobBackend, ContentId, DirectoryBlobBackend,
    ImmutableBlobBackend, ObjectKind, StoreGraph, StoreGraphKeyring,
    StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers, StoreGraphPhysicalQuotaBinders,
    StoreGraphS3Clients, StoreNodeId, StoreNodeSpec, StoreObjectProfilePolicyId,
    WriteBackRetentionAdmin,
};
use crucible_daemon::DirectoryCampaignGcJournal;
use serde_json::Value;
use tempfile::TempDir;

const CAMPAIGN: &str = "worked-network";
const PRINCIPAL: &str = "operator";
const START_COMMAND: &str = "4242424242424242424242424242424242424242424242424242424242424242";
const MAXIMUM_LOGICAL_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_PENDING_OBJECTS: u64 = 65_536;
const MAXIMUM_PENDING_BYTES: u64 = 512 * 1024 * 1024;

#[path = "support/campaign_packaged_process.rs"]
mod packaged;

#[test]
fn public_campaign_store_flight_survives_gc_and_service_restart() -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;

    let generated = run_json(
        command(&[
            "--format",
            "jsonl",
            "campaign",
            "fixture",
            "worked-network",
            "--output",
        ])
        .arg(&fixture.fixture),
        "generate worked-network fixture",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    let lineage = json_path(&generated, "lineage")?;
    let policy = json_path(&generated, "policy")?;
    let scenario_artifact = json_string(&generated, "scenario")?;
    let scenario = typed_content_id(&scenario_artifact)?;

    let validated = run_json(
        command(&["--format", "jsonl", "campaign", "validate-import"]).arg(&manifest),
        "validate generated import manifest",
    )?;
    assert_eq!(
        validated["schema"],
        "crucible.cli.campaign-import-validation.v1"
    );

    let mut service = fixture.start_service(Some(&manifest))?;
    let created = run_json(
        connected_campaign(&fixture)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy)
            .args(["--start-command", START_COMMAND]),
        "create and start imported campaign",
    )?;
    assert_eq!(created["schema"], "crucible.cli.campaign-acceptance.v3");
    assert_eq!(created["campaign"], CAMPAIGN);
    assert_eq!(created["replayed"], false);
    assert_eq!(created["start"]["command"], START_COMMAND);

    let live_head = campaign_status(&fixture)?;
    assert_eq!(live_head["state"], "running");
    let live_snapshot = json_string(&live_head, "snapshot")?;

    let store_status = run_json(
        command(&["--format", "jsonl", "store", "status"]).arg(&fixture.store),
        "inspect live composed store",
    )?;
    assert_eq!(store_status["schema"], "crucible.cli.store-status.v1");
    assert_eq!(store_status["root"], "primary");
    assert_eq!(store_status["nodes"][0]["kind"], "directory");

    let ensured = run_json(
        command(&["--format", "jsonl", "store", "ensure", &scenario, "--in"]).arg(&fixture.store),
        "authenticate imported scenario through live store",
    )?;
    assert_eq!(ensured["content"], scenario);
    assert_eq!(ensured["authenticated"], true);

    let before_orphan = fixture.verify_store()?;
    let retained_placements = json_u64(&before_orphan, "placements")?;
    assert!(retained_placements > 0);

    service.stop()?;

    let orphan_bytes = b"authenticated campaign-store process-flight orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    DirectoryBlobBackend::new("process-flight-primary", &fixture.objects)
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.to_vec()))?;
    let orphan_id = orphan.encode();
    let orphan_ensured = run_json(
        command(&["--format", "jsonl", "store", "ensure", &orphan_id, "--in"]).arg(&fixture.store),
        "authenticate injected orphan",
    )?;
    assert_eq!(orphan_ensured["logical_bytes"], orphan_bytes.len());

    let with_orphan = fixture.verify_store()?;
    assert_eq!(
        json_u64(&with_orphan, "placements")?,
        retained_placements + 1
    );

    let planned = run_json(&mut fixture.gc_command("plan"), "plan stopped-owner GC")?;
    assert_eq!(planned["schema"], "crucible.cli.campaign-store-gc.v2");
    assert_eq!(planned["operation"], "plan");
    assert_eq!(planned["phase"], "planned");
    let candidates = json_u64(&planned, "candidates")?;
    assert!(candidates >= 1);
    assert_eq!(json_u64(&planned, "unreachable_candidates")?, candidates);
    assert_eq!(json_u64(&planned, "reachable_cache_candidates")?, 0);
    assert!(json_u64(&planned, "candidate_logical_bytes")? >= orphan_bytes.len() as u64);

    let applied = run_json(&mut fixture.gc_command("apply"), "apply stopped-owner GC")?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["phase"], "complete");
    assert_eq!(applied["apply_status"], "applied");

    let after_gc = fixture.verify_store()?;
    let expected_placements = retained_placements
        .checked_add(1)
        .and_then(|placements| placements.checked_sub(candidates))
        .ok_or("GC candidate count exceeds the authenticated physical inventory")?;
    assert_eq!(json_u64(&after_gc, "placements")?, expected_placements);
    let missing_orphan = command(&["--format", "jsonl", "store", "ensure", &orphan_id, "--in"])
        .arg(&fixture.store)
        .output()?;
    assert!(!missing_orphan.status.success());
    assert!(String::from_utf8_lossy(&missing_orphan.stderr).contains("store ensure read failed"));
    let retained_scenario = run_json(
        command(&["--format", "jsonl", "store", "ensure", &scenario, "--in"]).arg(&fixture.store),
        "reauthenticate retained scenario after GC",
    )?;
    assert_eq!(retained_scenario["authenticated"], true);

    let mut restarted = fixture.start_service(None)?;
    let reopened_head = campaign_status(&fixture)?;
    assert_eq!(reopened_head["snapshot"], live_snapshot);
    assert_eq!(reopened_head["state"], "running");
    restarted.stop()?;

    Ok(())
}

#[test]
fn public_composed_store_flight_evicts_cache_and_flushes_write_back() -> Result<(), Box<dyn Error>>
{
    let fixture = ComposedFlightFixture::new()?;
    let generated = run_json(
        command(&[
            "--format",
            "jsonl",
            "campaign",
            "fixture",
            "worked-network",
            "--output",
        ])
        .arg(&fixture.base.fixture),
        "generate composed-store fixture",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    let lineage = json_path(&generated, "lineage")?;
    let policy_path = json_path(&generated, "policy")?;
    let scenario = ContentId::parse(&typed_content_id(&json_string(&generated, "scenario")?)?)?;
    let policy = CampaignPolicy::from_canonical_bytes(&fs::read(&policy_path)?)?
        .id()?
        .content_id();

    let mut service = fixture.base.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(&fixture.base)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy_path)
            .args(["--start-command", START_COMMAND]),
        "create campaign through composed store",
    )?;
    let live_head = campaign_status(&fixture.base)?;
    let live_snapshot = json_string(&live_head, "snapshot")?;

    let store_status = run_json(
        command(&["--format", "jsonl", "store", "status"]).arg(&fixture.base.store),
        "inspect composed store graph",
    )?;
    assert_eq!(store_status["root"], "profile");
    let node_kinds = store_status["nodes"]
        .as_array()
        .ok_or("store status omitted node descriptions")?
        .iter()
        .map(|node| Ok((json_string(node, "id")?, json_string(node, "kind")?)))
        .collect::<Result<BTreeMap<_, _>, Box<dyn Error>>>()?;
    assert_eq!(
        node_kinds,
        BTreeMap::from([
            (String::from("profile"), String::from("profile-validated")),
            (
                String::from("read-cache"),
                String::from("compressed-directory")
            ),
            (String::from("read-source"), String::from("directory")),
            (String::from("read-through"), String::from("read-through")),
            (String::from("routed"), String::from("routed")),
            (String::from("verified"), String::from("verified")),
            (String::from("write-back"), String::from("write-back")),
            (String::from("write-destination"), String::from("directory"),),
            (
                String::from("write-staging"),
                String::from("compressed-directory"),
            ),
        ])
    );

    let scenario_text = scenario.encode();
    let ensured = run_json(
        command(&[
            "--format",
            "jsonl",
            "store",
            "ensure",
            &scenario_text,
            "--in",
        ])
        .arg(&fixture.base.store),
        "promote scenario through read-through cache",
    )?;
    assert_eq!(ensured["authenticated"], true);
    assert!(fixture.read_source().contains(scenario)?);
    assert!(fixture.read_cache()?.contains(scenario)?);
    service.stop()?;

    let pending_before_gc = fixture.pending_write_back_roots()?;
    assert!(!pending_before_gc.is_empty());
    assert!(
        pending_before_gc
            .iter()
            .all(|(node, _id)| node == "write-back")
    );
    assert!(pending_before_gc.contains(&(String::from("write-back"), policy)));

    let planned = run_json(
        &mut fixture.base.gc_command_at("plan", &fixture.base.journal),
        "plan composed-store GC",
    )?;
    assert_eq!(planned["schema"], "crucible.cli.campaign-store-gc.v2");
    assert_eq!(planned["plan_version"], "v2");
    assert!(json_u64(&planned, "reachable_cache_candidates")? >= 1);
    assert!(
        planned["cache_required_copies"]
            .as_array()
            .is_some_and(|copies| copies.iter().any(|copy| {
                copy["candidate_backend"] == "read-cache"
                    && copy["required_backend"] == "read-source"
                    && copy["content"] == scenario_text
            }))
    );
    {
        let journal = DirectoryCampaignGcJournal::open(&fixture.base.journal)?;
        assert!(journal.roots().iter().any(|root| root == policy));
    }

    let applied = run_json(
        &mut fixture.base.gc_command_at("apply", &fixture.base.journal),
        "apply composed-store GC",
    )?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["apply_status"], "applied");
    assert!(!fixture.read_cache()?.contains(scenario)?);
    assert!(fixture.read_source().contains(scenario)?);
    assert!(
        fixture
            .pending_write_back_roots()?
            .contains(&(String::from("write-back"), policy))
    );

    let mut maintained = fixture.start_service_with_maintenance()?;
    fixture.wait_until_write_back_root_absent(policy, Duration::from_secs(20))?;
    assert!(fixture.write_destination().contains(policy)?);
    maintained.stop()?;
    assert!(
        !fixture
            .pending_write_back_roots()?
            .contains(&(String::from("write-back"), policy))
    );

    let after_maintenance = run_json(
        &mut fixture
            .base
            .gc_command_at("plan", &fixture.after_maintenance_gc_journal),
        "plan GC after write-back maintenance",
    )?;
    assert_eq!(after_maintenance["plan_version"], "v2");
    {
        let journal = DirectoryCampaignGcJournal::open(&fixture.after_maintenance_gc_journal)?;
        assert!(!journal.roots().iter().any(|root| root == policy));
    }

    let mut restarted = fixture.base.start_service(None)?;
    let reopened_head = campaign_status(&fixture.base)?;
    assert_eq!(reopened_head["snapshot"], live_snapshot);
    let reopened_snapshot = run_json(
        connected_campaign(&fixture.base).args([
            "snapshot",
            CAMPAIGN,
            "--snapshot",
            &live_snapshot,
        ]),
        "read canonical snapshot after composed-store restart",
    )?;
    assert_eq!(reopened_snapshot["snapshot"]["id"], live_snapshot);
    let reauthenticated = run_json(
        command(&[
            "--format",
            "jsonl",
            "store",
            "ensure",
            &scenario_text,
            "--in",
        ])
        .arg(&fixture.base.store),
        "read canonical scenario after composed-store restart",
    )?;
    assert_eq!(reauthenticated["authenticated"], true);
    restarted.stop()?;

    Ok(())
}

#[test]
fn public_offline_archive_transfer_reports_and_authenticates_sensitive_closure()
-> Result<(), Box<dyn Error>> {
    let source = FlightFixture::new()?;
    let destination = FlightFixture::new()?;
    let generated = run_json(
        command(&[
            "--format",
            "jsonl",
            "campaign",
            "fixture",
            "worked-network",
            "--output",
        ])
        .arg(&source.fixture),
        "generate archive source fixture",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    let lineage = json_path(&generated, "lineage")?;
    let policy = json_path(&generated, "policy")?;
    let mut service = source.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(&source)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy),
        "create archive source campaign",
    )?;
    let snapshot = json_string(&campaign_status(&source)?, "snapshot")?;
    service.stop()?;

    let trace_bytes = b"sensitive offline archive trace";
    let trace = ContentId::for_bytes(ObjectKind::Trace, 1, trace_bytes);
    DirectoryBlobBackend::new("archive-source-trace", &source.objects)
        .put_if_absent(trace, &BlobHandle::from_bytes(trace_bytes.to_vec()))?;
    let trace = trace.encode();

    // A symlink alias bypasses lexical source/destination comparison. The
    // second owner acquisition must still fail immediately on the same lock.
    let state_alias = source._temporary.path().join("state-alias");
    symlink(&source.state, &state_alias)?;
    let mut aliased = command(&[
        "--format",
        "jsonl",
        "campaign",
        "archive",
        "transfer",
        "--source-state",
    ]);
    aliased
        .arg(&source.state)
        .arg("--source-policy")
        .arg(&source.peer_policy)
        .arg("--source-store")
        .arg(&source.store)
        .args(["--source-campaign", CAMPAIGN, "--snapshot", &snapshot])
        .args(["--mode", "metadata"])
        .arg("--destination-state")
        .arg(&state_alias)
        .arg("--destination-policy")
        .arg(&source.peer_policy)
        .arg("--destination-store")
        .arg(&source.store)
        .args(["--archive", "aliased-owner"]);
    let aliased = output_with_timeout(aliased, Duration::from_secs(5))?;
    assert!(!aliased.status.success());
    let aliased_error = String::from_utf8_lossy(&aliased.stderr);
    assert!(
        aliased_error.contains("repository is already in use")
            || aliased_error.contains("state directory is invalid"),
        "unexpected aliased-owner failure: {aliased_error}",
    );

    let mut transfer = command(&[
        "--format",
        "jsonl",
        "campaign",
        "archive",
        "transfer",
        "--source-state",
    ]);
    let output = transfer
        .arg(&source.state)
        .arg("--source-policy")
        .arg(&source.peer_policy)
        .arg("--source-store")
        .arg(&source.store)
        .args(["--source-campaign", CAMPAIGN, "--snapshot", &snapshot])
        .args(["--mode", "mirror", "--retain", &trace])
        .arg("--destination-state")
        .arg(&destination.state)
        .arg("--destination-policy")
        .arg(&destination.peer_policy)
        .arg("--destination-store")
        .arg(&destination.store)
        .args(["--archive", "offline-copy"])
        .output()?;
    require_success(&output, "transfer offline archive")?;
    let preflight: Value = serde_json::from_slice(&output.stderr)?;
    let completion: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(preflight["schema"], "crucible.cli.campaign-archive-plan.v1");
    assert_eq!(preflight["phase"], "pre-transfer");
    assert!(
        preflight["sensitive_classes"]
            .as_array()
            .is_some_and(|classes| classes.iter().any(|class| class == "trace"))
    );
    let trace_class = preflight["classes"]
        .as_array()
        .and_then(|classes| classes.iter().find(|class| class["class"] == "trace"))
        .ok_or("pre-transfer report omitted trace class")?;
    assert_eq!(trace_class["logical_bytes"], trace_bytes.len());
    assert!(trace_class["physical_bytes"].is_null());
    assert_eq!(
        completion["schema"],
        "crucible.cli.campaign-archive-transfer.v1"
    );
    assert_eq!(completion["phase"], "complete");
    assert_eq!(completion["authenticated"], true);

    let inspected = run_json(
        command(&[
            "--format", "jsonl", "campaign", "archive", "inspect", "--state",
        ])
        .arg(&destination.state)
        .arg("--policy")
        .arg(&destination.peer_policy)
        .arg("--store")
        .arg(&destination.store)
        .args(["--archive", "offline-copy"]),
        "inspect offline archive",
    )?;
    assert_eq!(
        inspected["schema"],
        "crucible.cli.campaign-archive-inspection.v1"
    );
    assert_eq!(inspected["manifest"], completion["manifest"]);
    assert_eq!(inspected["authenticated"], true);
    assert!(
        inspected["sensitive_classes"]
            .as_array()
            .is_some_and(|classes| classes.iter().any(|class| class == "trace"))
    );

    Ok(())
}

struct FlightFixture {
    _temporary: TempDir,
    fixture: PathBuf,
    state: PathBuf,
    objects: PathBuf,
    socket: PathBuf,
    peer_policy: PathBuf,
    store: PathBuf,
    journal: PathBuf,
}

struct ComposedFlightFixture {
    base: FlightFixture,
    read_cache_root: PathBuf,
    read_source_root: PathBuf,
    write_staging_root: PathBuf,
    write_destination_root: PathBuf,
    write_back_journal: PathBuf,
    after_maintenance_gc_journal: PathBuf,
}

impl ComposedFlightFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let base = FlightFixture::new()?;
        let root = base._temporary.path();
        let read_cache_root = secure_directory(root, "read-cache")?;
        let read_source_root = secure_directory(root, "read-source")?;
        let write_staging_root = secure_directory(root, "write-staging")?;
        let write_destination_root = secure_directory(root, "write-destination")?;
        let write_back_journal = secure_directory(root, "write-back-journal")?;
        let after_maintenance_gc_journal = root.join("gc-journal-after-maintenance");
        let refs = root.join("refs");

        fs::write(
            &base.store,
            format!(
                r#"schema = "crucible.campaign-repository-store"
version = 1
root = "profile"
admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
ref_directory = {refs:?}

[[nodes]]
id = "profile"
[nodes.spec]
kind = "profile-validated"
child = "verified"
policy = "crucible.campaign.object-profile.v1"

[[nodes]]
id = "verified"
[nodes.spec]
kind = "verified"
child = "routed"

[[nodes]]
id = "routed"
[nodes.spec]
kind = "routed"
[nodes.spec.routes]
campaign-fact = "write-back"
campaign-snapshot = "write-back"
merkle-node = "write-back"
scenario = "read-through"
configuration = "write-back"
policy = "write-back"
exact-manifest = "write-back"
ram-extent = "write-back"
disk-extent = "write-back"
device-state = "write-back"
observation = "write-back"
finding = "write-back"
projection = "read-through"
trace = "read-through"

[[nodes]]
id = "read-through"
[nodes.spec]
kind = "read-through"
cache = "read-cache"
source = "read-source"

[[nodes]]
id = "read-cache"
[nodes.spec]
kind = "compressed-directory"
root = {read_cache_root:?}
maximum_logical_object_bytes = {MAXIMUM_LOGICAL_OBJECT_BYTES}

[[nodes]]
id = "read-source"
[nodes.spec]
kind = "directory"
root = {read_source_root:?}

[[nodes]]
id = "write-back"
[nodes.spec]
kind = "write-back"
staging = "write-staging"
destination = "write-destination"
journal_root = {write_back_journal:?}
maximum_pending_objects = {MAXIMUM_PENDING_OBJECTS}
maximum_pending_bytes = {MAXIMUM_PENDING_BYTES}

[[nodes]]
id = "write-staging"
[nodes.spec]
kind = "compressed-directory"
root = {write_staging_root:?}
maximum_logical_object_bytes = {MAXIMUM_LOGICAL_OBJECT_BYTES}

[[nodes]]
id = "write-destination"
[nodes.spec]
kind = "directory"
root = {write_destination_root:?}
"#,
            ),
        )?;
        fs::set_permissions(&base.store, fs::Permissions::from_mode(0o600))?;

        Ok(Self {
            base,
            read_cache_root,
            read_source_root,
            write_staging_root,
            write_destination_root,
            write_back_journal,
            after_maintenance_gc_journal,
        })
    }

    fn start_service_with_maintenance(&self) -> Result<CampaignServiceChild, Box<dyn Error>> {
        let mut command = self.base.service_command(None);
        command.args([
            "--campaign-maintenance-interval-ms",
            "100",
            "--campaign-maintenance-write-back-transfers",
            "65536",
        ]);
        self.base
            .start_service_command(command, Duration::from_secs(15))
    }

    fn read_cache(&self) -> Result<CompressedDirectoryBlobBackend, Box<dyn Error>> {
        Ok(CompressedDirectoryBlobBackend::new(
            "read-cache",
            &self.read_cache_root,
            MAXIMUM_LOGICAL_OBJECT_BYTES,
        )?)
    }

    fn read_source(&self) -> DirectoryBlobBackend {
        DirectoryBlobBackend::new("read-source", &self.read_source_root)
    }

    fn write_destination(&self) -> DirectoryBlobBackend {
        DirectoryBlobBackend::new("write-destination", &self.write_destination_root)
    }

    fn pending_write_back_roots(&self) -> Result<BTreeSet<(String, ContentId)>, Box<dyn Error>> {
        let graph = self.inspection_graph()?;
        let mut fence = graph.acquire_write_back_retention_fence()?;
        let mut roots = BTreeSet::new();
        fence.visit_roots(&mut |root| {
            roots.insert((root.node().to_owned(), root.id()));
            Ok(())
        })?;
        Ok(roots)
    }

    fn wait_until_write_back_root_absent(
        &self,
        id: ContentId,
        timeout: Duration,
    ) -> Result<(), Box<dyn Error>> {
        let expected = (String::from("write-back"), id);
        let deadline = Instant::now() + timeout;
        loop {
            if !self.pending_write_back_roots()?.contains(&expected) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "write-back maintenance did not acknowledge {id} before timeout"
                )
                .into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn inspection_graph(&self) -> Result<StoreGraph, Box<dyn Error>> {
        let read_cache = node_id("read-cache")?;
        let read_source = node_id("read-source")?;
        let read_through = node_id("read-through")?;
        let write_staging = node_id("write-staging")?;
        let write_destination = node_id("write-destination")?;
        let write_back = node_id("write-back")?;
        let routed = node_id("routed")?;
        let verified = node_id("verified")?;
        let profile = node_id("profile")?;

        let mut routes = all_campaign_object_kinds()
            .into_iter()
            .map(|kind| (kind, write_back.clone()))
            .collect::<BTreeMap<_, _>>();
        for kind in [
            ObjectKind::Scenario,
            ObjectKind::Projection,
            ObjectKind::Trace,
        ] {
            routes.insert(kind, read_through.clone());
        }

        let config = crucible_cas::content_store::StoreGraphConfig {
            root: profile.clone(),
            admitted_kinds: BTreeSet::from(all_campaign_object_kinds()),
            nodes: BTreeMap::from([
                (
                    read_cache.clone(),
                    StoreNodeSpec::CompressedDirectory {
                        root: self.read_cache_root.clone(),
                        maximum_logical_object_bytes: MAXIMUM_LOGICAL_OBJECT_BYTES,
                    },
                ),
                (
                    read_source.clone(),
                    StoreNodeSpec::Directory {
                        root: self.read_source_root.clone(),
                    },
                ),
                (
                    read_through,
                    StoreNodeSpec::ReadThrough {
                        cache: read_cache,
                        source: read_source,
                    },
                ),
                (
                    write_staging.clone(),
                    StoreNodeSpec::CompressedDirectory {
                        root: self.write_staging_root.clone(),
                        maximum_logical_object_bytes: MAXIMUM_LOGICAL_OBJECT_BYTES,
                    },
                ),
                (
                    write_destination.clone(),
                    StoreNodeSpec::Directory {
                        root: self.write_destination_root.clone(),
                    },
                ),
                (
                    write_back.clone(),
                    StoreNodeSpec::WriteBack {
                        staging: write_staging,
                        destination: write_destination,
                        journal_root: self.write_back_journal.clone(),
                        maximum_pending_objects: MAXIMUM_PENDING_OBJECTS,
                        maximum_pending_bytes: MAXIMUM_PENDING_BYTES,
                    },
                ),
                (routed.clone(), StoreNodeSpec::Routed { routes }),
                (verified.clone(), StoreNodeSpec::Verified { child: routed }),
                (
                    profile,
                    StoreNodeSpec::ProfileValidated {
                        child: verified,
                        policy: StoreObjectProfilePolicyId::new(CAMPAIGN_OBJECT_PROFILE_POLICY_V1)?,
                    },
                ),
            ]),
        };
        let mut profilers = StoreGraphObjectProfilers::new();
        profilers.insert(
            StoreObjectProfilePolicyId::new(CAMPAIGN_OBJECT_PROFILE_POLICY_V1)?,
            Arc::new(CampaignObjectProfiler),
        )?;

        Ok(StoreGraph::build_with_all_capabilities(
            config,
            &StoreGraphKeyring::new(),
            &StoreGraphNamespaceAuthorizers::new(),
            &profilers,
            &StoreGraphPhysicalQuotaBinders::new(),
            &StoreGraphS3Clients::new(),
        )?)
    }
}

impl FlightFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().to_path_buf();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let state = secure_directory(&root, "state")?;
        let objects = secure_directory(&root, "objects")?;
        let refs = secure_directory(&root, "refs")?;
        let fixture = root.join("fixture");
        let socket = root.join("campaign.sock");
        let peer_policy = root.join("peer-policy.toml");
        let store = root.join("store.toml");
        let journal = root.join("gc-journal");

        let metadata = fs::metadata(&root)?;
        fs::write(
            &peer_policy,
            format!(
                r#"schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = {}
group_id = {}
principal = "{PRINCIPAL}"

[[grants]]
principal = "{PRINCIPAL}"
operation = "create-campaign"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "apply-campaign-command"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign-status"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign-snapshot"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "explain-campaign-attempt"
campaign = "*"
"#,
                metadata.uid(),
                metadata.gid(),
            ),
        )?;
        fs::set_permissions(&peer_policy, fs::Permissions::from_mode(0o600))?;

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
"#,
            ),
        )?;
        fs::set_permissions(&store, fs::Permissions::from_mode(0o600))?;

        Ok(Self {
            _temporary: temporary,
            fixture,
            state,
            objects,
            socket,
            peer_policy,
            store,
            journal,
        })
    }

    fn start_service(&self, import: Option<&Path>) -> Result<CampaignServiceChild, Box<dyn Error>> {
        self.start_service_command(self.service_command(import), Duration::from_secs(15))
    }

    fn service_command(&self, import: Option<&Path>) -> Command {
        let mut command = command(&[
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--trusted-unauthenticated-bind",
            "--campaign-socket",
        ]);
        command
            .arg(&self.socket)
            .arg("--campaign-state")
            .arg(&self.state)
            .arg("--campaign-policy")
            .arg(&self.peer_policy)
            .arg("--campaign-store")
            .arg(&self.store);
        if let Some(import) = import {
            command.arg("--campaign-import-manifest").arg(import);
        }
        command
    }

    fn start_service_command(
        &self,
        mut command: Command,
        timeout: Duration,
    ) -> Result<CampaignServiceChild, Box<dyn Error>> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = command.spawn()?;
        let mut child = CampaignServiceChild {
            child,
            kill_on_drop: true,
        };
        let stdout = child
            .child
            .stdout
            .take()
            .ok_or("campaign service stdout was not piped")?;
        let announcement = match read_first_line(stdout, timeout) {
            Ok(line) => line,
            Err(error) => {
                let _ = child.child.kill();
                let _ = child.child.wait();
                let mut stderr = String::new();
                if let Some(mut stream) = child.child.stderr.take() {
                    stream.read_to_string(&mut stderr)?;
                }
                return Err(format!("{error}; stderr={stderr}").into());
            }
        };
        if !announcement.contains("http://") {
            return Err(format!("invalid service announcement: {announcement}").into());
        }
        let metadata = fs::metadata(&self.socket)?;
        if !metadata.file_type().is_socket() {
            return Err("campaign endpoint is not a Unix socket".into());
        }
        Ok(child)
    }

    fn verify_store(&self) -> Result<Value, Box<dyn Error>> {
        run_json(
            command(&["--format", "jsonl", "store", "verify"]).arg(&self.store),
            "verify complete physical inventory",
        )
    }

    fn gc_command(&self, operation: &str) -> Command {
        self.gc_command_at(operation, &self.journal)
    }

    fn gc_command_at(&self, operation: &str, journal: &Path) -> Command {
        let mut command = command(&["--format", "jsonl", "store", "gc", "--state"]);
        command
            .arg(&self.state)
            .arg("--policy")
            .arg(&self.peer_policy)
            .arg("--store")
            .arg(&self.store)
            .arg("--journal")
            .arg(journal)
            .arg(operation);
        command
    }
}

struct CampaignServiceChild {
    child: Child,
    kill_on_drop: bool,
}

impl CampaignServiceChild {
    fn stop(&mut self) -> Result<(), Box<dyn Error>> {
        send_sigterm(&self.child)?;
        // The packaged pool has a thirty-second bounded cleanup window.
        let status = wait_for_exit(&mut self.child, Duration::from_secs(45));
        let mut stderr = String::new();
        if let Some(mut stream) = self.child.stderr.take() {
            stream.read_to_string(&mut stderr)?;
        }
        if !stderr.is_empty() {
            eprintln!("campaign service stderr: {stderr}");
        }
        let status = status.map_err(|error| format!("{error}; stderr={stderr}"))?;
        if !status.success() {
            return Err(format!("campaign service failed: {status}; stderr={stderr}").into());
        }
        self.kill_on_drop = false;
        Ok(())
    }
}

impl Drop for CampaignServiceChild {
    fn drop(&mut self) {
        if self.kill_on_drop {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn connected_campaign(fixture: &FlightFixture) -> Command {
    let mut command = command(&["--format", "jsonl", "campaign", "--socket"]);
    command
        .arg(&fixture.socket)
        .args(["--principal", PRINCIPAL]);
    command
}

fn campaign_status(fixture: &FlightFixture) -> Result<Value, Box<dyn Error>> {
    run_json(
        connected_campaign(fixture).args(["status", CAMPAIGN]),
        "read campaign head",
    )
}

fn command(arguments: &[&str]) -> Command {
    // The hermetic VM copies both built executables into its store closure;
    // the build-time Cargo target path itself is not available in the guest.
    let binary = std::env::var_os("CRUCIBLE_PROCESS_FLIGHT_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_crucible").into());
    let mut command = Command::new(binary);
    command.args(arguments);
    command
}

fn run_json(command: &mut Command, operation: &str) -> Result<Value, Box<dyn Error>> {
    let output = command.output()?;
    parse_json_output(output, operation)
}

fn output_with_timeout(mut command: Command, timeout: Duration) -> Result<Output, Box<dyn Error>> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("archive command did not reject aliased ownership before timeout".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn parse_json_output(output: Output, operation: &str) -> Result<Value, Box<dyn Error>> {
    require_success(&output, operation)?;
    let stdout = String::from_utf8(output.stdout)?;
    let mut lines = stdout.lines();
    let line = lines
        .next()
        .ok_or_else(|| format!("{operation} returned empty stdout"))?;
    if lines.next().is_some() {
        return Err(format!("{operation} returned more than one JSONL record").into());
    }
    Ok(serde_json::from_str(line)?)
}

fn require_success(output: &Output, operation: &str) -> Result<(), Box<dyn Error>> {
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{operation} failed with {}; stdout=`{}` stderr=`{}`",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
    .into())
}

fn json_string(value: &Value, field: &str) -> Result<String, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("JSON field `{field}` is not a string").into())
}

fn json_path(value: &Value, field: &str) -> Result<PathBuf, Box<dyn Error>> {
    json_string(value, field).map(PathBuf::from)
}

fn typed_content_id(value: &str) -> Result<String, Box<dyn Error>> {
    value
        .split_once('@')
        .map(|(_, content)| content.to_owned())
        .ok_or_else(|| format!("typed campaign ID `{value}` does not contain a content ID").into())
}

fn json_u64(value: &Value, field: &str) -> Result<u64, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("JSON field `{field}` is not an unsigned integer").into())
}

fn node_id(value: &str) -> Result<StoreNodeId, Box<dyn Error>> {
    Ok(StoreNodeId::new(value)?)
}

const fn all_campaign_object_kinds() -> [ObjectKind; 14] {
    [
        ObjectKind::CampaignFact,
        ObjectKind::CampaignSnapshot,
        ObjectKind::MerkleNode,
        ObjectKind::Scenario,
        ObjectKind::Configuration,
        ObjectKind::Policy,
        ObjectKind::ExactManifest,
        ObjectKind::RamExtent,
        ObjectKind::DiskExtent,
        ObjectKind::DeviceState,
        ObjectKind::Observation,
        ObjectKind::Finding,
        ObjectKind::Projection,
        ObjectKind::Trace,
    ]
}

fn secure_directory(root: &Path, name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = root.join(name);
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

fn read_first_line(
    stdout: impl Read + Send + 'static,
    timeout: Duration,
) -> Result<String, Box<dyn Error>> {
    let (sender, receiver) = std_mpsc::channel();
    thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        let result = stdout.read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
        // Keep the pipe open for subsequent listener announcements and logs.
        // A first-line-only reader can otherwise make a healthy daemon fail
        // its next stdout write with EPIPE.
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
    });
    match receiver.recv_timeout(timeout) {
        Ok(Ok(line)) if !line.is_empty() => Ok(line),
        Ok(Ok(_)) => Err("campaign service exited before announcing its listener".into()),
        Ok(Err(error)) => Err(Box::new(error)),
        Err(std_mpsc::RecvTimeoutError::Timeout) => {
            Err("campaign service did not announce its listener before timeout".into())
        }
        Err(std_mpsc::RecvTimeoutError::Disconnected) => {
            Err("campaign service stdout reader exited without a result".into())
        }
    }
}

fn send_sigterm(child: &Child) -> Result<(), Box<dyn Error>> {
    let pid = i32::try_from(child.id())?;
    // SAFETY: `pid` is the live child process ID returned by `Child`. Sending
    // SIGTERM does not dereference memory and reports failure through errno.
    let result = unsafe { libc::kill(pid, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(Box::new(std::io::Error::last_os_error()))
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<ExitStatus, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("campaign service did not exit before timeout".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}
