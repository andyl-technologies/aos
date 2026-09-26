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
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crucible_campaign::{
    CAMPAIGN_OBJECT_PROFILE_POLICY_V1, CampaignHash, CampaignName, CampaignObjectProfiler,
    CampaignPolicy, CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignServiceOperation,
};
use crucible_cas::content_store::{
    BlobHandle, CompressedDirectoryBlobBackend, ContentId, DirectoryBlobBackend,
    ImmutableBlobBackend, ObjectKind, StoreGraph, StoreGraphKeyring,
    StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers, StoreGraphPhysicalQuotaBinders,
    StoreGraphS3Clients, StoreNodeId, StoreNodeSpec, StoreObjectProfilePolicyId,
    WriteBackRetentionAdmin,
};
use crucible_daemon::{DirectoryCampaignGcJournal, UnixPeerCampaignPolicy};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};

const CAMPAIGN: &str = "worked-network";
const PRINCIPAL: &str = "operator";
const START_COMMAND: &str = "4242424242424242424242424242424242424242424242424242424242424242";
const PAUSE_COMMAND: &str = "4343434343434343434343434343434343434343434343434343434343434343";
const RESUME_COMMAND: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const MAX_CAMPAIGN_SERVICE_STDERR_BYTES: u64 = 64 * 1024;
const MAXIMUM_LOGICAL_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_PENDING_OBJECTS: u64 = 65_536;
const MAXIMUM_PENDING_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(feature = "packaged-midpoint-flight")]
#[path = "campaign_store_process/canonical_branch.rs"]
mod canonical_branch;
#[cfg(feature = "packaged-midpoint-flight")]
#[path = "campaign_store_process/finding_exact_vm.rs"]
mod finding_exact_vm;
#[cfg(feature = "packaged-midpoint-flight")]
#[path = "campaign_store_process/midpoint_debug.rs"]
mod midpoint_debug;
#[path = "support/campaign_packaged_process.rs"]
mod packaged;
#[path = "campaign_store_process/service_diagnostics.rs"]
mod service_diagnostics;

use service_diagnostics::{
    append_process_diagnostics, descendant_process_commands, matching_lines_bounded,
};

#[test]
fn packaged_campaign_service_uses_mtls_without_debug_authority() -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    let args = fixture
        .service_command(None)
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(args.iter().any(|arg| arg == "--tls-cert"));
    assert!(args.iter().any(|arg| arg == "--tls-key"));
    assert!(args.iter().any(|arg| arg == "--client-ca"));
    assert!(
        !args
            .iter()
            .any(|arg| arg == "--trusted-unauthenticated-bind")
    );
    assert!(!args.iter().any(|arg| arg == "--debug-role"));
    let _ = crucible_api::mutual_tls_acceptor_from_pem(
        &fixture.tls_cert,
        &fixture.tls_key,
        &fixture.tls_ca,
    )?;
    for _ in 0..3 {
        let mut service = fixture.start_service(None)?;
        service.stop()?;
    }
    Ok(())
}

#[cfg(feature = "packaged-midpoint-flight")]
#[test]
fn packaged_midpoint_service_keeps_explicit_debug_authority() -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new_debug_authorized()?;
    let args = fixture
        .service_command(None)
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(
        args.iter()
            .any(|arg| arg == "--trusted-unauthenticated-bind")
    );
    assert!(!args.iter().any(|arg| arg == "--tls-cert"));
    Ok(())
}

#[test]
fn packaged_guest_choice_policy_grants_only_the_required_graph_query() -> Result<(), Box<dyn Error>>
{
    let fixture = FlightFixture::new()?;
    let policy = UnixPeerCampaignPolicy::from_toml_bytes(&fs::read(&fixture.peer_policy)?)?;
    let principal = CampaignPrincipal::new(PRINCIPAL)?;
    let campaign = CampaignName::new(CAMPAIGN)?;
    let request_digest = CampaignHash::derive("packaged-guest-choice-policy-test", b"graph");

    policy.authorize(
        &principal,
        CampaignServiceOperation::QueryCampaignGraph,
        &campaign,
        request_digest,
    )?;
    assert!(
        policy
            .authorize(
                &principal,
                CampaignServiceOperation::QueryCampaignFindings,
                &campaign,
                request_digest,
            )
            .is_err(),
        "the fixture correction must not grant unrelated graph-adjacent queries"
    );
    Ok(())
}

#[cfg(feature = "packaged-midpoint-flight")]
#[test]
fn public_campaign_debug_opens_authenticated_finding_at_fast_midpoint() -> Result<(), Box<dyn Error>>
{
    midpoint_debug::run_public_campaign_debug_flight_with_stopped_finding(
        midpoint_debug::FindingScenario::MarkerOnly,
        canonical_branch::run_imported_canonical_branch,
    )
}

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
    let live_report = campaign_report(&fixture, &live_snapshot)?;
    assert_eq!(live_report["schema"], "crucible.cli.campaign-report.v1");
    assert_eq!(live_report["snapshot"], live_snapshot);
    assert_eq!(live_report["explored_attempts"], 0);
    assert_eq!(live_report["stopped_attempts"], 0);
    assert_eq!(live_report["failed_attempts"], 0);
    assert_eq!(live_report["unexplored_attempts"], 0);
    assert!(live_report.get("unvisited_continuations").is_some());
    assert!(live_report.get("exhausted_continuations").is_some());
    assert!(live_report.get("pruned_continuations").is_some());
    assert_eq!(live_report["complete"], true);

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
    let reopened_report = campaign_report(&fixture, &live_snapshot)?;
    assert_eq!(reopened_report["snapshot"], live_report["snapshot"]);
    assert_eq!(reopened_report["state"], live_report["state"]);
    assert_eq!(reopened_report["estimate"], live_report["estimate"]);
    assert_eq!(
        reopened_report["estimator_endpoints"],
        live_report["estimator_endpoints"]
    );
    restarted.stop()?;

    Ok(())
}

#[test]
fn public_checkpoint_pause_survives_stopped_service_gc_and_cold_resume()
-> Result<(), Box<dyn Error>> {
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
        "generate checkpoint-pause fixture",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    let lineage = json_path(&generated, "lineage")?;
    let policy = json_path(&generated, "policy")?;

    let mut service = fixture.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(&fixture)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy)
            .args(["--start-command", START_COMMAND]),
        "start checkpoint-pause campaign",
    )?;
    let running = campaign_status(&fixture)?;
    assert_eq!(running["state"], "running");
    let running_snapshot = json_string(&running, "snapshot")?;

    run_json(
        connected_campaign(&fixture).args([
            "pause",
            CAMPAIGN,
            "--expected",
            &running_snapshot,
            "--command",
            PAUSE_COMMAND,
            "--active",
            "checkpoint",
        ]),
        "request exact checkpoint pause",
    )?;
    let paused = campaign_status(&fixture)?;
    assert_eq!(paused["state"], "paused");
    let paused_snapshot = json_string(&paused, "snapshot")?;
    assert_ne!(paused_snapshot, running_snapshot);
    service.stop()?;

    let planned = run_json(&mut fixture.gc_command("plan"), "plan paused-owner GC")?;
    assert_eq!(planned["phase"], "planned");
    let applied = run_json(&mut fixture.gc_command("apply"), "apply paused-owner GC")?;
    assert_eq!(applied["apply_status"], "applied");

    let mut restarted = fixture.start_service(None)?;
    let reopened = campaign_status(&fixture)?;
    assert_eq!(reopened["state"], "paused");
    assert_eq!(reopened["snapshot"], paused_snapshot);
    run_json(
        connected_campaign(&fixture).args([
            "resume",
            CAMPAIGN,
            "--expected",
            &paused_snapshot,
            "--command",
            RESUME_COMMAND,
        ]),
        "resume cold checkpoint-paused campaign",
    )?;
    let resumed = campaign_status(&fixture)?;
    assert_eq!(resumed["state"], "running");
    assert_ne!(resumed["snapshot"], paused_snapshot);
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
    assert_eq!(planned["plan_version"], "v1");
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
    assert_eq!(after_maintenance["plan_version"], "v1");
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

#[path = "campaign_store_process/archive_transfer.rs"]
mod archive_transfer;

struct FlightFixture {
    _temporary: TempDir,
    fixture: PathBuf,
    state: PathBuf,
    objects: PathBuf,
    socket: PathBuf,
    peer_policy: PathBuf,
    store: PathBuf,
    journal: PathBuf,
    tls_ca: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    service_mode: FlightServiceMode,
}

#[derive(Clone, Copy)]
enum FlightServiceMode {
    Campaign,
    #[cfg(feature = "packaged-midpoint-flight")]
    Debugger,
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
version = 2
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
    #[cfg(feature = "packaged-midpoint-flight")]
    fn new_debug_authorized() -> Result<Self, Box<dyn Error>> {
        let mut fixture = Self::new()?;
        fixture.service_mode = FlightServiceMode::Debugger;
        Ok(fixture)
    }

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
        let tls_ca = root.join("campaign-ca.pem");
        let tls_cert = root.join("campaign-server.pem");
        let tls_key = root.join("campaign-server-key.pem");

        // The HTTP listener is unused by this flight. Authentic mTLS keeps its
        // debugger policy empty while the Unix campaign principal remains active.
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;
        let mut server_params = CertificateParams::new(vec![String::from("127.0.0.1")])?;
        server_params.is_ca = IsCa::ExplicitNoCa;
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &ca)?;
        fs::write(&tls_ca, ca.pem())?;
        fs::write(&tls_cert, server_cert.pem())?;
        fs::write(&tls_key, server_key.serialize_pem())?;
        fs::set_permissions(&tls_key, fs::Permissions::from_mode(0o600))?;

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
operation = "derive-campaign"
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
operation = "query-campaign-report"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "watch-campaign"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign-snapshot"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign-graph-object"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "query-campaign-graph"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "query-campaign-request-attempts"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "query-campaign-choices"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign-choice-object"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "submit-branch-request"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "explain-campaign-attempt"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign-trace-chunk"
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
version = 2
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
            tls_ca,
            tls_cert,
            tls_key,
            service_mode: FlightServiceMode::Campaign,
        })
    }

    fn start_service(&self, import: Option<&Path>) -> Result<CampaignServiceChild, Box<dyn Error>> {
        self.start_service_command(self.service_command(import), Duration::from_secs(15))
    }

    fn service_command(&self, import: Option<&Path>) -> Command {
        let mut command = command(&["serve", "--listen", "127.0.0.1:0"]);
        match self.service_mode {
            FlightServiceMode::Campaign => {
                command
                    .arg("--tls-cert")
                    .arg(&self.tls_cert)
                    .arg("--tls-key")
                    .arg(&self.tls_key)
                    .arg("--client-ca")
                    .arg(&self.tls_ca);
            }
            #[cfg(feature = "packaged-midpoint-flight")]
            FlightServiceMode::Debugger => {
                command.arg("--trusted-unauthenticated-bind");
            }
        }
        command
            .arg("--campaign-socket")
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
        let stderr = NamedTempFile::new_in(self._temporary.path())?;
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr.reopen()?));
        let child = command.spawn()?;
        let mut child = CampaignServiceChild {
            child,
            #[cfg(feature = "packaged-midpoint-flight")]
            daemon_url: String::new(),
            stderr,
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
                let service_process = match child.child.try_wait() {
                    Ok(Some(exit)) => format!("exited({exit})"),
                    Ok(None) => format!("running(pid={})", child.child.id()),
                    Err(status_error) => format!("status-error({status_error})"),
                };
                let mut diagnostics = format!("service={service_process}");
                append_process_diagnostics(&mut diagnostics);

                let _ = child.child.kill();
                let _ = wait_for_exit(&mut child.child, Duration::from_secs(5));
                let stderr = child.stderr_tail();
                return Err(format!("{error}; {diagnostics}; stderr={stderr}").into());
            }
        };
        let scheme = match self.service_mode {
            FlightServiceMode::Campaign => "https://",
            #[cfg(feature = "packaged-midpoint-flight")]
            FlightServiceMode::Debugger => "http://",
        };
        if !announcement.contains(scheme) {
            return Err(format!("invalid service announcement: {announcement}").into());
        }
        #[cfg(feature = "packaged-midpoint-flight")]
        {
            child.daemon_url = announcement
                .split_once(" at ")
                .and_then(|(_, suffix)| suffix.split_once(" mode="))
                .map(|(url, _)| url.to_owned())
                .ok_or_else(|| {
                    format!("service announcement omitted its daemon URL: {announcement}")
                })?;
        }
        wait_for_campaign_socket(&self.socket, timeout)?;
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
    #[cfg(feature = "packaged-midpoint-flight")]
    daemon_url: String,
    stderr: NamedTempFile,
    kill_on_drop: bool,
}

impl CampaignServiceChild {
    #[cfg(feature = "packaged-midpoint-flight")]
    fn daemon_url(&self) -> &str {
        &self.daemon_url
    }

    fn stop(&mut self) -> Result<(), Box<dyn Error>> {
        let signal = send_sigterm(&self.child);
        // The packaged pool has a thirty-second bounded cleanup window.
        let status = wait_for_exit(&mut self.child, Duration::from_secs(45));
        let stderr = self.stderr_tail();
        if !stderr.is_empty() {
            eprintln!("campaign service stderr: {stderr}");
        }
        signal.map_err(|error| format!("{error}; stderr={stderr}"))?;
        let status = status.map_err(|error| format!("{error}; stderr={stderr}"))?;
        if !status.success() {
            return Err(format!("campaign service failed: {status}; stderr={stderr}").into());
        }
        self.kill_on_drop = false;
        Ok(())
    }

    fn stderr_tail(&self) -> String {
        let Ok(mut stderr) = self.stderr.reopen() else {
            return String::from("<campaign service stderr unavailable>");
        };
        let Ok(length) = stderr.metadata().map(|metadata| metadata.len()) else {
            return String::from("<campaign service stderr metadata unavailable>");
        };
        let start = length.saturating_sub(MAX_CAMPAIGN_SERVICE_STDERR_BYTES);
        if stderr.seek(SeekFrom::Start(start)).is_err() {
            return String::from("<campaign service stderr seek failed>");
        }

        let mut bytes = Vec::with_capacity(
            usize::try_from(length - start).unwrap_or(MAX_CAMPAIGN_SERVICE_STDERR_BYTES as usize),
        );
        if stderr
            .take(MAX_CAMPAIGN_SERVICE_STDERR_BYTES)
            .read_to_end(&mut bytes)
            .is_err()
        {
            return String::from("<campaign service stderr read failed>");
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Reads exact stderr records with `prefix` without retaining unrelated output.
    fn stderr_lines_with_prefix(
        &self,
        prefix: &str,
        maximum_lines: usize,
        maximum_line_bytes: usize,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let stderr = self.stderr.reopen()?;
        matching_lines_bounded(stderr, prefix, maximum_lines, maximum_line_bytes)
    }
}

impl Drop for CampaignServiceChild {
    fn drop(&mut self) {
        if self.kill_on_drop {
            let signal = send_sigterm(&self.child);
            let graceful = wait_for_exit(&mut self.child, Duration::from_secs(45));
            let forced = if graceful.is_err() {
                let _ = self.child.kill();
                Some(wait_for_exit(&mut self.child, Duration::from_secs(5)))
            } else {
                None
            };

            let stderr = self.stderr_tail();
            if signal.is_err() || graceful.is_err() || !stderr.is_empty() {
                eprintln!(
                    "campaign service failure cleanup: signal={signal:?} graceful={graceful:?} forced={forced:?} stderr={stderr}"
                );
            }
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

fn campaign_report(fixture: &FlightFixture, snapshot: &str) -> Result<Value, Box<dyn Error>> {
    run_json(
        connected_campaign(fixture).args([
            "report",
            CAMPAIGN,
            "--snapshot",
            snapshot,
            "--pages",
            "2",
        ]),
        "read campaign report",
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

fn wait_for_campaign_socket(path: &Path, timeout: Duration) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => return Ok(()),
            Ok(_) => return Err("campaign endpoint is not a Unix socket".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "campaign endpoint was not bound before the readiness deadline: {}",
                        path.display()
                    )
                    .into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
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
            return Err("campaign service did not exit before timeout".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}
