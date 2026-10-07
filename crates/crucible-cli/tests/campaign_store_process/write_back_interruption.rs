//! Public write-back recovery across loss of an uncommitted snapshot publisher.
//!
//! The existing recovery feature terminates the actual service after durable
//! snapshot staging and pending-journal publication, before authoritative ref
//! CAS. This host-process control does not model guest checkpoint or progress.

use super::*;

use crucible_campaign::{CampaignSnapshot, CampaignSnapshotId, ObjectEnvelope};
use crucible_cas::content_store::{DirectoryRefBackend, MutableRefBackend, RefName};

const SNAPSHOT_PUBLICATION_TRIGGER: &str =
    "crucible.destructive-recovery.daemon-during-snapshot-publication";
const TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
const PUBLICATION_EXIT_CODE: i32 = 86;

struct RetainedSnapshot {
    identity: CampaignSnapshotId,
    bytes: Vec<u8>,
}

struct PendingObjects {
    bytes: BTreeMap<ContentId, Vec<u8>>,
    journal: Vec<u8>,
}

#[test]
fn public_write_back_snapshot_process_loss_retains_roots_and_retries() -> Result<(), Box<dyn Error>>
{
    let fixture = ComposedFlightFixture::new()?;
    let retained = create_campaigns(&fixture)?;
    let before = pending_objects(&fixture)?;
    assert!(!before.bytes.is_empty());
    assert_authoritative_heads(&fixture, &retained)?;

    let mut fault_command = fixture.base.service_command(None);
    fault_command.env(TRIGGER_ENVIRONMENT, SNAPSHOT_PUBLICATION_TRIGGER);
    let mut publisher = fixture
        .base
        .start_service_command(fault_command, Duration::from_secs(15))?;
    assert_live_heads(&fixture, &retained)?;
    assert_eq!(pending_objects(&fixture)?.bytes, before.bytes);

    let prior = retained
        .get(CAMPAIGN)
        .ok_or("retained main campaign is absent")?;
    let rejected = output_with_timeout(
        pause_command(&fixture, prior.identity),
        Duration::from_secs(15),
    )?;
    assert!(
        !rejected.status.success(),
        "the interrupted public mutation was acknowledged"
    );
    let exited = wait_for_exit(&mut publisher.child, Duration::from_secs(5))?;
    assert_eq!(
        exited.code(),
        Some(PUBLICATION_EXIT_CODE),
        "wrong publication exit; command stderr={}; service stderr={}",
        String::from_utf8_lossy(&rejected.stderr),
        publisher.stderr_tail(),
    );
    // Only a reaped, exact original fault exit ends this test owner's custody.
    publisher.kill_on_drop = false;
    drop(publisher);

    let interrupted = pending_objects(&fixture)?;
    assert!(
        before
            .bytes
            .iter()
            .all(|(id, bytes)| interrupted.bytes.get(id) == Some(bytes))
    );
    let unpublished = interrupted_snapshot(&interrupted, &before, prior.identity)?;
    assert!(
        retained
            .values()
            .all(|snapshot| snapshot.identity != unpublished)
    );
    assert!(
        !fixture
            .write_destination()
            .contains(unpublished.content_id())?
    );
    assert_authoritative_heads(&fixture, &retained)?;
    println!("write_back_uncommitted_snapshot_process_exit=86");

    reclaim_orphan_without_pending_deletion(&fixture, &interrupted)?;
    assert_authoritative_heads(&fixture, &retained)?;
    println!("write_back_pending_publication_roots_survive_public_gc=true");

    let mut recovered_command = fixture.base.service_command(None);
    recovered_command.env_remove(TRIGGER_ENVIRONMENT);
    let mut recovered = fixture
        .base
        .start_service_command(recovered_command, Duration::from_secs(15))?;
    assert_live_heads(&fixture, &retained)?;
    let accepted = run_json(
        &mut pause_command(&fixture, prior.identity),
        "recover the identical interrupted public pause",
    )?;
    assert_eq!(accepted["prior_snapshot"], prior.identity.to_text());
    assert_eq!(accepted["new_snapshot"], unpublished.to_text());
    assert_eq!(accepted["command"], PAUSE_COMMAND);
    assert_eq!(accepted["replayed"], false);
    let replayed = run_json(
        &mut pause_command(&fixture, prior.identity),
        "replay the recovered public pause",
    )?;
    assert_eq!(replayed["new_snapshot"], unpublished.to_text());
    assert_eq!(replayed["replayed"], true);

    let mut completed = retained;
    let graph = fixture.inspection_graph()?;
    completed.insert(
        CAMPAIGN.to_owned(),
        RetainedSnapshot {
            identity: unpublished,
            bytes: graph
                .read(unpublished.content_id(), None)?
                .read_all(MAXIMUM_LOGICAL_OBJECT_BYTES)?,
        },
    );
    assert_live_heads(&fixture, &completed)?;
    recovered.stop()?;
    println!("write_back_interrupted_publication_identical_recovery=true");

    complete_pending_and_reclaim_staging(&fixture, &completed)?;
    println!("write_back_process_recovery_all_pending_completed=true");
    Ok(())
}

/// Creates the original three public refs without enabling the fault hook.
fn create_campaigns(
    fixture: &ComposedFlightFixture,
) -> Result<BTreeMap<String, RetainedSnapshot>, Box<dyn Error>> {
    let generated = run_json(
        unarmed(
            command(&[
                "--format",
                "jsonl",
                "campaign",
                "fixture",
                "worked-network",
                "--output",
            ])
            .arg(&fixture.base.fixture),
        ),
        "generate write-back process-loss fixture",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    let lineage = json_path(&generated, "lineage")?;
    let policy = json_path(&generated, "policy")?;
    let mut service_command = fixture.base.service_command(Some(&manifest));
    service_command.env_remove(TRIGGER_ENVIRONMENT);
    let mut service = fixture
        .base
        .start_service_command(service_command, Duration::from_secs(15))?;
    run_json(
        unarmed(
            connected_campaign(&fixture.base)
                .args(["create", CAMPAIGN, "--lineage"])
                .arg(&lineage)
                .arg("--policy")
                .arg(&policy)
                .args(["--start-command", START_COMMAND]),
        ),
        "create write-back main campaign",
    )?;

    let mut retained = BTreeMap::new();
    let mut parent = retain_live_head(fixture, CAMPAIGN, &mut retained)?;
    let mut parent_name = CAMPAIGN;
    for derived in DERIVED_CAMPAIGNS {
        run_json(
            unarmed(connected_campaign(&fixture.base).args([
                "derive",
                parent_name,
                "--snapshot",
                &parent.to_text(),
                derived,
            ])),
            "derive a retained write-back campaign",
        )?;
        let next = retain_live_head(fixture, derived, &mut retained)?;
        assert_ne!(next, parent);
        parent = next;
        parent_name = derived;
    }
    assert_eq!(retained.len(), 3);
    assert_eq!(
        retained
            .values()
            .map(|snapshot| snapshot.identity)
            .collect::<BTreeSet<_>>()
            .len(),
        3,
    );
    service.stop()?;
    Ok(retained)
}

fn retain_live_head(
    fixture: &ComposedFlightFixture,
    name: &str,
    retained: &mut BTreeMap<String, RetainedSnapshot>,
) -> Result<CampaignSnapshotId, Box<dyn Error>> {
    let status = live_status(fixture, name)?;
    let identity = CampaignSnapshotId::parse(&json_string(&status, "snapshot")?)?;
    let bytes = fixture
        .inspection_graph()?
        .read(identity.content_id(), None)?
        .read_all(MAXIMUM_LOGICAL_OBJECT_BYTES)?;
    retained.insert(name.to_owned(), RetainedSnapshot { identity, bytes });
    Ok(identity)
}

fn live_status(fixture: &ComposedFlightFixture, name: &str) -> Result<Value, Box<dyn Error>> {
    run_json(
        unarmed(connected_campaign(&fixture.base).args(["status", name])),
        "authenticate the public write-back campaign head",
    )
}

fn assert_live_heads(
    fixture: &ComposedFlightFixture,
    retained: &BTreeMap<String, RetainedSnapshot>,
) -> Result<(), Box<dyn Error>> {
    for (name, snapshot) in retained {
        assert_eq!(
            live_status(fixture, name)?["snapshot"],
            snapshot.identity.to_text()
        );
        let inspected = run_json(
            unarmed(connected_campaign(&fixture.base).args([
                "snapshot",
                name,
                "--snapshot",
                &snapshot.identity.to_text(),
            ])),
            "authenticate retained canonical snapshot after process loss",
        )?;
        assert_eq!(inspected["snapshot"]["id"], snapshot.identity.to_text());
    }
    assert_authoritative_heads(fixture, retained)
}

/// Uses the real authoritative backend, independently of a service connection.
fn assert_authoritative_heads(
    fixture: &ComposedFlightFixture,
    retained: &BTreeMap<String, RetainedSnapshot>,
) -> Result<(), Box<dyn Error>> {
    let refs = DirectoryRefBackend::new(fixture.base._temporary.path().join("refs"));
    let graph = fixture.inspection_graph()?;
    for (name, snapshot) in retained {
        let reference = RefName::new(format!("campaigns/{name}"))?;
        assert_eq!(
            refs.read_ref(&reference)?,
            Some(snapshot.identity.content_id())
        );
        assert_eq!(
            graph
                .read(snapshot.identity.content_id(), None)?
                .read_all(MAXIMUM_LOGICAL_OBJECT_BYTES)?,
            snapshot.bytes,
        );
    }
    Ok(())
}

fn pause_command(fixture: &ComposedFlightFixture, prior: CampaignSnapshotId) -> Command {
    let mut command = connected_campaign(&fixture.base);
    command
        .args([
            "pause",
            CAMPAIGN,
            "--expected",
            &prior.to_text(),
            "--command",
            PAUSE_COMMAND,
            "--active",
            "checkpoint",
        ])
        .env_remove(TRIGGER_ENVIRONMENT);
    command
}

fn unarmed(command: &mut Command) -> &mut Command {
    command.env_remove(TRIGGER_ENVIRONMENT)
}

/// Reads actual pending owners and authenticated content while holding their fence.
fn pending_objects(fixture: &ComposedFlightFixture) -> Result<PendingObjects, Box<dyn Error>> {
    let graph = fixture.inspection_graph()?;
    let mut fence = graph.acquire_write_back_retention_fence()?;
    let mut bytes = BTreeMap::new();
    fence.visit_roots(&mut |root| {
        assert_eq!(root.node(), "write-back");
        let content = graph
            .read(root.id(), None)?
            .read_all(MAXIMUM_LOGICAL_OBJECT_BYTES)?;
        assert_eq!(content.len() as u64, root.logical_length());
        assert!(root.id().authenticates(&content));
        assert!(bytes.insert(root.id(), content).is_none());
        Ok(())
    })?;
    let journal = fs::read(fixture.write_back_journal.join("transfers-v1.log"))?;
    Ok(PendingObjects { bytes, journal })
}

fn interrupted_snapshot(
    interrupted: &PendingObjects,
    before: &PendingObjects,
    prior: CampaignSnapshotId,
) -> Result<CampaignSnapshotId, Box<dyn Error>> {
    let mut snapshots = Vec::new();
    for (id, bytes) in &interrupted.bytes {
        if before.bytes.contains_key(id) || id.kind() != ObjectKind::CampaignSnapshot {
            continue;
        }
        let envelope = ObjectEnvelope::from_canonical_bytes(bytes)?;
        assert_eq!(envelope.content_id(), *id);
        let snapshot = CampaignSnapshot::from_canonical_bytes(envelope.body())?;
        assert_eq!(snapshot.parent(), Some(prior));
        assert_eq!(snapshot.id()?.content_id(), *id);
        snapshots.push(snapshot.id()?);
    }
    assert_eq!(snapshots.len(), 1, "the fault must stage one new snapshot");
    snapshots
        .pop()
        .ok_or_else(|| "interrupted snapshot is absent".into())
}

fn staging(
    fixture: &ComposedFlightFixture,
) -> Result<CompressedDirectoryBlobBackend, Box<dyn Error>> {
    Ok(CompressedDirectoryBlobBackend::new(
        "write-staging",
        &fixture.write_staging_root,
        MAXIMUM_LOGICAL_OBJECT_BYTES,
    )?)
}

fn reclaim_orphan_without_pending_deletion(
    fixture: &ComposedFlightFixture,
    pending: &PendingObjects,
) -> Result<(), Box<dyn Error>> {
    let bytes = b"authenticated unjournaled process-loss debris";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    let leaf = staging(fixture)?;
    leaf.put_if_absent(orphan, &BlobHandle::from_bytes(bytes.to_vec()))?;
    assert!(!pending.bytes.contains_key(&orphan));
    assert_eq!(leaf.read(orphan, None)?.read_all(1024)?, bytes);

    let planned = run_json(
        unarmed(&mut fixture.base.gc_command("plan")),
        "plan GC after interrupted write-back publication",
    )?;
    assert!(json_u64(&planned, "unreachable_candidates")? > 0);
    {
        let journal = DirectoryCampaignGcJournal::open(&fixture.base.journal)?;
        let roots = journal.roots().iter().collect::<BTreeSet<_>>();
        for id in pending.bytes.keys() {
            assert!(roots.contains(id));
            assert!(
                journal
                    .candidates()
                    .iter()
                    .all(|candidate| candidate.id() != *id)
            );
        }
        assert!(journal.candidates().iter().any(|candidate| {
            candidate.backend() == "write-staging" && candidate.id() == orphan
        }));
    }
    let applied = run_json(
        unarmed(&mut fixture.base.gc_command("apply")),
        "reclaim real orphan without deleting pending publication roots",
    )?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["apply_status"], "applied");
    assert!(!leaf.contains(orphan)?);
    let preserved = pending_objects(fixture)?;
    assert_eq!(preserved.bytes, pending.bytes);
    assert_eq!(preserved.journal, pending.journal);
    Ok(())
}

fn complete_pending_and_reclaim_staging(
    fixture: &ComposedFlightFixture,
    retained: &BTreeMap<String, RetainedSnapshot>,
) -> Result<(), Box<dyn Error>> {
    let pending = pending_objects(fixture)?;
    assert!(!pending.bytes.is_empty());
    let mut maintained = fixture.start_service_with_maintenance()?;
    // Every wait consumes the same original maintenance budget, not 20s per root.
    let deadline = Instant::now() + Duration::from_secs(20);
    for id in pending.bytes.keys() {
        fixture.wait_until_write_back_root_absent(
            *id,
            deadline.saturating_duration_since(Instant::now()),
        )?;
    }
    assert!(pending_objects(fixture)?.bytes.is_empty());
    let destination = fixture.write_destination();
    for (id, bytes) in &pending.bytes {
        assert_eq!(
            destination
                .read(*id, None)?
                .read_all(MAXIMUM_LOGICAL_OBJECT_BYTES)?,
            *bytes
        );
    }
    assert_live_heads(fixture, retained)?;
    maintained.stop()?;

    let planned = run_json(
        unarmed(
            &mut fixture
                .base
                .gc_command_at("plan", &fixture.after_maintenance_gc_journal),
        ),
        "plan completed write-back staging eviction",
    )?;
    assert!(json_u64(&planned, "reachable_cache_candidates")? > 0);
    {
        let journal = DirectoryCampaignGcJournal::open(&fixture.after_maintenance_gc_journal)?;
        let mut eligible = BTreeSet::new();
        for candidate in journal.candidates().iter() {
            if candidate.backend() != "write-staging" {
                continue;
            }
            // Completed, unreferenced intermediate objects may be reclaimed.
            // Reachable staging eviction must name its durable required copy.
            let crucible_daemon::CampaignGcCandidateReason::ReachableCache { required_backend } =
                candidate.reason()
            else {
                continue;
            };
            assert_eq!(required_backend, "write-destination");
            assert!(destination.contains(candidate.id())?);
            eligible.insert(candidate.id());
        }
        for snapshot in retained.values() {
            assert!(eligible.contains(&snapshot.identity.content_id()));
        }
    }
    let applied = run_json(
        unarmed(
            &mut fixture
                .base
                .gc_command_at("apply", &fixture.after_maintenance_gc_journal),
        ),
        "evict completed staging with durable destination copies",
    )?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["apply_status"], "applied");
    assert_authoritative_heads(fixture, retained)?;

    let mut reopen_command = fixture.base.service_command(None);
    reopen_command.env_remove(TRIGGER_ENVIRONMENT);
    let mut reopened = fixture
        .base
        .start_service_command(reopen_command, Duration::from_secs(15))?;
    assert_live_heads(fixture, retained)?;
    reopened.stop()?;
    Ok(())
}
