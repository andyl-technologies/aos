//! Real exact-restored guest progress after packed repack, corruption and GC.

use super::super::super::archive_transfer::{packed_archive_fixture, packed_repack_command};
use super::*;
use crucible_cas::content_store::{PackedBlobBackend, StoreError};
use crucible_qemu::QemuLaunchArtifactIdentity;

const PACKED_NODE: &str = "packed";
const TARGET_PACK_BYTES: u64 = 65_536;
const INCOMPATIBLE_STORE: &str = "store object or operation is incompatible";

#[test]
#[ignore = "requires packaged QEMU, cgroup-v2 and project quota inside the VM check"]
fn public_exact_paused_guest_survives_packed_repack_corruption_and_gc() -> Result<(), Box<dyn Error>>
{
    let fixture = packed_archive_fixture()?;
    let backend = Arc::new(open_packed_backend(&fixture)?);
    let checkpoints = ExactCheckpointStore::new(backend.clone(), 1024 * 1024 * 1024)?;
    let (compiled, _) = compile_guest_choice_campaign(&fixture)?;
    let packaged = QemuLaunchArtifactIdentity::authenticate(
        required_path("CRUCIBLE_FLIGHT_QEMU")?,
        required_path("CRUCIBLE_FLIGHT_PLUGIN")?,
    )?;
    create_guest_choice_campaign(&fixture, &compiled, packaged.qemu_build_id())?;
    let authority = write_component_authority(&fixture)?;
    let immutable_inputs = guest_choice_immutable_inputs(&authority)?;
    let mut service = start_packaged_service(&fixture, &authority)?;
    grant_and_start_guest_choice_campaign(&fixture)?;
    let genesis = json_string(&compiled, "genesis_artifact")?;
    let (active, terminal_request) = maintenance_setup::select_running_maintenance_attempt(
        &fixture,
        &mut service,
        &genesis,
        0xa1,
        0xa2,
    )?;
    attest_fingerprint_enabled_qemu_descendants(&service, "packed-maintenance-source")?;
    let mut command_sequence = 0xa3_u64;
    let checkpoint = capture_checkpoint_after_progress_with_store(
        &fixture,
        &service,
        active,
        &mut command_sequence,
        None,
        &checkpoints,
    )?;
    let authenticated_basis = authenticate_checkpoint(&checkpoints, checkpoint)?;
    let paused = campaign_status(&fixture)?;
    assert_eq!(paused["state"], "paused");
    let paused_snapshot = json_string(&paused, "snapshot")?;
    let mut retained_refs = Vec::new();
    for name in DERIVED_CAMPAIGNS {
        run_json(
            connected_campaign(&fixture).args([
                "derive",
                CAMPAIGN,
                "--snapshot",
                &paused_snapshot,
                name,
            ]),
            "derive exact-paused packed maintenance campaign",
        )?;
        retained_refs.push((
            name,
            json_string(&campaign_status_named(&fixture, name)?, "snapshot")?,
        ));
    }
    storage_recovery::require_live_owner_gc_refusal(&fixture)?;
    service.stop()?;
    require_no_guest("packed-maintenance-paused")?;

    repack(&fixture, "packed-maintenance-repack")?;
    assert_eq!(
        authenticate_checkpoint(&checkpoints, checkpoint)?,
        authenticated_basis
    );
    let index = fixture.objects.join(".packed-admin/index-v1");
    let original_index = corrupt_index(&index)?;
    require_corrupt_store_verify_refusal(&fixture)?;
    let refused = match start_packaged_service(&fixture, &authority) {
        Ok(mut unexpected) => {
            unexpected.stop()?;
            return Err("corrupt packed index unexpectedly admitted a packaged executor".into());
        }
        Err(error) => error,
    };
    assert!(
        refused.to_string().contains(INCOMPATIBLE_STORE),
        "corrupt index lacked its original storage incompatibility: {refused}"
    );
    require_no_guest("packed-maintenance-corruption-refused")?;
    fs::write(&index, &original_index)?;
    assert_eq!(fs::read(&index)?, original_index);
    fixture.verify_store()?;
    assert_eq!(
        authenticate_checkpoint(&checkpoints, checkpoint)?,
        authenticated_basis
    );
    attest_guest_choice_immutable_inputs(
        "packed-maintenance-restored",
        &immutable_inputs,
        &authority,
    )?;

    let orphan_bytes = b"packed maintenance authenticated crash debris";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    backend.put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.to_vec()))?;
    reclaim_orphan(&fixture, &backend, orphan)?;
    assert_eq!(
        authenticate_checkpoint(&checkpoints, checkpoint)?,
        authenticated_basis
    );
    assert!(
        checkpoints
            .load_attempt_checkpoint(checkpoint)?
            .promotion_source()
            .is_some()
    );

    let mut restored = start_packaged_service(&fixture, &authority)?;
    assert_eq!(campaign_status(&fixture)?["snapshot"], paused_snapshot);
    assert_eq!(campaign_status(&fixture)?["state"], "paused");
    require_retained_refs(&fixture, &retained_refs)?;
    assert_eq!(
        wait_for_promoted_checkpoint_with_store(&fixture, active, &checkpoints)?,
        checkpoint
    );
    resume_campaign(&fixture, &next_command_identity(&mut command_sequence)?)?;
    let (origin, execution) = wait_for_resumed_attempt(&fixture, active, checkpoint)?;
    assert_eq!(origin, checkpoint);
    attest_fingerprint_enabled_qemu_descendants(&restored, "packed-maintenance-exact-resume")?;
    wait_for_resumed_guest_progress(&restored, active, execution)?;
    let advanced = capture_checkpoint_after_progress_with_store(
        &fixture,
        &restored,
        active,
        &mut command_sequence,
        Some(checkpoint),
        &checkpoints,
    )?;
    assert_ne!(advanced, checkpoint);
    let resumed = wait_for_attempt_explanation(&fixture, active)?;
    assert_eq!(resumed["selection"]["value"], "u64:7");
    assert_eq!(resumed["proposal"]["request"], terminal_request);
    require_retained_refs(&fixture, &retained_refs)?;
    restored.stop()?;
    require_no_guest("packed-maintenance-finished")?;

    println!("packed_maintenance_original_checkpoint={checkpoint}");
    println!("packed_maintenance_advanced_checkpoint={advanced}");
    println!("packed_maintenance_real_exact_pause=true");
    println!("packed_maintenance_public_repack_authenticated=true");
    println!("packed_maintenance_corrupt_index_refused_before_guest=true");
    println!("packed_maintenance_original_index_restored=true");
    println!("packed_maintenance_nonempty_gc_preserves_checkpoint=true");
    println!("packed_maintenance_exact_origin_preserved=true");
    println!("packed_maintenance_scheduler_observed_guest_progress=true");
    println!("packed_maintenance_distinct_authenticated_checkpoint=true");
    println!("packed_maintenance_selected_outcome_preserved=true");
    println!("packed_maintenance_derived_refs_preserved=2");
    println!("packed_maintenance_final_guest_cleanup=true");
    Ok(())
}

// The public loader authenticates the bounded complete restore inventory. Load
// both the promoted root and its retained raw source after each maintenance step.
fn authenticate_checkpoint(
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
) -> Result<(u64, ExactCheckpointId, u64), Box<dyn Error>> {
    let loaded = checkpoints.load_attempt_checkpoint(checkpoint)?;
    assert_eq!(loaded.root(), checkpoint);
    let source = loaded
        .promotion_source()
        .ok_or("checkpoint lacks actual promotion evidence")?;
    let raw = checkpoints.load_attempt_checkpoint(source)?;
    assert_eq!(raw.root(), source);
    let promoted_bytes = loaded.authenticated_restore_bytes()?;
    let raw_bytes = raw.authenticated_restore_bytes()?;
    assert!(promoted_bytes > 0 && raw_bytes > 0);
    Ok((promoted_bytes, source, raw_bytes))
}

fn open_packed_backend(fixture: &FlightFixture) -> Result<PackedBlobBackend, StoreError> {
    PackedBlobBackend::open(PACKED_NODE, &fixture.objects, TARGET_PACK_BYTES)
}

fn repack(fixture: &FlightFixture, name: &str) -> Result<(), Box<dyn Error>> {
    let journal = fixture._temporary.path().join(name);
    let planned = run_json(
        &mut packed_repack_command(fixture, &journal, "plan"),
        "plan packed checkpoint repack",
    )?;
    assert_eq!(planned["schema"], "crucible.cli.packed-repack.v1");
    assert_eq!(planned["phase"], "planned");
    for field in ["logical_objects", "logical_bytes", "packs"] {
        assert!(
            json_u64(&planned["before"], field)? > 0,
            "empty repack {field}"
        );
    }
    let applied = run_json(
        &mut packed_repack_command(fixture, &journal, "apply"),
        "apply packed checkpoint repack",
    )?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["phase"], "applied");
    for field in ["logical_objects", "logical_bytes"] {
        assert_eq!(
            json_u64(&applied["after"], field)?,
            json_u64(&planned["before"], field)?,
            "repack changed {field}"
        );
    }
    fixture.verify_store()?;
    Ok(())
}

fn corrupt_index(index: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let original = fs::read(index)?;
    let mut corrupt = original.clone();
    let first = corrupt
        .first_mut()
        .ok_or("packed index unexpectedly empty")?;
    *first ^= 0xff;
    fs::write(index, corrupt)?;
    Ok(original)
}

fn require_corrupt_store_verify_refusal(fixture: &FlightFixture) -> Result<(), Box<dyn Error>> {
    let rejected = fixture
        .verify_store()
        .err()
        .ok_or("public store verify accepted the corrupted packed index")?;
    assert!(
        rejected.to_string().contains(INCOMPATIBLE_STORE),
        "corrupt public verification lacked its original incompatibility: {rejected}"
    );
    Ok(())
}

fn reclaim_orphan(
    fixture: &FlightFixture,
    backend: &PackedBlobBackend,
    orphan: ContentId,
) -> Result<(), Box<dyn Error>> {
    let planned = run_json(&mut fixture.gc_command("plan"), "plan packed checkpoint GC")?;
    assert_eq!(planned["phase"], "planned");
    let journal = DirectoryCampaignGcJournal::open(&fixture.journal)?;
    assert!(
        journal
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == orphan)
    );
    drop(journal);
    let applied = run_json(
        &mut fixture.gc_command("apply"),
        "apply packed checkpoint GC",
    )?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["apply_status"], "applied");
    assert!(!backend.contains(orphan)?);
    Ok(())
}

fn require_retained_refs(
    fixture: &FlightFixture,
    refs: &[(&str, String)],
) -> Result<(), Box<dyn Error>> {
    for (name, snapshot) in refs {
        assert_eq!(
            campaign_status_named(fixture, name)?["snapshot"],
            snapshot.as_str()
        );
    }
    Ok(())
}

fn require_no_guest(stage: &str) -> Result<(), Box<dyn Error>> {
    maintenance_transfer::assert_no_nested_qemu_processes(stage)?;
    require_empty_guest_choice_run_root(stage)
}

#[test]
fn public_packed_repack_rejects_changed_generation_without_rewriting_the_plan()
-> Result<(), Box<dyn Error>> {
    let fixture = packed_archive_fixture()?;
    let backend = open_packed_backend(&fixture)?;
    let bytes = b"original authenticated packed control";
    let original = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    backend.put_if_absent(original, &BlobHandle::from_bytes(bytes.to_vec()))?;
    let journal = fixture._temporary.path().join("stale-repack");
    let planned = run_json(
        &mut packed_repack_command(&fixture, &journal, "plan"),
        "plan before genuine mutation",
    )?;
    assert_eq!(planned["phase"], "planned");
    let original_journal = fs::read(journal.join("record-v1.json"))?;
    let index_before = fs::read(fixture.objects.join(".packed-admin/index-v1"))?;
    let later_bytes = b"later authenticated logical mutation";
    let later = ContentId::for_bytes(ObjectKind::Trace, 1, later_bytes);
    backend.put_if_absent(later, &BlobHandle::from_bytes(later_bytes.to_vec()))?;
    let index_after_mutation = fs::read(fixture.objects.join(".packed-admin/index-v1"))?;
    assert_ne!(index_before, index_after_mutation);

    let refused = output_with_timeout(
        packed_repack_command(&fixture, &journal, "apply"),
        Duration::from_secs(20),
    )?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains(INCOMPATIBLE_STORE));
    assert_eq!(
        fs::read(fixture.objects.join(".packed-admin/index-v1"))?,
        index_after_mutation
    );
    assert_eq!(fs::read(journal.join("record-v1.json"))?, original_journal);
    assert!(backend.contains(original)? && backend.contains(later)?);
    repack(&fixture, "current-repack")?;
    assert!(backend.contains(original)? && backend.contains(later)?);
    Ok(())
}

#[test]
fn public_packed_startup_refuses_corrupt_index_and_restores_exact_bytes()
-> Result<(), Box<dyn Error>> {
    let fixture = packed_archive_fixture()?;
    let backend = open_packed_backend(&fixture)?;
    let bytes = b"packed corruption control";
    let content = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    backend.put_if_absent(content, &BlobHandle::from_bytes(bytes.to_vec()))?;
    let index = fixture.objects.join(".packed-admin/index-v1");
    let original_index = fs::read(&index)?;
    assert!(matches!(
        PackedBlobBackend::open("wrong-owner", &fixture.objects, TARGET_PACK_BYTES),
        Err(StoreError::Incompatible)
    ));
    assert_eq!(fs::read(&index)?, original_index);
    repack(&fixture, "corruption-control-repack")?;
    let original = corrupt_index(&index)?;
    require_corrupt_store_verify_refusal(&fixture)?;
    assert!(matches!(
        open_packed_backend(&fixture),
        Err(StoreError::Incompatible)
    ));
    let rejected = match fixture.start_service(None) {
        Ok(mut unexpected) => {
            unexpected.stop()?;
            return Err("corrupt packed index admitted the public owner".into());
        }
        Err(error) => error,
    };
    assert!(rejected.to_string().contains(INCOMPATIBLE_STORE));
    fs::write(&index, &original)?;
    assert_eq!(fs::read(&index)?, original);
    fixture.verify_store()?;
    assert!(open_packed_backend(&fixture)?.contains(content)?);
    let mut restored = fixture.start_service(None)?;
    restored.stop()?;
    Ok(())
}

#[test]
fn public_packed_gc_refuses_live_owner_then_reclaims_authenticated_orphan()
-> Result<(), Box<dyn Error>> {
    let fixture = packed_archive_fixture()?;
    let backend = open_packed_backend(&fixture)?;
    let bytes = b"unreferenced packed GC control";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    backend.put_if_absent(orphan, &BlobHandle::from_bytes(bytes.to_vec()))?;
    let mut service = fixture.start_service(None)?;
    storage_recovery::require_live_owner_gc_refusal(&fixture)?;
    assert!(backend.contains(orphan)?);
    service.stop()?;
    reclaim_orphan(&fixture, &backend, orphan)?;
    Ok(())
}
