//! Real exact-restored guest progress after authenticated tier cache eviction.

use super::*;
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{DirectoryRefBackend, MutableRefBackend, RefCasOutcome, RefName};
use crucible_daemon::{CampaignGcCandidateReason, CampaignGcJournalPhase};
use crucible_qemu::QemuLaunchArtifactIdentity;

const CACHE_NODE: &str = "tier-cache";
const SOURCE_NODE: &str = "tier-source";

/// Owns physically independent cache and authoritative directory placements.
struct TierFixture {
    flight: FlightFixture,
    cache: DirectoryBlobBackend,
    source: Arc<DirectoryBlobBackend>,
}

impl TierFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let flight = FlightFixture::new()?;
        let root = flight._temporary.path();
        let cache_root = secure_directory(root, "tier-cache")?;
        let refs = root.join("refs");
        let source_root = &flight.objects;
        fs::write(
            &flight.store,
            format!(
                r#"schema = "crucible.campaign-repository-store"
version = 2
root = "verified"
admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
ref_directory = {refs:?}

[[nodes]]
id = "verified"
[nodes.spec]
kind = "verified"
child = "tiers"

[[nodes]]
id = "tiers"
[nodes.spec]
kind = "tiered"
tiers = [
  {{ child = "tier-cache", readable = true, writable = false, promote_reads = true }},
  {{ child = "tier-source", readable = true, writable = true, promote_reads = false }}
]

[[nodes]]
id = "tier-cache"
[nodes.spec]
kind = "directory"
root = {cache_root:?}

[[nodes]]
id = "tier-source"
[nodes.spec]
kind = "directory"
root = {source_root:?}
"#,
            ),
        )?;
        fs::set_permissions(&flight.store, fs::Permissions::from_mode(0o600))?;
        let cache = DirectoryBlobBackend::new(CACHE_NODE, cache_root);
        let source = Arc::new(DirectoryBlobBackend::new(SOURCE_NODE, source_root));
        Ok(Self {
            flight,
            cache,
            source,
        })
    }

    fn ensure(&self, id: ContentId) -> Result<(), Box<dyn Error>> {
        let ensured = run_json(
            command(&["--format", "jsonl", "store", "ensure", &id.encode(), "--in"])
                .arg(&self.flight.store),
            "authenticate and promote retained tier object",
        )?;
        assert_eq!(ensured["authenticated"], true);
        assert_eq!(ensured["content"], id.encode());
        Ok(())
    }

    fn plan(&self, journal: &Path, id: ContentId) -> Result<Value, Box<dyn Error>> {
        let planned = run_json(
            &mut self.flight.gc_command_at("plan", journal),
            "plan reachable tier cache eviction",
        )?;
        assert_eq!(planned["phase"], "planned");
        assert!(json_u64(&planned, "reachable_cache_candidates")? > 0);
        let owned = DirectoryCampaignGcJournal::open(journal)?;
        assert!(owned.candidates().iter().any(|candidate| {
            candidate.id() == id
                && candidate.backend() == CACHE_NODE
                && matches!(candidate.reason(), CampaignGcCandidateReason::ReachableCache {
                    required_backend
                } if required_backend == SOURCE_NODE)
        }));
        Ok(planned)
    }

    fn evict(&self, journal: &Path, id: ContentId) -> Result<(), Box<dyn Error>> {
        let planned = self.plan(journal, id)?;
        let applied = run_json(
            &mut self.flight.gc_command_at("apply", journal),
            "apply authenticated tier cache eviction",
        )?;
        assert_eq!(applied["plan"], planned["plan"]);
        assert_eq!(applied["apply_status"], "applied");
        assert!(json_u64(&applied, "reachable_cache_candidates")? > 0);
        assert!(!self.cache.contains(id)?);
        assert!(self.source.contains(id)?);
        Ok(())
    }

    fn refuse_stale_apply(&self, journal: &Path, id: ContentId) -> Result<(), Box<dyn Error>> {
        self.plan(journal, id)?;
        let before = ["plan-v2", "roots-v1", "candidates-v2", "state-v1"]
            .map(|name| fs::read(journal.join(name)))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        // This stopped-owner physical mutation changes the required inventory,
        // not the guest's canonical root or its retained checkpoint identity.
        let later_bytes = b"tier maintenance later required-source inventory";
        let later = ContentId::for_bytes(ObjectKind::Trace, 1, later_bytes);
        self.source
            .put_if_absent(later, &BlobHandle::from_bytes(later_bytes.to_vec()))?;
        let rejected = output_with_timeout(
            self.flight.gc_command_at("apply", journal),
            Duration::from_secs(20),
        )?;
        assert!(!rejected.status.success());
        assert!(
            String::from_utf8_lossy(&rejected.stderr)
                .contains("campaign GC physical inventory changed for backend tier-source"),
            "stale tier apply lacked the original physical-basis refusal: {}",
            String::from_utf8_lossy(&rejected.stderr)
        );
        for (name, original) in ["plan-v2", "roots-v1", "candidates-v2", "state-v1"]
            .into_iter()
            .zip(before)
        {
            assert_eq!(fs::read(journal.join(name))?, original);
        }
        assert_eq!(
            DirectoryCampaignGcJournal::open(journal)?.phase(),
            CampaignGcJournalPhase::Planned
        );
        assert!(self.cache.contains(id)? && self.source.contains(id)?);
        Ok(())
    }
}

#[test]
#[ignore = "requires packaged QEMU, cgroup-v2 and project quota inside the VM check"]
fn public_exact_paused_guest_survives_tier_cache_eviction_and_promotion()
-> Result<(), Box<dyn Error>> {
    let tier = TierFixture::new()?;
    let fixture = &tier.flight;
    // Inspect only the required leaf: authentication must not itself refill
    // the cache whose absent-to-present transition this flight measures.
    let checkpoints = ExactCheckpointStore::new(tier.source.clone(), 1024 * 1024 * 1024)?;
    let (compiled, _) = compile_guest_choice_campaign(fixture)?;
    let packaged = QemuLaunchArtifactIdentity::authenticate(
        required_path("CRUCIBLE_FLIGHT_QEMU")?,
        required_path("CRUCIBLE_FLIGHT_PLUGIN")?,
    )?;
    create_guest_choice_campaign(fixture, &compiled, packaged.qemu_build_id())?;
    let authority = write_component_authority(fixture)?;
    let immutable_inputs = guest_choice_immutable_inputs(&authority)?;
    let mut service = start_packaged_service(fixture, &authority)?;
    grant_and_start_guest_choice_campaign(fixture)?;
    let genesis = json_string(&compiled, "genesis_artifact")?;
    let (active, terminal_request) = maintenance_setup::select_running_maintenance_attempt(
        fixture,
        &mut service,
        &genesis,
        0xb1,
        0xb2,
    )?;
    attest_fingerprint_enabled_qemu_descendants(&service, "tier-maintenance-source")?;
    let mut sequence = 0xb3_u64;
    let checkpoint = capture_checkpoint_after_progress_with_store(
        fixture,
        &service,
        active,
        &mut sequence,
        None,
        &checkpoints,
    )?;
    let restore_basis = authenticate_restore_basis(&checkpoints, checkpoint)?;
    let paused = campaign_status(fixture)?;
    assert_eq!(paused["state"], "paused");
    let paused_snapshot = json_string(&paused, "snapshot")?;
    let mut retained = Vec::new();
    for name in DERIVED_CAMPAIGNS {
        run_json(
            connected_campaign(fixture).args([
                "derive",
                CAMPAIGN,
                "--snapshot",
                &paused_snapshot,
                name,
            ]),
            "derive exact-paused tier maintenance campaign",
        )?;
        retained.push((
            name,
            json_string(&campaign_status_named(fixture, name)?, "snapshot")?,
        ));
    }
    service.stop()?;
    require_no_guest("tier-maintenance-paused")?;

    let original_refs = read_authoritative_refs(fixture)?;
    let content = checkpoint.content_id();
    tier.ensure(content)?;
    assert!(tier.cache.contains(content)? && tier.source.contains(content)?);
    tier.refuse_stale_apply(&fixture._temporary.path().join("stale-tier-gc"), content)?;
    tier.evict(&fixture.journal, content)?;
    assert_eq!(
        authenticate_restore_basis(&checkpoints, checkpoint)?,
        restore_basis
    );
    // Required-leaf authentication and direct refs cannot refill the cache.
    // Keep every tiered repository/status read after explicit repromotion.
    assert_eq!(read_authoritative_refs(fixture)?, original_refs);
    assert!(!tier.cache.contains(content)?);
    tier.ensure(content)?;
    assert!(tier.cache.contains(content)? && tier.source.contains(content)?);
    assert_eq!(read_authoritative_refs(fixture)?, original_refs);
    assert_eq!(campaign_status(fixture)?["snapshot"], paused_snapshot);
    require_retained_refs(fixture, &retained)?;
    let cached_bytes = authenticate_object(&tier.cache, content)?;
    let required_bytes = authenticate_object(tier.source.as_ref(), content)?;
    assert!(cached_bytes > 0);
    assert_eq!(cached_bytes, required_bytes);
    assert_eq!(
        authenticate_restore_basis(&checkpoints, checkpoint)?,
        restore_basis
    );
    attest_guest_choice_immutable_inputs(
        "tier-maintenance-restored",
        &immutable_inputs,
        &authority,
    )?;

    let mut restored = start_packaged_service(fixture, &authority)?;
    assert_eq!(campaign_status(fixture)?["snapshot"], paused_snapshot);
    assert_eq!(campaign_status(fixture)?["state"], "paused");
    assert_eq!(
        wait_for_promoted_checkpoint_with_store(fixture, active, &checkpoints)?,
        checkpoint
    );
    resume_campaign(fixture, &next_command_identity(&mut sequence)?)?;
    let (origin, execution) = wait_for_resumed_attempt(fixture, active, checkpoint)?;
    assert_eq!(origin, checkpoint);
    attest_fingerprint_enabled_qemu_descendants(&restored, "tier-maintenance-exact-resume")?;
    wait_for_resumed_guest_progress(&restored, active, execution)?;
    let advanced = capture_checkpoint_after_progress_with_store(
        fixture,
        &restored,
        active,
        &mut sequence,
        Some(checkpoint),
        &checkpoints,
    )?;
    assert_ne!(advanced, checkpoint);
    let resumed = wait_for_attempt_explanation(fixture, active)?;
    assert_eq!(resumed["selection"]["value"], "u64:7");
    assert_eq!(resumed["proposal"]["request"], terminal_request);
    require_retained_refs(fixture, &retained)?;
    restored.stop()?;
    require_no_guest("tier-maintenance-finished")?;

    println!("tier_maintenance_original_checkpoint={checkpoint}");
    println!("tier_maintenance_advanced_checkpoint={advanced}");
    for claim in [
        "tier_maintenance_real_exact_pause=true",
        "tier_maintenance_stale_gc_refused_before_deletion=true",
        "tier_maintenance_reachable_cache_evicted=true",
        "tier_maintenance_required_restore_preserved=true",
        "tier_maintenance_authenticated_cache_repromoted=true",
        "tier_maintenance_exact_origin_preserved=true",
        "tier_maintenance_scheduler_observed_guest_progress=true",
        "tier_maintenance_distinct_authenticated_checkpoint=true",
        "tier_maintenance_selected_outcome_preserved=true",
        "tier_maintenance_derived_refs_preserved=2",
        "tier_maintenance_final_guest_cleanup=true",
    ] {
        println!("{claim}");
    }
    Ok(())
}

fn authenticate_restore_basis(
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
) -> Result<(ExactCheckpointId, u64, u64), Box<dyn Error>> {
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
    Ok((source, promoted_bytes, raw_bytes))
}

fn authenticate_object(
    backend: &DirectoryBlobBackend,
    id: ContentId,
) -> Result<u64, Box<dyn Error>> {
    Ok(backend.read(id, None)?.copy_to(&mut std::io::sink())?)
}

// This reads the original canonical ref records without loading their blobs
// through the tier graph; it cannot promote an evicted checkpoint placement.
fn read_authoritative_refs(
    fixture: &FlightFixture,
) -> Result<Vec<(RefName, ContentId)>, Box<dyn Error>> {
    let refs = DirectoryRefBackend::new(fixture._temporary.path().join("refs"));
    let mut retained = Vec::new();
    for campaign in std::iter::once(CAMPAIGN).chain(DERIVED_CAMPAIGNS) {
        let name = RefName::new(format!("campaigns/{campaign}"))?;
        let content = refs
            .read_ref(&name)?
            .ok_or("tier maintenance lost an authoritative campaign ref")?;
        retained.push((name, content));
    }
    Ok(retained)
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

// These controls exercise physical maintenance through public processes, not
// guest execution. The genuine ignored flight above owns the guest oracle.
fn retain_control(tier: &TierFixture, required: bool) -> Result<ContentId, Box<dyn Error>> {
    let retained = ContentEnvelope::new(
        "crucible.test.tier-maintenance-retained",
        1,
        BTreeSet::new(),
        b"authenticated tier maintenance retained control".to_vec(),
    )?;
    let bytes = retained.canonical_bytes();
    let id = retained.content_id(ObjectKind::Trace);
    tier.cache
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))?;
    if required {
        tier.source
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))?;
    }
    let refs = DirectoryRefBackend::new(tier.flight._temporary.path().join("refs"));
    assert!(matches!(
        refs.compare_exchange(&RefName::new("retained/tier-control")?, None, id)?,
        RefCasOutcome::Advanced { next } if next == id
    ));
    Ok(id)
}

#[test]
fn public_tier_gc_rejects_changed_required_basis_before_deletion() -> Result<(), Box<dyn Error>> {
    let tier = TierFixture::new()?;
    let id = retain_control(&tier, true)?;
    let before = authenticate_object(&tier.cache, id)?;
    tier.refuse_stale_apply(&tier.flight.journal, id)?;
    assert_eq!(authenticate_object(&tier.cache, id)?, before);
    assert_eq!(authenticate_object(tier.source.as_ref(), id)?, before);
    Ok(())
}

#[test]
fn public_tier_gc_preserves_cache_without_an_authenticated_required_copy()
-> Result<(), Box<dyn Error>> {
    let tier = TierFixture::new()?;
    let id = retain_control(&tier, false)?;
    assert!(!tier.source.contains(id)?);
    let planned = run_json(
        &mut tier.flight.gc_command("plan"),
        "plan missing required copy",
    )?;
    assert_eq!(json_u64(&planned, "reachable_cache_candidates")?, 0);
    assert!(
        !DirectoryCampaignGcJournal::open(&tier.flight.journal)?
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == id)
    );
    let applied = run_json(
        &mut tier.flight.gc_command("apply"),
        "apply retained cache plan",
    )?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert!(tier.cache.contains(id)?);
    assert!(!tier.source.contains(id)?);
    assert!(authenticate_object(&tier.cache, id)? > 0);
    Ok(())
}

#[test]
fn public_tier_gc_evicts_only_cache_then_authentically_repromotes() -> Result<(), Box<dyn Error>> {
    let tier = TierFixture::new()?;
    let id = retain_control(&tier, true)?;
    let original = authenticate_object(tier.source.as_ref(), id)?;
    tier.evict(&tier.flight.journal, id)?;
    assert_eq!(authenticate_object(tier.source.as_ref(), id)?, original);
    tier.ensure(id)?;
    assert!(tier.cache.contains(id)?);
    assert_eq!(authenticate_object(&tier.cache, id)?, original);
    assert_eq!(authenticate_object(tier.source.as_ref(), id)?, original);
    Ok(())
}
