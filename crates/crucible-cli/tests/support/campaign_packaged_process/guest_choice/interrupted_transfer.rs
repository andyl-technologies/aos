//! Real executable archive interruption, retained roots, GC and exact recipient.
//!
//! The final manifest is deliberately corrupted after authentic publication in
//! the destination leaf. Original transfer ordering copies the selected guest
//! closure first, then refuses that manifest before publishing either ref.

use super::*;
use crucible_campaign::{
    CampaignArchivePlan, CampaignArchivePolicy, CampaignSnapshotId, ObjectEnvelope,
};
use crucible_cas::content_store::{
    DirectoryRefBackend, MutableRefBackend, RefName, StoreError, StoreGraphConfig,
};
use crucible_daemon::{
    CampaignLocalRepositoryStore, CampaignLocalServiceConfig, CampaignLocalServiceMode,
    CampaignLoopbackEndpointConfig, CampaignLoopbackServerConfig, CampaignTransferRetentionAdmin,
    DirectoryCampaignTransferJournal, DirectoryExactPinMaterializationStore,
    EXACT_PIN_MATERIALIZATION_DIRECTORY,
};

#[cfg(test)]
#[path = "interrupted_transfer/controls.rs"]
mod controls;

#[test]
#[ignore = "requires packaged QEMU, cgroup-v2 and project quota inside the VM check"]
fn public_exact_recipient_survives_interrupted_archive_and_journal_root_gc()
-> Result<(), Box<dyn Error>> {
    maintenance_transfer::run_transfer_flight(
        maintenance_transfer::ArchiveTransferMode::Interrupted,
    )?;

    // The shared runner has completed the genuine recipient and original
    // incompatible-runtime refusal before these guest claims become visible.
    println!("interrupted_transfer_exact_origin_preserved=true");
    println!("interrupted_transfer_execution_bound_guest_progress=true");
    println!("interrupted_transfer_distinct_authenticated_checkpoint=true");
    println!("interrupted_transfer_selected_outcome_preserved=true");
    println!("interrupted_transfer_owned_guest_cleanup=true");
    Ok(())
}

/// Derives two authoritative refs while the original source owner is serving.
///
/// # Errors
///
/// Returns the original public derivation or authenticated status failure.
pub(super) fn derive_source_refs(
    source: &FlightFixture,
    snapshot: &str,
) -> Result<(), Box<dyn Error>> {
    for name in DERIVED_CAMPAIGNS {
        run_json(
            connected_campaign(source).args(["derive", CAMPAIGN, "--snapshot", snapshot, name]),
            "retain source ref before interrupted transfer",
        )?;
        json_string(&campaign_status_named(source, name)?, "snapshot")?;
    }
    Ok(())
}

/// Runs the journal/GC window around an actual guest-derived executable plan.
///
/// # Errors
///
/// Returns the original authentication, copy, journal, GC or ref failure.
pub(super) fn transfer_after_interruption(
    source: &FlightFixture,
    destination: &FlightFixture,
    snapshot: &str,
) -> Result<(Value, Value), Box<dyn Error>> {
    let plan = source_plan(source, snapshot)?;
    assert!(!plan.manifest().checkpoint_selections().is_empty());
    assert!(plan.selected().iter().any(|entry| {
        matches!(
            entry.id().kind(),
            ObjectKind::RamExtent | ObjectKind::DeviceState
        )
    }));
    let window = InterruptedCopy::refuse(source, destination, snapshot, &plan)?;
    let (preflight, complete) = window.repair_gc_and_retry(source, destination, snapshot)?;

    for claim in [
        "interrupted_transfer_original_corruption_refused=true",
        "interrupted_transfer_both_original_journals_retained=true",
        "interrupted_transfer_partial_exact_copy_authenticated=true",
        "interrupted_transfer_refs_absent_before_completion=true",
        "interrupted_transfer_public_gc_preserved_pending_roots=true",
        "interrupted_transfer_public_gc_reclaimed_orphans=2",
        "interrupted_transfer_exact_byte_repair=true",
        "interrupted_transfer_identical_retry_authenticated=true",
        "interrupted_transfer_completed_retry_idempotent=true",
        "interrupted_transfer_derived_refs_preserved=2",
    ] {
        println!("{claim}");
    }
    Ok((preflight, complete))
}

/// Acquires the real stopped source owner and its original exact-pin resolver.
fn source_plan(
    source: &FlightFixture,
    snapshot: &str,
) -> Result<CampaignArchivePlan, Box<dyn Error>> {
    let primary = StoreNodeId::new("primary")?;
    let (graph, administration) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: primary.clone(),
        admitted_kinds: BTreeSet::from(all_campaign_object_kinds()),
        nodes: BTreeMap::from([(
            primary,
            StoreNodeSpec::Directory {
                root: source.objects.clone(),
            },
        )]),
    })?;
    let graph = Arc::new(graph);
    let checkpoints = ExactCheckpointStore::new(graph.clone(), 1024 * 1024 * 1024)?;
    let store = CampaignLocalRepositoryStore::new_with_maintenance(
        graph,
        Arc::new(authoritative_refs(source)),
        administration,
    )?;
    let metadata = fs::metadata(&source.state)?;
    let endpoint = CampaignLoopbackEndpointConfig::new(
        source.socket.to_string_lossy().as_ref(),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )?;
    let owner = CampaignLocalServiceConfig::new(
        endpoint,
        &source.state,
        &source.peer_policy,
        CampaignLocalServiceMode::ReadWrite,
        CampaignLoopbackServerConfig::default(),
    )?
    .prepare_with_store(store)?;
    let mut pins = DirectoryExactPinMaterializationStore::open(
        source.state.join(EXACT_PIN_MATERIALIZATION_DIRECTORY),
    )?;
    Ok(owner.plan_campaign_archive_with_exact_pins(
        CampaignName::new(CAMPAIGN)?,
        CampaignSnapshotId::parse(snapshot)?,
        CampaignArchivePolicy::Executable,
        [],
        &checkpoints,
        &mut pins,
    )?)
}

/// Retains only real records and authenticated copied object identities.
struct InterruptedCopy {
    manifest: ContentId,
    manifest_path: PathBuf,
    original_bytes: Vec<u8>,
    objects: BTreeMap<ContentId, u64>,
    source_journal: JournalInventory,
    destination_journal: JournalInventory,
    source_refs: BTreeMap<RefName, ContentId>,
}

impl InterruptedCopy {
    fn refuse(
        source: &FlightFixture,
        destination: &FlightFixture,
        snapshot: &str,
        plan: &CampaignArchivePlan,
    ) -> Result<Self, Box<dyn Error>> {
        require_destination_refs_absent(destination)?;
        let source_refs = retained_source_refs(source)?;
        let manifest = plan.manifest_id().content_id();
        let original_bytes =
            ObjectEnvelope::for_archive_manifest(plan.manifest())?.canonical_bytes();
        let backend = directory_backend(destination);
        for (id, _) in plan.transfer_objects() {
            assert!(
                !backend.contains(id)?,
                "destination already contained selected transfer bytes"
            );
        }
        backend.put_if_absent(manifest, &BlobHandle::from_bytes(original_bytes.clone()))?;
        authenticate_ids(
            &backend,
            &BTreeMap::from([(manifest, original_bytes.len() as u64)]),
        )?;
        let manifest_path = object_path(destination, manifest);
        assert_eq!(fs::read(&manifest_path)?, original_bytes);

        let mut damaged = original_bytes.clone();
        let last = damaged
            .last_mut()
            .ok_or("empty authentic archive manifest")?;
        *last ^= 1;
        fs::write(&manifest_path, damaged)?;
        require_transfer_corruption(source, destination, snapshot, manifest)?;

        let objects = plan
            .transfer_objects()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let source_journal = journal_inventory(source)?;
        let destination_journal = journal_inventory(destination)?;
        assert_eq!(source_journal.roots, objects);
        assert_eq!(destination_journal.roots, objects);
        assert_eq!(
            source_journal.records.keys().collect::<Vec<_>>(),
            destination_journal.records.keys().collect::<Vec<_>>()
        );
        assert_eq!(source_journal.records.len(), 1);
        require_destination_refs_absent(destination)?;
        assert_eq!(retained_source_refs(source)?, source_refs);

        // At least one real selected object arrived before the final manifest
        // failed; drain all preceding copies, not just their directory entries.
        let preceding = objects
            .iter()
            .filter(|(id, _)| **id != manifest)
            .map(|(id, length)| (*id, *length))
            .collect::<BTreeMap<_, _>>();
        assert!(!preceding.is_empty());
        authenticate_ids(&backend, &preceding)?;
        let transferred = plan
            .selected()
            .iter()
            .filter(|entry| entry.id() != manifest)
            .count();
        assert!(transferred > 0);
        Ok(Self {
            manifest,
            manifest_path,
            original_bytes,
            objects,
            source_journal,
            destination_journal,
            source_refs,
        })
    }

    fn repair_gc_and_retry(
        self,
        source: &FlightFixture,
        destination: &FlightFixture,
        snapshot: &str,
    ) -> Result<(Value, Value), Box<dyn Error>> {
        fs::write(&self.manifest_path, &self.original_bytes)?;
        assert_eq!(fs::read(&self.manifest_path)?, self.original_bytes);
        authenticate_ids(&directory_backend(destination), &self.objects)?;
        assert_eq!(journal_inventory(source)?, self.source_journal);
        assert_eq!(journal_inventory(destination)?, self.destination_journal);

        for (fixture, name) in [(source, "source"), (destination, "destination")] {
            reclaim_orphan_under_transfer_roots(fixture, name, &self.objects)?;
        }
        assert_eq!(journal_inventory(source)?, self.source_journal);
        assert_eq!(journal_inventory(destination)?, self.destination_journal);
        assert_eq!(retained_source_refs(source)?, self.source_refs);
        require_destination_refs_absent(destination)?;

        let (preflight, complete) =
            maintenance_transfer::transfer_executable_archive(source, destination, snapshot)?;
        assert_eq!(preflight["manifest"], self.manifest_id());
        assert_eq!(complete["manifest"], preflight["manifest"]);
        assert_eq!(complete["authenticated"], true);
        assert!(json_u64(&complete, "existing_objects")? > 0);
        require_completed_publication(destination, snapshot, self.manifest)?;
        require_empty_journal(source)?;
        require_empty_journal(destination)?;

        let refs = retained_source_refs(source)?;
        assert_eq!(refs, self.source_refs);
        let (again_plan, again) =
            maintenance_transfer::transfer_executable_archive(source, destination, snapshot)?;
        assert_eq!(again_plan["manifest"], preflight["manifest"]);
        assert_eq!(again["manifest"], complete["manifest"]);
        assert_eq!(again["authenticated"], true);
        assert_eq!(json_u64(&again, "copied_objects")?, 0);
        require_completed_publication(destination, snapshot, self.manifest)?;
        require_empty_journal(source)?;
        require_empty_journal(destination)?;
        assert_eq!(retained_source_refs(source)?, self.source_refs);
        Ok((preflight, complete))
    }

    fn manifest_id(&self) -> String {
        format!("crucible.campaign.archive-manifest@{}", self.manifest)
    }
}

fn require_transfer_corruption(
    source: &FlightFixture,
    destination: &FlightFixture,
    snapshot: &str,
    manifest: ContentId,
) -> Result<(), Box<dyn Error>> {
    let failed =
        maintenance_transfer::executable_archive_command(source, destination, snapshot).output()?;
    assert!(!failed.status.success());
    assert!(
        failed.stdout.is_empty(),
        "failed transfer emitted completion bytes"
    );
    let diagnostic = String::from_utf8_lossy(&failed.stderr);
    let original = StoreError::Corrupt { id: manifest }.to_string();
    assert!(
        diagnostic.contains("archive transfer failed") && diagnostic.contains(&original),
        "transfer refused without its original manifest error: {diagnostic}"
    );
    let preflight = diagnostic
        .lines()
        .find(|line| line.starts_with('{'))
        .ok_or("failed copy lacked original pre-transfer report")?;
    let report: Value = serde_json::from_str(preflight)?;
    assert_eq!(report["phase"], "pre-transfer");
    assert_eq!(
        report["manifest"],
        format!("crucible.campaign.archive-manifest@{manifest}")
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct JournalInventory {
    records: BTreeMap<String, Vec<u8>>,
    roots: BTreeMap<ContentId, u64>,
}

fn journal_inventory(fixture: &FlightFixture) -> Result<JournalInventory, Box<dyn Error>> {
    let root = fixture.state.join("campaign-transfers");
    let journal = DirectoryCampaignTransferJournal::open(&root)?;
    let mut fence = journal.acquire_campaign_transfer_retention_fence()?;
    let mut roots = BTreeMap::new();
    let summary = fence.visit_roots(&mut |root| {
        assert!(roots.insert(root.id(), root.logical_length()).is_none());
        Ok(())
    })?;
    assert!(summary.records() <= 1);
    let mut records = BTreeMap::new();
    for entry in fs::read_dir(root.join("records"))? {
        let entry = entry?;
        assert!(entry.file_type()?.is_file());
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF8 transfer record")?;
        assert!(name.ends_with(".transfer"));
        assert!(records.insert(name, fs::read(entry.path())?).is_none());
    }
    assert_eq!(summary.records(), records.len() as u64);
    assert_eq!(summary.roots(), roots.len() as u64);
    Ok(JournalInventory { records, roots })
}

fn require_empty_journal(fixture: &FlightFixture) -> Result<(), Box<dyn Error>> {
    let inventory = journal_inventory(fixture)?;
    assert!(inventory.records.is_empty() && inventory.roots.is_empty());
    Ok(())
}

fn reclaim_orphan_under_transfer_roots(
    fixture: &FlightFixture,
    role: &str,
    objects: &BTreeMap<ContentId, u64>,
) -> Result<(), Box<dyn Error>> {
    let backend = directory_backend(fixture);
    authenticate_ids(&backend, objects)?;
    let bytes = format!("interrupted-transfer {role} authenticated unreachable orphan");
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, bytes.as_bytes());
    backend.put_if_absent(orphan, &BlobHandle::from_bytes(bytes.into_bytes()))?;
    let planned = run_json(
        &mut fixture.gc_command("plan"),
        "plan incomplete transfer GC",
    )?;
    let journal = DirectoryCampaignGcJournal::open(&fixture.journal)?;
    assert!(
        journal
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == orphan)
    );
    for id in objects.keys() {
        assert!(journal.roots().iter().any(|root| root == *id));
        assert!(
            !journal
                .candidates()
                .iter()
                .any(|candidate| candidate.id() == *id)
        );
    }
    drop(journal);
    let applied = run_json(
        &mut fixture.gc_command("apply"),
        "apply incomplete transfer GC",
    )?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["apply_status"], "applied");
    assert!(!backend.contains(orphan)?);
    authenticate_ids(&backend, objects)
}

fn authenticate_ids(
    backend: &DirectoryBlobBackend,
    objects: &BTreeMap<ContentId, u64>,
) -> Result<(), Box<dyn Error>> {
    for (id, length) in objects {
        let source = backend.read(*id, None)?;
        assert_eq!(source.logical_length(), *length);
        assert_eq!(source.copy_to(&mut std::io::sink())?, *length);
    }
    Ok(())
}

fn authoritative_refs(fixture: &FlightFixture) -> DirectoryRefBackend {
    DirectoryRefBackend::new(fixture._temporary.path().join("refs"))
}

fn retained_source_refs(
    fixture: &FlightFixture,
) -> Result<BTreeMap<RefName, ContentId>, Box<dyn Error>> {
    let refs = authoritative_refs(fixture);
    std::iter::once(CAMPAIGN)
        .chain(DERIVED_CAMPAIGNS)
        .map(|campaign| {
            let name = RefName::new(format!("campaigns/{campaign}"))?;
            let value = refs
                .read_ref(&name)?
                .ok_or("interrupted transfer lost source ref")?;
            Ok((name, value))
        })
        .collect()
}

fn require_destination_refs_absent(fixture: &FlightFixture) -> Result<(), Box<dyn Error>> {
    let refs = authoritative_refs(fixture);
    for name in [
        format!("archives/{}", maintenance_transfer::ARCHIVE_NAME),
        format!("campaigns/{CAMPAIGN}"),
    ] {
        assert!(refs.read_ref(&RefName::new(name)?)?.is_none());
    }
    Ok(())
}

fn require_completed_publication(
    fixture: &FlightFixture,
    snapshot: &str,
    manifest: ContentId,
) -> Result<(), Box<dyn Error>> {
    let refs = authoritative_refs(fixture);
    assert_eq!(
        refs.read_ref(&RefName::new(format!(
            "archives/{}",
            maintenance_transfer::ARCHIVE_NAME
        ))?)?,
        Some(manifest)
    );
    assert_eq!(
        refs.read_ref(&RefName::new(format!("campaigns/{CAMPAIGN}"))?)?,
        Some(CampaignSnapshotId::parse(snapshot)?.content_id())
    );
    assert_eq!(
        maintenance_transfer::inspect_archive(fixture)?["authenticated"],
        true
    );
    Ok(())
}

fn directory_backend(fixture: &FlightFixture) -> DirectoryBlobBackend {
    DirectoryBlobBackend::new("primary", &fixture.objects)
}

fn object_path(fixture: &FlightFixture, id: ContentId) -> PathBuf {
    let encoded = id.encode();
    let digest = encoded
        .rsplit('.')
        .next()
        .expect("canonical content ID digest");
    fixture
        .objects
        .join("objects")
        .join(&digest[..2])
        .join(encoded)
}
