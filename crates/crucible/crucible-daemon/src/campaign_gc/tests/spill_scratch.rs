//! Scratch-directory lifetime and duplicate-inventory regressions for
//! externally sorted GC planning and apply.

use super::*;

/// Names the private GC scratch directories directly inside `parent`.
fn scratch_directories(parent: &std::path::Path) -> Vec<String> {
    fs::read_dir(parent)
        .expect("list scratch parent")
        .map(|entry| {
            entry
                .expect("scratch parent entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with(".crucible-gc-spill."))
        .collect()
}

#[test]
fn planning_scratch_lives_with_the_plan_and_the_journal_keeps_its_own_copies() {
    let fixture = apply_fixture(2);
    assert_eq!(
        scratch_directories(fixture.spill_parent.path()).len(),
        1,
        "the prepared plan's manifests live in one scratch directory"
    );
    let journal_parent = tempfile::tempdir().expect("journal parent");
    let journal_root = journal_parent.path().join("journal");
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &fixture.prepared)
        .expect("create journal");
    let expected = fixture.prepared.candidates().entries_for_test();
    let ApplyFixture {
        prepared,
        spill_parent,
        ..
    } = fixture;

    drop(prepared);

    assert!(scratch_directories(spill_parent.path()).is_empty());
    assert_eq!(journal.candidates().entries_for_test(), expected);
    assert!(journal.candidates().path().starts_with(&journal_root));
    assert!(journal.roots().path().starts_with(&journal_root));
}

#[test]
fn planning_rejects_a_duplicated_placement_and_removes_its_scratch() {
    let spill_parent = tempfile::tempdir().expect("GC spill parent");
    let blobs = Arc::new(MemoryBlobBackend::new("duplicate-primary", 1024 * 1024));
    let orphan_bytes = b"duplicated orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store orphan");
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let duplicating = DuplicatingInventoryAdmin {
        inner: blobs.as_ref(),
    };
    let physical = CampaignGcRawPhysicalStore::new("duplicate-primary", &duplicating)
        .expect("duplicating physical store");
    let mut ledger = MemoryAssignmentLedger::default();

    let result = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        hash("crucible.test.gc.duplicate-placement.v1", 0x31),
        &[physical],
        spill_parent.path(),
    );

    assert!(matches!(
        result,
        Err(CampaignGcPlanningError::Blob {
            source: StoreError::InvalidComposition { .. },
            ..
        })
    ));
    assert!(scratch_directories(spill_parent.path()).is_empty());
}

#[test]
fn apply_counts_a_duplicated_candidate_placement_and_fails_before_deletion() {
    let mut fixture = apply_fixture(1);
    let journal_parent = tempfile::tempdir().expect("journal parent");
    let journal_root = journal_parent.path().join("journal");
    let (mut journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &fixture.prepared)
        .expect("create journal");
    let duplicating = DuplicatingInventoryAdmin {
        inner: fixture.blobs.as_ref(),
    };
    let physical = CampaignGcRawPhysicalStore::new("apply-primary", &duplicating)
        .expect("duplicating physical store");

    let result = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut fixture.ledger,
            None,
            None,
        ),
        fixture.graph,
        &[physical],
    );

    assert!(matches!(
        result,
        Err(CampaignGcApplyError::CandidateSetChanged { .. })
    ));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(fixture.blobs.object_count().expect("object count"), 1);
    assert!(scratch_directories(&journal_root).is_empty());
}

#[test]
fn successful_apply_removes_its_scratch_from_the_journal() {
    let mut fixture = apply_fixture(2);
    let journal_parent = tempfile::tempdir().expect("journal parent");
    let journal_root = journal_parent.path().join("journal");
    let (mut journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &fixture.prepared)
        .expect("create journal");
    let physical = CampaignGcRawPhysicalStore::new("apply-primary", fixture.blobs.as_ref())
        .expect("apply physical store");

    let report = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut fixture.ledger,
            None,
            None,
        ),
        fixture.graph,
        &[physical],
    )
    .expect("apply plan");

    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(scratch_directories(&journal_root).is_empty());
}

/// Admin whose inventory reports every placement twice.
struct DuplicatingInventoryAdmin<'a> {
    inner: &'a MemoryBlobBackend,
}

impl BlobStoreAdmin for DuplicatingInventoryAdmin<'_> {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        Ok(Box::new(DuplicatingInventoryFence {
            inner: self.inner.acquire_inventory_fence()?,
        }))
    }
}

struct DuplicatingInventoryFence<'a> {
    inner: Box<dyn BlobInventoryFence + 'a>,
}

impl BlobInventoryFence for DuplicatingInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        self.inner.visit_inventory(&mut |record| {
            visitor(record)?;
            visitor(record)
        })
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        self.inner.delete_candidate(id)
    }
}
