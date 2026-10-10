//! Shared fenced batch deletion, interruption, and fresh-plan recovery.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct ObservedAdmin {
    backend: Arc<MemoryBlobBackend>,
    inventories: Arc<AtomicUsize>,
    visits: Arc<AtomicUsize>,
    deletions: Arc<AtomicUsize>,
}

impl BlobStoreAdmin for ObservedAdmin {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        Ok(Box::new(ObservedFence {
            inner: self.backend.acquire_inventory_fence()?,
            inventories: &self.inventories,
            visits: &self.visits,
            deletions: &self.deletions,
        }))
    }
}

struct ObservedFence<'a> {
    inner: Box<dyn BlobInventoryFence + 'a>,
    inventories: &'a AtomicUsize,
    visits: &'a AtomicUsize,
    deletions: &'a AtomicUsize,
}

impl BlobInventoryFence for ObservedFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        self.inventories.fetch_add(1, Ordering::SeqCst);
        self.inner.visit_inventory(&mut |record| {
            self.visits.fetch_add(1, Ordering::SeqCst);
            visitor(record)
        })
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let result = self.inner.delete_candidate(id)?;
        self.deletions.fetch_add(1, Ordering::SeqCst);
        Ok(result)
    }
}

#[derive(Debug)]
pub(super) struct OriginalBoundaryFailure;

impl std::fmt::Display for OriginalBoundaryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original finite GC scope stopped after its second deletion")
    }
}

impl std::error::Error for OriginalBoundaryFailure {}

pub(super) fn has_original_boundary(error: &(dyn std::error::Error + 'static)) -> bool {
    error.is::<OriginalBoundaryFailure>() || error.source().is_some_and(has_original_boundary)
}

#[test]
fn unreachable_batch_has_constant_inventory_passes() {
    let mut gc_fixture = crate::campaign_gc::ComponentGcOperation::new();
    let operation = gc_fixture.context();
    let mut fixture = apply_fixture(64, &operation);
    let temp = tempfile::TempDir::new().expect("journal parent");
    let (mut journal, _) = DirectoryCampaignGcJournal::create(
        temp.path().join("batch"),
        &fixture.prepared,
        &operation,
    )
    .expect("durable admitted batch");
    let admin = ObservedAdmin {
        backend: fixture.blobs.clone(),
        inventories: Arc::new(AtomicUsize::new(0)),
        visits: Arc::new(AtomicUsize::new(0)),
        deletions: Arc::new(AtomicUsize::new(0)),
    };
    let physical =
        CampaignGcRawPhysicalStore::new("apply-primary", &admin).expect("same physical authority");

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
        &operation,
    )
    .expect("fenced bounded batch");

    assert_eq!(report.candidates(), 64);
    assert_eq!(admin.deletions.load(Ordering::SeqCst), 64);
    assert_eq!(admin.inventories.load(Ordering::SeqCst), 3);
    assert_eq!(admin.visits.load(Ordering::SeqCst), 128);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn interrupted_batch_retains_typed_cause_and_requires_fresh_plan() {
    let mut gc_fixture = crate::campaign_gc::ComponentGcOperation::new();
    let original = gc_fixture.context();
    let mut fixture = apply_fixture(8, &original);
    let temp = tempfile::TempDir::new().expect("journal parent");
    let (mut journal, _) = DirectoryCampaignGcJournal::create(
        temp.path().join("interrupted"),
        &fixture.prepared,
        &original,
    )
    .expect("durable original batch");
    let admin = ObservedAdmin {
        backend: fixture.blobs.clone(),
        inventories: Arc::new(AtomicUsize::new(0)),
        visits: Arc::new(AtomicUsize::new(0)),
        deletions: Arc::new(AtomicUsize::new(0)),
    };
    let stopped = AtomicBool::new(false);
    let mut boundary = || {
        original.check()?;
        if admin.deletions.load(Ordering::SeqCst) == 2 && !stopped.swap(true, Ordering::SeqCst) {
            return Err(StoreError::Supervision {
                source: Box::new(OriginalBoundaryFailure),
            });
        }
        Ok(())
    };
    let interrupted =
        CampaignGcOperationContext::new(original.marks(), original.original(), &mut boundary)
            .expect("same admitted mark authority");
    let physical =
        CampaignGcRawPhysicalStore::new("apply-primary", &admin).expect("same physical authority");

    let error = apply_single_host_campaign_gc(
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
        &interrupted,
    )
    .expect_err("original boundary must stop the batch");
    assert!(has_original_boundary(&error));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Applying);
    assert_eq!(fixture.blobs.object_count().expect("remaining objects"), 6);
    drop(interrupted);

    let old_plan = apply_single_host_campaign_gc(
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
        &original,
    );
    assert!(
        matches!(old_plan, Err(CampaignGcApplyError::InterruptedJournal)),
        "an Applying journal must refuse reuse before inventory revalidation: {old_plan:?}",
    );
    let fresh = plan_single_host_campaign_gc(
        &fixture.repository,
        fixture.refs.as_ref(),
        &mut fixture.ledger,
        None,
        None,
        fixture.graph,
        (&[physical], &original),
    )
    .expect("authenticate fresh remaining inventory");
    let (mut fresh_journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("fresh"), &fresh, &original)
            .expect("fresh durable batch");
    let report = apply_single_host_campaign_gc(
        &mut fresh_journal,
        CampaignGcApplySources::new(
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut fixture.ledger,
            None,
            None,
        ),
        fixture.graph,
        &[physical],
        &original,
    )
    .expect("collect remaining objects under a fresh plan");
    assert_eq!(report.candidates(), 6);
    assert_eq!(fixture.blobs.object_count().expect("final objects"), 0);
}
