//! GC immutable metadata sharing and original-credit journal admission.

use std::sync::atomic::{AtomicBool, Ordering};

use crucible_cas::content_store::StorePhysicalQuotaGuard;

use super::*;

#[test]
fn prepared_and_journal_clones_retain_metadata_until_the_last_borrower() {
    let mut fixture = operation::ComponentGcOperation::new();
    let resources = fixture.resources();
    let operation = fixture.context();
    let prepared = apply_fixture(1, &operation).prepared;
    let clone = prepared.clone();
    assert!(std::ptr::eq(
        prepared.plan().physical().as_ptr(),
        clone.plan().physical().as_ptr()
    ));
    assert!(std::ptr::eq(
        prepared.candidates().iter().next().expect("one candidate"),
        clone.candidates().iter().next().expect("cloned candidate"),
    ));
    let canonical = prepared
        .plan()
        .canonical_bytes(&operation)
        .expect("canonical header");
    assert_eq!(
        prepared.plan().id().expect("streamed identity").as_hash(),
        CampaignHash::derive(super::super::GC_PLAN_ID_DOMAIN, &canonical)
    );

    drop(canonical);
    let directory = tempfile::tempdir().expect("journal parent");
    let (journal, _) =
        DirectoryCampaignGcJournal::create(directory.path().join("journal"), &prepared, &operation)
            .expect("admitted journal");
    assert!(std::ptr::eq(
        prepared.plan().physical().as_ptr(),
        journal.plan().physical().as_ptr()
    ));
    let retained_plan = journal.plan().clone();
    let retained_candidates = journal.candidates().clone();
    drop(prepared);
    drop(clone);
    drop(journal);
    drop(operation);
    drop(fixture);

    const COMPLETE_ALLOWANCE: u64 = 256 * 1024 * 1024;
    assert!(matches!(
        resources.reserve_resources(0, COMPLETE_ALLOWANCE),
        Err(StoreError::Quota)
    ));
    drop(retained_plan);
    assert!(matches!(
        resources.reserve_resources(0, COMPLETE_ALLOWANCE),
        Err(StoreError::Quota)
    ));
    drop(retained_candidates);
    let complete = resources
        .reserve_resources(128, COMPLETE_ALLOWANCE)
        .expect("final metadata borrower releases the original finite account");
    drop(complete);
}

struct RefusingResources {
    inner: Arc<dyn StorePhysicalQuotaGuard>,
    refuse: AtomicBool,
}

impl StorePhysicalQuotaGuard for RefusingResources {
    fn verify(&self) -> Result<(), StoreError> {
        self.inner.verify()
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<Arc<dyn Send + Sync>, StoreError> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(StoreError::Quota);
        }
        self.inner.reserve_resources(descriptors, resident_bytes)
    }
}

#[test]
fn journal_open_refuses_original_credit_before_decoding_any_persisted_manifest() {
    let resources = Arc::new(RefusingResources {
        inner: crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
            .expect("finite original metadata account"),
        refuse: AtomicBool::new(false),
    });
    let mut fixture = operation::ComponentGcOperation::with_resources(resources.clone());
    let operation = fixture.context();
    let prepared = apply_fixture(1, &operation).prepared;
    let directory = tempfile::tempdir().expect("journal parent");
    let root = directory.path().join("journal");
    let (journal, _) =
        DirectoryCampaignGcJournal::create(&root, &prepared, &operation).expect("valid journal");
    drop(journal);
    // Even a malformed header must not be read before its account admits the
    // journal's exact descriptor and bounded codec/path custody.
    std::fs::write(root.join("plan-v2"), b"malformed").expect("malformed persisted header");
    resources.refuse.store(true, Ordering::SeqCst);
    assert!(matches!(
        DirectoryCampaignGcJournal::open(&root, &operation),
        Err(CampaignGcJournalError::Resources(StoreError::Quota))
    ));
    resources.refuse.store(false, Ordering::SeqCst);
    assert!(matches!(
        DirectoryCampaignGcJournal::open(&root, &operation),
        Err(CampaignGcJournalError::Plan(
            CampaignGcPlanError::InvalidLength
        ))
    ));
}
