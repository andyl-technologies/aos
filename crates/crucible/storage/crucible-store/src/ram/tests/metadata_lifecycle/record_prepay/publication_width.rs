//! Bounded pending metadata and byte totals under the existing original bank.

use super::*;

#[test]
fn pending_width_keeps_exact_encoded_total_and_duplicate_does_not_grow_it() {
    let directory = tempfile::tempdir().expect("RAM codec fixture");
    let quota = ObservedQuota::new();
    let backend = Arc::new(
        crate::content_store::PackedBlobBackend::open(
            "pending-width",
            directory.path(),
            4 * 1024 * 1024,
        )
        .expect("actual wide publication backend"),
    );
    let store = RamStore::new(
        backend,
        DurabilityRequirement::new(1, false).expect("durable"),
        RamStoreLimits::default(),
    )
    .expect("actual packed store");
    let original = DecodeBudget::for_store(quota.clone()).expect("same original");
    let baseline = quota.used();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).expect("same work");
    store
        .begin_publication_batch(&mut work)
        .expect("paid pending metadata");
    for ordinal in 0..256_u64 {
        let mut page = [0x19; 4096];
        page[..8].copy_from_slice(&ordinal.to_be_bytes());
        store
            .put_page(&page, &OriginalRetention, &mut work)
            .expect("actual page codec");
    }
    let pending = work.pending.as_ref().expect("pending retained");
    assert_eq!(pending.len(), 256);
    assert_eq!(
        pending.encoded_bytes,
        pending
            .iter()
            .map(|object| object.source.logical_length())
            .sum::<u64>()
    );
    assert!(pending.encoded_bytes <= 4 * 1024 * 1024);
    let total = pending.encoded_bytes;
    let mut last = [0x19; 4096];
    last[..8].copy_from_slice(&255_u64.to_be_bytes());
    store
        .put_page(&last, &OriginalRetention, &mut work)
        .expect("pending duplicate");
    assert_eq!(work.pending.as_ref().expect("same batch").len(), 256);
    assert_eq!(
        work.pending.as_ref().expect("same batch").encoded_bytes,
        total
    );
    store
        .flush_publication_batch(&mut work)
        .expect("checked publication and readback");
    assert_eq!(
        work.pending
            .as_ref()
            .expect("next empty batch")
            .encoded_bytes,
        0
    );
    drop(work);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn full_width_directory_outcome_survives_outer_validation_refusal() {
    let directory = tempfile::tempdir().expect("directory outcome fixture");
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let original = DecodeBudget::for_store(quota.clone()).expect("same original");
    let baseline = quota.used();
    let objects = (0..256_u64)
        .map(|ordinal| {
            let bytes = ordinal.to_be_bytes().to_vec();
            let id = ContentId::for_bytes(crate::content_store::ObjectKind::Trace, 1, &bytes);
            (id, crate::content_store::BlobHandle::from_bytes(bytes))
        })
        .collect::<Vec<_>>();

    let receipt = store
        .backend
        .put_many_if_absent_with_boundary(&original, &objects, &mut || Ok(()))
        .expect("actual 256 durable directory publications");
    let error = receipt
        .check(|_| Err(StoreError::Unavailable))
        .expect_err("same committed scope retains outer validation refusal");

    let StoreError::DirectoryScope { source } = &error else {
        panic!("actual directory carrier: {error:?}")
    };
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::Unavailable)
    ));
    assert_eq!(source.outcome().published_objects, 256);
    assert_eq!(source.outcome().durable_objects, 256);
    assert!(!source.outcome().durability_uncertain);
    assert!(source.cleanup_failure().is_none());
    drop(error);
    assert_eq!(quota.used(), baseline);
    original
        .check()
        .expect("original remains live after local refusal");
}
