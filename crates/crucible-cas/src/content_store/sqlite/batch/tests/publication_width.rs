//! Wider checked SQLite transactions with unchanged aggregate source staging.

use super::*;

fn inputs() -> Vec<(ContentId, BlobHandle)> {
    (0..256_u64)
        .map(|ordinal| {
            let bytes = ordinal.to_be_bytes();
            (
                ContentId::for_bytes(ObjectKind::Trace, 1, &bytes),
                BlobHandle::from_bytes(bytes),
            )
        })
        .collect()
}

#[test]
fn full_width_advances_metadata_once_and_returns_ordered_durable_receipts() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_width::full_width_advances_metadata_once_and_returns_ordered_durable_receipts",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog fixture");
    let guard = original_quota();
    let backend = bounded_leaf("full-width", root.path(), &guard);
    let original = DecodeBudget::for_store(guard.clone()).expect("same original");
    let objects = inputs();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let before = load_metadata(&backend.lock_connection().expect("metadata"))
        .expect("metadata")
        .1;
    let receipts = backend
        .put_many_if_absent_with_boundary(&original, &objects, &mut || Ok(()))
        .expect("one checked transaction");

    assert_eq!(receipts.len(), 256);
    assert!(
        receipts
            .iter()
            .zip(&objects)
            .all(|(receipt, (id, source))| {
                receipt.id == *id
                    && receipt.is_durable()
                    && receipt
                        .placements
                        .iter()
                        .all(|placement| placement.logical_length == source.logical_length())
            })
    );
    assert_eq!(
        load_metadata(&backend.lock_connection().expect("metadata"))
            .expect("metadata")
            .1,
        before + 1
    );
    drop(receipts);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
    for (ordinal, (id, _)) in objects.iter().enumerate() {
        let source = backend
            .read_with_boundary(&original, *id, None, &mut || Ok(()))
            .expect("current row");
        let body = source
            .read_all_with_boundary(&original, 8, &mut || Ok(()))
            .expect("DONE EOF and full hash");
        assert_eq!(&*body, &(ordinal as u64).to_be_bytes());
    }
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn late_source_corruption_precedes_transaction_and_publishes_no_rows() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_width::late_source_corruption_precedes_transaction_and_publishes_no_rows",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog fixture");
    let guard = original_quota();
    let backend = bounded_leaf("full-width-corrupt", root.path(), &guard);
    let original = DecodeBudget::for_store(guard.clone()).expect("same original");
    let mut objects = inputs();
    let corrupt = objects[200].0;
    objects[200].1 = BlobHandle::from_bytes([0x19; 8]);
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let before = load_metadata(&backend.lock_connection().expect("metadata"))
        .expect("metadata")
        .1;
    let error = backend
        .put_many_if_absent_with_boundary(&original, &objects, &mut || Ok(()))
        .expect_err("full identity authentication before transaction");

    assert!(matches!(original_failure(&error), StoreError::Corrupt { id } if *id == corrupt));
    assert_eq!(
        load_metadata(&backend.lock_connection().expect("metadata"))
            .expect("metadata")
            .1,
        before
    );
    let count: i64 = backend
        .lock_connection()
        .expect("row count")
        .query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))
        .expect("row count");
    assert_eq!(count, 0);
    drop(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
}
