//! Measures complete control-fence walks and preserves predicate/error order.

use super::*;

fn expected_walks(
    bucket: &FileBucket<ReadFs, TokioClock, Validator>,
    control: &Control,
) -> Vec<PathBuf> {
    let key = BucketKey::parse("CAPABILITIES").unwrap();
    let coordination = bucket.root().join(key.lock_name());
    let mut result = Vec::new();
    for walk in [
        bucket.root(),
        control.path.parent().unwrap(),
        coordination.parent().unwrap(),
    ] {
        let mut path = PathBuf::new();
        for part in walk.components() {
            path.push(part);
            result.push(path.clone());
        }
    }
    result
}

#[tokio::test]
async fn control_recheck_batches_all_three_walks_with_duplicate_entry_parity() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let expected = expected_walks(&bucket, &control);
    bucket.inner.fs.scalar_batches.store(true, Ordering::SeqCst);
    bucket.inner.fs.reset_read_counters();
    control.recheck(&bucket.inner.fs).await.unwrap();
    let scalar = bucket.inner.fs.read_counters();

    bucket
        .inner
        .fs
        .scalar_batches
        .store(false, Ordering::SeqCst);
    bucket.inner.fs.reset_read_counters();
    control.recheck(&bucket.inner.fs).await.unwrap();
    let native = bucket.inner.fs.read_counters();
    assert_eq!(native.0, scalar.0);
    assert_eq!(native.0, expected.len() + 3);
    assert_eq!(native.1, 4);
    assert!(native.1 < scalar.1);
    assert_eq!(native.2, 0);
    assert_eq!(*bucket.inner.fs.batch_paths.lock().unwrap(), vec![expected]);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    eprintln!("control fence entries/dispatches/GETs {scalar:?}->{native:?}");
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn control_recheck_short_combined_walk_refuses_before_leaf_reads() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let expected = expected_walks(&bucket, &control);
    bucket.inner.fs.reset_read_counters();
    bucket.inner.fs.short_batch.store(true, Ordering::SeqCst);

    assert!(matches!(
        control.recheck(&bucket.inner.fs).await.unwrap_err().kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert_eq!(
        bucket.inner.fs.metadata_reads.load(Ordering::SeqCst),
        expected.len()
    );
    assert_eq!(bucket.inner.fs.record_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    control.recheck(&bucket.inner.fs).await.unwrap();
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn control_recheck_earlier_unsafe_walk_precedes_later_missing_coordination_parent() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let locks = bucket.root().join(".terrane-locks");
    let saved = bucket.root().join("saved-coordination");
    let original = TokioLocalFs
        .symlink_metadata(bucket.root())
        .await
        .unwrap()
        .permissions();
    TokioLocalFs
        .set_permissions_and_sync(bucket.root(), std::fs::Permissions::from_mode(0o775))
        .await
        .unwrap();
    tokio::fs::rename(&locks, &saved).await.unwrap();
    bucket.inner.fs.reset_read_counters();

    assert!(matches!(
        control.recheck(&bucket.inner.fs).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(
        bucket
            .inner
            .fs
            .batch_paths
            .lock()
            .unwrap()
            .first()
            .unwrap()
            .contains(&locks)
    );
    assert_eq!(bucket.inner.fs.record_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    tokio::fs::rename(&saved, &locks).await.unwrap();
    TokioLocalFs
        .set_permissions_and_sync(bucket.root(), original)
        .await
        .unwrap();
    control.recheck(&bucket.inner.fs).await.unwrap();
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn control_recheck_retains_final_leaf_check_after_combined_walk_mutation() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let original = TokioLocalFs
        .symlink_metadata(bucket.root())
        .await
        .unwrap()
        .permissions();
    bucket.inner.fs.reset_read_counters();
    *bucket.inner.fs.batch_permission_change.lock().unwrap() =
        Some((bucket.root().to_owned(), bucket.root().to_owned()));

    assert!(control.recheck(&bucket.inner.fs).await.is_err());
    assert!(
        bucket
            .inner
            .fs
            .batch_permission_change
            .lock()
            .unwrap()
            .is_none()
    );
    assert_eq!(bucket.inner.fs.record_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    TokioLocalFs
        .set_permissions_and_sync(bucket.root(), original)
        .await
        .unwrap();
    control.recheck(&bucket.inner.fs).await.unwrap();
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}
