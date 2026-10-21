//! Checks actual ordinary descriptor receipts without protected effect authority.

#![allow(clippy::unwrap_used, reason = "Fixture failures are test assertions")]

use crate::bucket::tests;
use crate::store::{CorruptSubject, StoreErrorKind};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use terrane_format::bucket::BucketKey;

fn key() -> BucketKey {
    BucketKey::parse("objects/index/2/MANIFEST").unwrap()
}

#[tokio::test]
async fn ordinary_receipt_keeps_public_hardlinks_and_actual_full_metadata() {
    let bucket = tests::fixture().await;
    let key = key();
    let path = bucket.path(&key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = b"independent complete ordinary artifact";
    std::fs::write(&path, bytes).unwrap();
    std::fs::hard_link(&path, path.with_file_name("alias")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let metadata = std::fs::symlink_metadata(&path).unwrap();

    let read = bucket.read_optional_ordinary_retained(&key).await.unwrap();
    assert_eq!(read.bytes(), Some(bytes.as_slice()));
    assert_eq!(read.path(), path);
    let original = read.metadata().unwrap();
    assert_eq!(original.len(), bytes.len() as u64);
    assert_eq!(
        (original.dev(), original.ino()),
        (metadata.dev(), metadata.ino())
    );
    assert_eq!(original.nlink(), 2);
    assert_eq!(original.mode() & 0o777, 0o666);
    assert!(read.is_ordinary_retained());
    assert!(read.retained_payload().is_none());
    read.revalidate_retained(&bucket.inner.fs).await.unwrap();
    let cloned = read.clone();
    cloned.revalidate_retained(&bucket.inner.fs).await.unwrap();
    assert_eq!(cloned.into_bytes(), Some(bytes.to_vec()));
}

#[tokio::test]
async fn ordinary_receipt_preserves_missing_and_incompatible_layout_outcomes() {
    let bucket = tests::fixture().await;
    let key = key();
    let path = bucket.path(&key);
    let read = bucket.read_optional_ordinary_retained(&key).await.unwrap();
    assert!(read.bytes().is_none());
    assert!(read.metadata().is_none());
    assert!(!read.is_ordinary_retained());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    assert!(
        bucket
            .read_optional_ordinary_retained(&key)
            .await
            .unwrap()
            .bytes()
            .is_none()
    );

    let target = path.with_file_name("target");
    std::fs::write(&target, b"not the named file").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let error = bucket
        .read_optional_ordinary_retained(&key)
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Corrupt(CorruptSubject::RefName("CAPABILITIES".into()))
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let error = bucket
        .read_optional_ordinary_retained(&key)
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Corrupt(CorruptSubject::RefName("CAPABILITIES".into()))
    );
}

#[tokio::test]
async fn ordinary_receipt_refuses_equal_bytes_replaced_leaf_and_ancestor() {
    let bucket = tests::fixture().await;
    let key = key();
    let path = bucket.path(&key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = b"unchanged bytes do not recapture original identity";
    std::fs::write(&path, bytes).unwrap();
    let read = bucket.read_optional_ordinary_retained(&key).await.unwrap();
    let old = path.with_file_name("original");
    std::fs::rename(&path, &old).unwrap();
    std::fs::write(&path, bytes).unwrap();
    assert_ne!(
        read.metadata().unwrap().ino(),
        std::fs::metadata(&path).unwrap().ino()
    );
    assert!(read.revalidate_retained(&bucket.inner.fs).await.is_err());

    let current = bucket.read_optional_ordinary_retained(&key).await.unwrap();
    let parent = path.parent().unwrap();
    let saved = parent.with_file_name("old-parent");
    std::fs::rename(parent, &saved).unwrap();
    std::fs::create_dir(parent).unwrap();
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(current.revalidate_retained(&bucket.inner.fs).await.is_err());
}

#[tokio::test]
async fn ordinary_receipt_cannot_supply_protected_effect_inputs() {
    let bucket = tests::fixture().await;
    let key = key();
    let path = bucket.path(&key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"otherwise protected-compatible bytes").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let read = bucket.read_optional_ordinary_retained(&key).await.unwrap();
    read.revalidate_retained(&bucket.inner.fs).await.unwrap();
    assert!(read.retained_payload().is_none());
    assert_eq!(
        read.require_effect_compatible().err().unwrap().kind(),
        &StoreErrorKind::Unsupported
    );
    assert_eq!(
        read.clone()
            .require_effect_compatible()
            .err()
            .unwrap()
            .kind(),
        &StoreErrorKind::Unsupported
    );

    let protected = crate::store::native_publication_effects::PayloadReadCapture::capture(
        &bucket.inner.fs,
        &path,
        bucket.publication_operator_uid().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        protected.finish(&read).err().unwrap().kind(),
        &StoreErrorKind::Unsupported
    );
}

#[tokio::test]
async fn ordinary_body_batch_preserves_each_original_and_stops_at_missing_suffix() {
    let bucket = tests::fixture().await;
    let first = BucketKey::parse("objects/index/2/0.idx").unwrap();
    let second = BucketKey::parse("objects/index/2/1.idx").unwrap();
    let missing = BucketKey::parse("objects/index/2/2.idx").unwrap();
    let later = BucketKey::parse("objects/index/2/3.idx").unwrap();
    let path = bucket.path(&first);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"original first body").unwrap();
    std::fs::write(bucket.path(&second), b"original second body").unwrap();
    std::fs::write(bucket.path(&later), b"later body must not be consumed").unwrap();
    std::fs::hard_link(&path, path.with_file_name("alias")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

    let mut rows = bucket
        .read_optional_ordinary_batch(&[first.clone(), second, missing, later])
        .await
        .unwrap()
        .unwrap()
        .into_iter();
    let first = rows.next().unwrap().unwrap();
    let second = rows.next().unwrap().unwrap();
    let absent = rows.next().unwrap().unwrap();
    assert!(rows.next().is_none());
    assert_eq!(first.bytes(), Some(b"original first body".as_slice()));
    assert_eq!(second.bytes(), Some(b"original second body".as_slice()));
    assert!(absent.bytes().is_none());
    assert!(!absent.is_ordinary_retained());
    assert_eq!(first.metadata().unwrap().nlink(), 2);
    assert_eq!(first.metadata().unwrap().mode() & 0o777, 0o666);
    first.revalidate_retained(&bucket.inner.fs).await.unwrap();
    second.revalidate_retained(&bucket.inner.fs).await.unwrap();

    std::fs::rename(&path, path.with_file_name("original-first")).unwrap();
    std::fs::write(&path, b"original first body").unwrap();
    assert!(first.revalidate_retained(&bucket.inner.fs).await.is_err());
    second.revalidate_retained(&bucket.inner.fs).await.unwrap();
}

#[tokio::test]
async fn ordinary_body_batch_refuses_symlinked_leaf_before_later_body_reads() {
    let bucket = tests::fixture().await;
    let first = BucketKey::parse("objects/index/2/0.idx").unwrap();
    let second = BucketKey::parse("objects/index/2/1.idx").unwrap();
    let later = BucketKey::parse("objects/index/2/2.idx").unwrap();
    let path = bucket.path(&first);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"independent ordinary first").unwrap();
    std::os::unix::fs::symlink(&path, bucket.path(&second)).unwrap();
    std::fs::write(bucket.path(&later), b"unread later body").unwrap();

    let mut rows = bucket
        .read_optional_ordinary_batch(&[first, second, later])
        .await
        .unwrap()
        .unwrap()
        .into_iter();
    assert_eq!(
        rows.next().unwrap().unwrap().bytes(),
        Some(b"independent ordinary first".as_slice())
    );
    assert_eq!(
        rows.next().unwrap().err().unwrap().kind(),
        &StoreErrorKind::Corrupt(CorruptSubject::RefName("CAPABILITIES".into()))
    );
    assert!(rows.next().is_none());
}
