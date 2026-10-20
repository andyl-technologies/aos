//! Compares ordinary native reads with scalar faults and complete consumers.

#![allow(clippy::unwrap_used, reason = "fixture failures are test assertions")]

mod content;
mod fixture;

use crate::bucket::tests;
use crate::store::{CorruptSubject, LocalFs, NativeOrdinaryRead, StoreErrorKind};
use fixture::{DefaultFs, Fault, Mode, Probe, bucket};
use std::io::ErrorKind;
use terrane_format::bucket::BucketKey;

fn key() -> BucketKey {
    BucketKey::parse("objects/index/2/MANIFEST").unwrap()
}

fn assert_layout(error: &crate::store::StoreFailure) {
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Corrupt(CorruptSubject::RefName("CAPABILITIES".into()))
    );
}

#[tokio::test]
async fn ordinary_consumer_matches_native_and_scalar_outcomes() {
    let source = tests::fixture().await;
    let key = key();
    let path = source.path(&key);
    for mode in [Mode::Native, Mode::Scalar] {
        let probe = bucket(&source, mode, Fault::None);
        assert!(probe.read_optional(&key).await.unwrap().is_none());
        assert_eq!(probe.inner.fs.counts(), (1, 0, 0, 0));
    }
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for mode in [Mode::Native, Mode::Scalar] {
        let probe = bucket(&source, mode, Fault::None);
        assert!(probe.read_optional(&key).await.unwrap().is_none());
        assert_eq!(
            probe.inner.fs.counts(),
            if matches!(mode, Mode::Native) {
                (1, 1, 0, 0)
            } else {
                (1, 1, 1, 0)
            }
        );
    }
    let bytes = vec![0x7c; 2 * 1024 * 1024 + 31];
    std::fs::write(&path, &bytes).unwrap();
    std::fs::hard_link(&path, path.with_file_name("alias")).unwrap();
    for mode in [Mode::Native, Mode::Scalar] {
        let probe = bucket(&source, mode, Fault::None);
        let record = probe.read_optional_observed(&key).await.unwrap();
        assert_eq!(record.bytes(), Some(bytes.as_slice()));
        assert_eq!(record.path(), path);
        assert_eq!(record.metadata().unwrap().len(), bytes.len() as u64);
        assert_eq!(
            probe.inner.fs.counts(),
            if matches!(mode, Mode::Native) {
                (1, 1, 0, 0)
            } else {
                (1, 1, 2, 1)
            }
        );
    }
    std::fs::remove_file(&path).unwrap();
    for node in ["directory", "symlink", "fifo"] {
        match node {
            "directory" => std::fs::create_dir(&path).unwrap(),
            "symlink" => std::os::unix::fs::symlink(path.with_file_name("alias"), &path).unwrap(),
            _ => assert!(
                std::process::Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            ),
        }
        for mode in [Mode::Native, Mode::Scalar] {
            let probe = bucket(&source, mode, Fault::None);
            assert_layout(&probe.read_optional(&key).await.unwrap_err());
            assert_eq!(probe.inner.fs.counts().3, 0);
        }
        if node == "directory" {
            std::fs::remove_dir(&path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
    }
    std::fs::remove_dir_all(source.root()).unwrap();
}

#[tokio::test]
async fn ordinary_consumer_rejects_ordered_parents_before_leaf_hook() {
    let source = tests::fixture().await;
    let objects = source.root().join("objects");
    std::fs::create_dir_all(&objects).unwrap();
    // Initialization creates this directory; deliberately replace its node type.
    std::fs::remove_dir_all(objects.join("index")).unwrap();
    std::fs::write(objects.join("index"), b"unsafe earlier parent").unwrap();
    for fault in [
        Fault::None,
        Fault::LaterParent(ErrorKind::NotFound),
        Fault::LaterParent(ErrorKind::PermissionDenied),
    ] {
        let probe = bucket(&source, Mode::Native, fault);
        assert_layout(&probe.read_optional(&key()).await.unwrap_err());
        assert_eq!(probe.inner.fs.counts(), (1, 0, 0, 0));
    }
    std::fs::remove_dir_all(source.root()).unwrap();
}

#[tokio::test]
async fn ordinary_consumer_rejects_short_parent_batch_before_leaf_hook() {
    let source = tests::fixture().await;
    let probe = bucket(&source, Mode::Native, Fault::ShortBatch);
    assert_layout(&probe.read_optional(&key()).await.unwrap_err());
    assert_eq!(probe.inner.fs.counts(), (1, 0, 0, 0));
    std::fs::remove_dir_all(source.root()).unwrap();
}

#[tokio::test]
async fn ordinary_consumer_propagates_supported_errors_without_scalar_retry() {
    let source = tests::fixture().await;
    let key = key();
    std::fs::create_dir_all(source.path(&key).parent().unwrap()).unwrap();
    for (actual, expected) in [
        (ErrorKind::PermissionDenied, StoreErrorKind::ReadOnly),
        (ErrorKind::ReadOnlyFilesystem, StoreErrorKind::ReadOnly),
        (ErrorKind::StorageFull, StoreErrorKind::Capacity),
        (ErrorKind::Unsupported, StoreErrorKind::Unsupported),
        (
            ErrorKind::InvalidInput,
            StoreErrorKind::Unavailable { retry_after: None },
        ),
        (
            ErrorKind::NotFound,
            StoreErrorKind::Unavailable { retry_after: None },
        ),
    ] {
        let probe = bucket(&source, Mode::Error(actual), Fault::None);
        assert_eq!(
            probe.read_optional(&key).await.unwrap_err().kind(),
            &expected
        );
        assert_eq!(probe.inner.fs.counts(), (1, 1, 0, 0));
    }
    std::fs::remove_dir_all(source.root()).unwrap();
}

#[tokio::test]
async fn ordinary_consumer_scalar_fallback_preserves_all_fault_boundaries() {
    let source = tests::fixture().await;
    let key = key();
    let path = source.path(&key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"whole scalar body").unwrap();
    for (fault, counts, absent) in [
        (Fault::Before(ErrorKind::NotFound), (1, 1, 1, 0), true),
        (Fault::Body(ErrorKind::NotFound), (1, 1, 1, 1), true),
        (Fault::After(ErrorKind::NotFound), (1, 1, 2, 1), false),
        (Fault::Before(ErrorKind::Interrupted), (1, 1, 1, 0), false),
        (Fault::Body(ErrorKind::Interrupted), (1, 1, 1, 1), false),
        (Fault::After(ErrorKind::Interrupted), (1, 1, 2, 1), false),
    ] {
        let probe = bucket(&source, Mode::Scalar, fault);
        let result = probe.read_optional(&key).await;
        if absent {
            assert!(result.unwrap().is_none());
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                &StoreErrorKind::Unavailable { retry_after: None }
            );
        }
        assert_eq!(probe.inner.fs.counts(), counts);
    }
    std::fs::remove_dir_all(source.root()).unwrap();
}

#[tokio::test]
async fn ordinary_consumer_forwards_only_actual_transparent_bindings() {
    let source = tests::fixture().await;
    let path = source.root().join("ordinary-leaf");
    std::fs::write(&path, b"actual captured binding").unwrap();
    for mode in [
        Mode::Native,
        Mode::Scalar,
        Mode::Error(ErrorKind::StorageFull),
    ] {
        let captured = Probe::new(mode, Fault::None);
        let borrowed = crate::ref_advance::FsRef(&captured);
        let result = borrowed
            .read_ordinary_record(NativeOrdinaryRead::for_leaf(&path))
            .await;
        match mode {
            Mode::Native => assert!(result.unwrap().is_some()),
            Mode::Scalar => assert!(result.unwrap().is_none()),
            Mode::Error(kind) => assert_eq!(result.err().unwrap().kind(), kind),
        }
        assert_eq!(captured.counts(), (0, 1, 0, 0));
    }
    let default = DefaultFs(Probe::new(Mode::Native, Fault::None));
    let borrowed = crate::ref_advance::FsRef(&default);
    assert!(
        borrowed
            .read_ordinary_record(NativeOrdinaryRead::for_leaf(
                &source.root().join("absent-default")
            ))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(default.0.counts(), (0, 0, 0, 0));
    std::fs::remove_dir_all(source.root()).unwrap();
}

#[tokio::test]
async fn ordinary_consumer_keeps_parent_recheck_and_whole_body_verification() {
    content::parent_recheck_and_whole_body().await;
}

#[tokio::test]
async fn ordinary_consumer_keeps_range_and_hash_rejections() {
    content::range_and_hash_rejections().await;
}
