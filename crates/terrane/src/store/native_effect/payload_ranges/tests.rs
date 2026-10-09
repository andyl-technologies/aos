//! Exercises genuine original-descriptor ranges and native worker lifetimes.

#![allow(clippy::unwrap_used, reason = "Fixture failures are test assertions")]

use super::*;
use crate::store::TokioLocalFs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc,
};

struct Fixture {
    root: PathBuf,
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "terrane-payload-ranges-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("data.pack");
        std::fs::write(&path, b"header--requested-body--unrelated-body--footer").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self { root, path }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Cleanup does not replace any assertion about the original descriptor.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn original_ranges_read_exact_bytes_and_revalidate_without_whole_body() {
    let fixture = Fixture::new();
    let mut capture = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let range = ByteRange {
        start: 8,
        length: 14,
    };

    let bytes = capture.read_range(&TokioLocalFs, range).await.unwrap();
    assert_eq!(bytes, b"requested-body");
    let retained = capture.finish();
    assert_eq!(retained.ranges.len(), 1);
    assert_eq!(retained.ranges[0].range, range);
    assert_eq!(retained.ranges[0].bytes, b"requested-body");
    assert!(retained.length > range.length);
    let closing = NativePayloadRangeRead::new(Recipe::Check(retained.clone()));
    assert_eq!(
        closing
            .closing_data_ranges_for_test()
            .unwrap()
            .collect::<Vec<_>>(),
        vec![(fixture.path.as_path(), range)]
    );
    retained.revalidate(&TokioLocalFs).await.unwrap();
}

#[tokio::test]
async fn zero_range_at_original_end_is_checked_and_overflow_refuses() {
    let fixture = Fixture::new();
    let mut capture = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let range = ByteRange {
        start: capture.len(),
        length: 0,
    };
    assert!(
        capture
            .read_range(&TokioLocalFs, range)
            .await
            .unwrap()
            .is_empty()
    );

    for range in [
        ByteRange {
            start: capture.len(),
            length: 1,
        },
        ByteRange {
            start: u64::MAX,
            length: 1,
        },
        ByteRange {
            start: capture.len() + 1,
            length: 0,
        },
    ] {
        let error = capture
            .read_range(&TokioLocalFs, range)
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Invalid(InvalidReason::Range(range))
        );
    }
    assert_eq!(capture.retained.ranges.len(), 1);
    capture.finish().revalidate(&TokioLocalFs).await.unwrap();
}

#[tokio::test]
async fn equal_bytes_replaced_leaf_cannot_rebind_original_descriptor() {
    let fixture = Fixture::new();
    let mut capture = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let original_inode = std::fs::metadata(&fixture.path).unwrap().ino();
    let bytes = std::fs::read(&fixture.path).unwrap();
    std::fs::rename(&fixture.path, fixture.root.join("old.pack")).unwrap();
    std::fs::write(&fixture.path, &bytes).unwrap();
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read(&fixture.path).unwrap(), bytes);
    assert_ne!(
        std::fs::metadata(&fixture.path).unwrap().ino(),
        original_inode
    );

    assert!(
        capture
            .read_range(
                &TokioLocalFs,
                ByteRange {
                    start: 8,
                    length: 14
                }
            )
            .await
            .is_err()
    );
    assert!(capture.finish().revalidate(&TokioLocalFs).await.is_err());
}

#[tokio::test]
async fn replaced_original_ancestor_refuses_before_bounded_read() {
    let fixture = Fixture::new();
    let mut capture = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let old_inode = std::fs::metadata(&fixture.root).unwrap().ino();
    let bytes = std::fs::read(&fixture.path).unwrap();
    let moved = fixture.root.with_extension("original");
    std::fs::rename(&fixture.root, &moved).unwrap();
    std::fs::create_dir(&fixture.root).unwrap();
    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&fixture.path, bytes).unwrap();
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_ne!(std::fs::metadata(&fixture.root).unwrap().ino(), old_inode);

    assert!(
        capture
            .read_range(
                &TokioLocalFs,
                ByteRange {
                    start: 8,
                    length: 14
                }
            )
            .await
            .is_err()
    );
    assert!(capture.finish().revalidate(&TokioLocalFs).await.is_err());
    std::fs::remove_dir_all(moved).unwrap();
}

#[tokio::test]
async fn ordinary_capture_rejects_symlinks_and_nondirectory_ancestors() {
    let fixture = Fixture::new();
    let saved = fixture.root.join("saved");
    std::fs::rename(&fixture.path, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &fixture.path).unwrap();
    assert!(
        PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
            .await
            .is_err()
    );

    std::fs::remove_file(&fixture.path).unwrap();
    std::fs::create_dir(&fixture.path).unwrap();
    assert!(
        PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
            .await
            .is_err()
    );
    assert!(
        PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &saved.join("child.pack"))
            .await
            .is_err()
    );

    let alias = fixture.root.join("directory-alias");
    std::os::unix::fs::symlink(&fixture.root, &alias).unwrap();
    assert!(
        PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &alias.join("saved"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn in_place_changes_refuse_original_range_and_final_closure() {
    let fixture = Fixture::new();
    let mut capture = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    capture
        .read_range(
            &TokioLocalFs,
            ByteRange {
                start: 8,
                length: 14,
            },
        )
        .await
        .unwrap();
    let mut bytes = std::fs::read(&fixture.path).unwrap();
    bytes[8] ^= 1;
    std::fs::write(&fixture.path, bytes).unwrap();

    assert!(
        capture
            .read_range(
                &TokioLocalFs,
                ByteRange {
                    start: 8,
                    length: 14
                }
            )
            .await
            .is_err()
    );
    assert!(capture.finish().revalidate(&TokioLocalFs).await.is_err());
}

#[tokio::test]
async fn cancelled_waiter_retains_descriptor_until_actual_worker_finishes() {
    let fixture = Fixture::new();
    let capture = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let weak = Arc::downgrade(&capture.retained.original);
    let mut request = NativePayloadRangeRead::new(Recipe::Read {
        original: Arc::clone(&capture.retained.original),
        range: ByteRange {
            start: 8,
            length: 14,
        },
    });
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    request.before_read = Some(Box::new(move || {
        entered_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
    }));
    drop(capture);
    let waiter = tokio::spawn(async move { TokioLocalFs.read_payload_ranges(request).await });
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .unwrap();

    waiter.abort();
    assert!(matches!(waiter.await, Err(error) if error.is_cancelled()));
    assert!(weak.upgrade().is_some());
    resume_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn ordinary_ranges_preserve_public_hardlinks_without_protected_authority() {
    let fixture = Fixture::new();
    std::fs::hard_link(&fixture.path, fixture.root.join("public-alias")).unwrap();
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let mut capture = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();

    assert_eq!(capture.metadata().nlink(), 2);
    assert_eq!(capture.metadata().mode() & 0o777, 0o666);

    assert_eq!(
        capture
            .read_range(
                &TokioLocalFs,
                ByteRange {
                    start: 8,
                    length: 14
                }
            )
            .await
            .unwrap(),
        b"requested-body"
    );
    let retained = capture.finish();
    retained.revalidate(&TokioLocalFs).await.unwrap();
}
