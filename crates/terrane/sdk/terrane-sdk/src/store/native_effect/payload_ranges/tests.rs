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
async fn closing_batch_checks_every_original_and_never_rebinds_a_changed_suffix() {
    let fixture = Fixture::new();
    let second_path = fixture.root.join("second.pack");
    std::fs::copy(&fixture.path, &second_path).unwrap();

    let range = ByteRange {
        start: 8,
        length: 14,
    };
    let mut first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let mut second = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &second_path)
        .await
        .unwrap();
    assert_eq!(
        first.read_range(&TokioLocalFs, range).await.unwrap(),
        b"requested-body"
    );
    assert_eq!(
        second.read_range(&TokioLocalFs, range).await.unwrap(),
        b"requested-body"
    );
    let first = Arc::new(first.finish());
    let second = Arc::new(second.finish());
    let originals = vec![Arc::clone(&first), Arc::clone(&second)];
    RetainedPayloadRanges::revalidate_all(&TokioLocalFs, originals.clone())
        .await
        .unwrap();

    // The prefix remains valid. A changed later original must refuse the whole
    // request, even if a fresh capture can now verify its current body.
    std::fs::write(
        &second_path,
        b"header--changed---body--unrelated-body--footer",
    )
    .unwrap();
    first.revalidate(&TokioLocalFs).await.unwrap();
    assert!(
        RetainedPayloadRanges::revalidate_all(&TokioLocalFs, originals.clone())
            .await
            .is_err()
    );
    let mut fresh = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &second_path)
        .await
        .unwrap();
    assert_eq!(
        fresh.read_range(&TokioLocalFs, range).await.unwrap(),
        b"changed---body"
    );
    RetainedPayloadRanges::revalidate_all(
        &TokioLocalFs,
        vec![Arc::clone(&first), Arc::new(fresh.finish())],
    )
    .await
    .unwrap();
    assert!(
        RetainedPayloadRanges::revalidate_all(&TokioLocalFs, originals)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn repeated_leaf_captures_share_only_handles_and_release_them() {
    let fixture = Fixture::new();
    let mut first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    first
        .read_range(
            &TokioLocalFs,
            ByteRange {
                start: 8,
                length: 14,
            },
        )
        .await
        .unwrap();
    let handle = Arc::downgrade(&first.retained.original.file);
    let mut captures = Vec::new();
    for _ in 0..64 {
        let capture = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &first.retained.original.file,
            &capture.retained.original.file,
        ));
        assert!(!Arc::ptr_eq(
            &first.retained.original,
            &capture.retained.original,
        ));
        assert!(capture.retained.ranges.is_empty());
        captures.push(capture);
    }

    assert_eq!(first.retained.ranges.len(), 1);
    drop(first);
    assert!(handle.upgrade().is_some());
    let mut last = captures.pop().unwrap();
    assert_eq!(
        last.read_range(
            &TokioLocalFs,
            ByteRange {
                start: 0,
                length: 8,
            },
        )
        .await
        .unwrap(),
        b"header--",
    );
    assert!(
        captures
            .iter()
            .all(|capture| capture.retained.ranges.is_empty())
    );
    last.finish().revalidate(&TokioLocalFs).await.unwrap();
    drop(captures);
    assert!(handle.upgrade().is_none());
}

#[tokio::test]
async fn equal_bytes_replacement_keeps_shared_leaf_handles_distinct() {
    let fixture = Fixture::new();
    let first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let bytes = std::fs::read(&fixture.path).unwrap();
    std::fs::rename(&fixture.path, fixture.root.join("old.pack")).unwrap();
    std::fs::write(&fixture.path, &bytes).unwrap();
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut second = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(
        &first.retained.original.file,
        &second.retained.original.file,
    ));
    assert_ne!(first.metadata().ino(), second.metadata().ino());
    assert_eq!(
        second
            .read_range(
                &TokioLocalFs,
                ByteRange {
                    start: 0,
                    length: bytes.len() as u64,
                },
            )
            .await
            .unwrap(),
        bytes,
    );
    assert!(first.finish().revalidate(&TokioLocalFs).await.is_err());
    second.finish().revalidate(&TokioLocalFs).await.unwrap();
}

#[tokio::test]
async fn fresh_capture_after_same_inode_mutation_keeps_observations_independent() {
    let fixture = Fixture::new();
    let first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    std::fs::write(&fixture.path, b"mutated").unwrap();

    let mut second = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    assert_eq!(first.metadata().ino(), second.metadata().ino());
    assert!(Arc::ptr_eq(
        &first.retained.original.file,
        &second.retained.original.file,
    ));
    assert_ne!(first.len(), second.len());
    assert_eq!(
        second
            .read_range(
                &TokioLocalFs,
                ByteRange {
                    start: 0,
                    length: 7,
                },
            )
            .await
            .unwrap(),
        b"mutated",
    );
    assert!(first.finish().revalidate(&TokioLocalFs).await.is_err());
    second.finish().revalidate(&TokioLocalFs).await.unwrap();
}

#[tokio::test]
async fn changed_leaf_stamp_keeps_handle_sharing_independent() {
    for change in ["mode", "links"] {
        let fixture = Fixture::new();
        let first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
            .await
            .unwrap();
        match change {
            "mode" => {
                std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
            "links" => {
                std::fs::hard_link(&fixture.path, fixture.root.join("alias.pack")).unwrap();
            }
            _ => unreachable!(),
        }

        let second = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
            .await
            .unwrap();
        assert_eq!(first.metadata().ino(), second.metadata().ino(), "{change}");
        assert!(
            !Arc::ptr_eq(
                &first.retained.original.file,
                &second.retained.original.file
            ),
            "{change}",
        );
        assert!(
            first.finish().revalidate(&TokioLocalFs).await.is_err(),
            "{change}",
        );
        second.finish().revalidate(&TokioLocalFs).await.unwrap();
    }
}

#[tokio::test]
async fn shared_leaf_handle_does_not_bypass_fresh_open_failure() {
    let fixture = Fixture::new();
    let first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let path = fixture.path.clone();
    let removed = fixture.root.join("old.pack");
    let mut request = NativePayloadRangeRead::new(Recipe::Capture {
        path: fixture.path.clone(),
    });
    request.before_leaf_open = Some(Box::new(move || {
        std::fs::rename(&path, &removed).unwrap();
        std::os::unix::fs::symlink(&removed, &path).unwrap();
    }));

    // The race follows the named regular-file observation. O_NOFOLLOW must
    // still perform the real open, even while a previous handle is live.
    let error = request.execute().err().unwrap();
    assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
    assert!(first.finish().revalidate(&TokioLocalFs).await.is_err());
}

#[tokio::test]
async fn cancelled_shared_leaf_worker_retains_handle_until_completion() {
    let fixture = Fixture::new();
    let first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let second = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(
        &first.retained.original.file,
        &second.retained.original.file,
    ));
    let handle = Arc::downgrade(&first.retained.original.file);
    let mut request = NativePayloadRangeRead::new(Recipe::Read {
        original: Arc::clone(&second.retained.original),
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
    drop(first);
    drop(second);
    let waiter = tokio::spawn(async move { TokioLocalFs.read_payload_ranges(request).await });
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .unwrap();

    waiter.abort();
    assert!(matches!(waiter.await, Err(error) if error.is_cancelled()));
    assert!(handle.upgrade().is_some());
    resume_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while handle.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(handle.upgrade().is_none());
}

#[tokio::test]
async fn distinct_leaves_share_original_ancestors_without_retaining_them_globally() {
    let fixture = Fixture::new();
    let second_path = fixture.root.join("second.pack");
    std::fs::write(&second_path, b"independent leaf").unwrap();
    let first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let second = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &second_path)
        .await
        .unwrap();

    for (first, second) in first
        .retained
        .original
        .directories
        .iter()
        .zip(&second.retained.original.directories)
    {
        assert!(Arc::ptr_eq(first, second));
    }
    assert_ne!(first.metadata().ino(), second.metadata().ino());
    let ancestor = Arc::downgrade(first.retained.original.directories.last().unwrap());

    drop(first);
    assert!(ancestor.upgrade().is_some());
    second.finish().revalidate(&TokioLocalFs).await.unwrap();
    assert!(ancestor.upgrade().is_none());
}

#[tokio::test]
async fn replaced_ancestor_never_rebinds_original_shared_descriptor() {
    let fixture = Fixture::new();
    let first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    let removed = fixture.root.with_extension("original");
    std::fs::rename(&fixture.root, &removed).unwrap();
    std::fs::create_dir(&fixture.root).unwrap();
    std::fs::write(&fixture.path, b"replacement leaf").unwrap();

    let second = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(
        first.retained.original.directories.last().unwrap(),
        second.retained.original.directories.last().unwrap(),
    ));
    assert!(first.finish().revalidate(&TokioLocalFs).await.is_err());
    second.finish().revalidate(&TokioLocalFs).await.unwrap();

    std::fs::remove_dir_all(removed).unwrap();
}

#[tokio::test]
async fn changed_ancestor_mode_refuses_old_receipt_and_keeps_capture_independent() {
    let fixture = Fixture::new();
    let first = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o750)).unwrap();

    let second = PayloadRangeCapture::capture_ordinary(&TokioLocalFs, &fixture.path)
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(
        first.retained.original.directories.last().unwrap(),
        second.retained.original.directories.last().unwrap(),
    ));
    assert!(first.finish().revalidate(&TokioLocalFs).await.is_err());
    second.finish().revalidate(&TokioLocalFs).await.unwrap();
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
    let ancestor = Arc::downgrade(capture.retained.original.directories.last().unwrap());
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
    assert!(ancestor.upgrade().is_some());
    resume_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        // The original's strong count reaches zero before its fields finish
        // dropping. Wait for the worker's ancestor handles as well.
        while weak.upgrade().is_some() || ancestor.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(weak.upgrade().is_none());
    assert!(ancestor.upgrade().is_none());
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
