//! Exercises whole native reads and physical changes at local recipe boundaries.

#![allow(clippy::unwrap_used, reason = "fixture failures are test assertions")]

mod fixture;

use super::{NativeOrdinaryRead, OrdinaryReadOutcome, TestStage};
use crate::store::{LocalFs, TokioLocalFs};
use fixture::Directory;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn recipe(
    path: &std::path::Path,
    stage: TestStage,
    action: impl FnMut() + Send + 'static,
) -> NativeOrdinaryRead {
    let mut read = NativeOrdinaryRead::for_leaf(path);
    let mut action = action;
    read.observation = Some(Box::new(move |observed| {
        if observed == stage {
            action();
        }
    }));
    read
}

#[tokio::test]
async fn ordinary_recipe_reads_complete_public_and_hardlinked_files() {
    let directory = Directory::new();
    let path = directory.path.join("leaf");
    let bytes = vec![0x5a; 2 * 1024 * 1024 + 17];
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::hard_link(&path, directory.path.join("alias")).unwrap();
    let before = std::fs::symlink_metadata(&path).unwrap();

    let record = TokioLocalFs
        .read_ordinary_record(NativeOrdinaryRead::for_leaf(&path))
        .await
        .unwrap()
        .unwrap();

    match record.into_outcome() {
        OrdinaryReadOutcome::Present(actual, metadata) => {
            assert_eq!(actual, bytes);
            assert_eq!(
                (before.dev(), before.ino()),
                (metadata.dev(), metadata.ino())
            );
            assert_eq!(metadata.nlink(), 2);
            assert_eq!(metadata.mode() & 0o777, 0o644);
        }
        _ => panic!("ordinary public hardlinked body was rejected"),
    }
}

#[test]
fn ordinary_recipe_preserves_named_and_open_absence() {
    let directory = Directory::new();
    let path = directory.path.join("leaf");
    for missing in [&path, &directory.path.join("missing/leaf")] {
        assert!(matches!(
            NativeOrdinaryRead::for_leaf(missing)
                .execute()
                .unwrap()
                .into_outcome(),
            OrdinaryReadOutcome::Absent
        ));
    }
    std::fs::write(&path, b"body").unwrap();
    let removed = path.clone();
    let read = recipe(&path, TestStage::BeforeOpen, move || {
        std::fs::remove_file(&removed).unwrap()
    });

    assert!(matches!(
        read.execute().unwrap().into_outcome(),
        OrdinaryReadOutcome::Absent
    ));
}

#[test]
fn ordinary_recipe_rejects_symlink_directory_and_fifo_without_reading() {
    let directory = Directory::new();
    let target = directory.path.join("target");
    std::fs::write(&target, b"body must not be read").unwrap();
    let link = directory.path.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let folder = directory.path.join("folder");
    std::fs::create_dir(&folder).unwrap();
    let fifo = directory.path.join("fifo");
    fixture::fifo(&fifo);

    for path in [link, folder, fifo] {
        let read = recipe(&path, TestStage::BeforeOpen, || {
            panic!("nonregular named leaf reached open")
        });
        assert!(matches!(
            read.execute().unwrap().into_outcome(),
            OrdinaryReadOutcome::InvalidLayout
        ));
    }

    let path = directory.path.join("swapped");
    std::fs::write(&path, b"initial regular body").unwrap();
    let swapped = path.clone();
    let target = target.clone();
    let mut read = NativeOrdinaryRead::for_leaf(&path);
    read.observation = Some(Box::new(move |stage| match stage {
        TestStage::BeforeOpen => {
            std::fs::remove_file(&swapped).unwrap();
            std::os::unix::fs::symlink(&target, &swapped).unwrap();
        }
        TestStage::BeforeBody => panic!("O_NOFOLLOW must refuse the swapped symlink before body"),
        _ => {}
    }));
    assert_eq!(
        read.execute().err().unwrap().raw_os_error(),
        Some(libc::ELOOP)
    );
}

#[test]
fn ordinary_recipe_preserves_body_error_and_after_read_disappearance() {
    let directory = Directory::new();
    let path = directory.path.join("leaf");
    std::fs::write(&path, b"body").unwrap();
    let changed = path.clone();
    let descriptor_nonregular = recipe(&path, TestStage::BeforeOpen, move || {
        std::fs::remove_file(&changed).unwrap();
        fixture::fifo(&changed);
    });
    assert_eq!(
        descriptor_nonregular.execute().err().unwrap().kind(),
        std::io::ErrorKind::InvalidInput
    );

    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"body").unwrap();
    let removed = path.clone();
    let disappeared = recipe(&path, TestStage::AfterBody, move || {
        std::fs::remove_file(&removed).unwrap()
    });
    assert_eq!(
        disappeared.execute().err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    // /proc exposes a regular named descriptor whose complete read fails.
    // This is a real kernel read error, independent of an injected return value.
    let proc = std::path::Path::new("/proc/self/mem");
    assert!(std::fs::symlink_metadata(proc).unwrap().is_file());
    let mut descriptor = std::fs::File::open(proc).unwrap();
    assert!(descriptor.metadata().unwrap().is_file());
    let mut bytes = Vec::new();
    let actual_body_error = std::io::Read::read_to_end(&mut descriptor, &mut bytes).unwrap_err();
    assert_eq!(actual_body_error.raw_os_error(), Some(libc::EIO));
    let error = NativeOrdinaryRead::for_leaf(proc).execute().err().unwrap();
    assert_eq!(error.raw_os_error(), actual_body_error.raw_os_error());
}

#[test]
fn ordinary_recipe_rejects_same_bytes_named_inode_replacement() {
    let directory = Directory::new();
    let path = directory.path.join("leaf");
    let replacement = directory.path.join("replacement");
    std::fs::write(&path, b"same bytes").unwrap();
    std::fs::write(&replacement, b"same bytes").unwrap();
    assert_ne!(
        std::fs::metadata(&path).unwrap().ino(),
        std::fs::metadata(&replacement).unwrap().ino()
    );
    let destination = path.clone();
    let read = recipe(&path, TestStage::AfterBody, move || {
        std::fs::rename(&replacement, &destination).unwrap()
    });

    assert!(matches!(
        read.execute().unwrap().into_outcome(),
        OrdinaryReadOutcome::InvalidLayout
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"same bytes");

    for kind in ["symlink", "directory"] {
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"same bytes").unwrap();
        let changed = path.clone();
        let read = recipe(&path, TestStage::AfterBody, move || {
            std::fs::remove_file(&changed).unwrap();
            if kind == "symlink" {
                std::os::unix::fs::symlink("absent-target", &changed).unwrap();
            } else {
                std::fs::create_dir(&changed).unwrap();
            }
        });
        assert!(matches!(
            read.execute().unwrap().into_outcome(),
            OrdinaryReadOutcome::InvalidLayout
        ));
        if kind == "directory" {
            std::fs::remove_dir(&path).unwrap();
            std::fs::write(&path, b"same bytes").unwrap();
        }
    }
}

#[tokio::test]
async fn ordinary_recipe_cancellation_delivers_no_result_or_authority() {
    let directory = Directory::new();
    let path = directory.path.join("leaf");
    std::fs::write(&path, b"read data").unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let mut finished_tx = Some(finished_tx);
    let mut entered_tx = Some(entered_tx);
    let mut read = NativeOrdinaryRead::for_leaf(&path);
    read.observation = Some(Box::new(move |stage| {
        if stage == TestStage::BeforeBody {
            entered_tx.take().unwrap().send(()).unwrap();
            release_rx.recv().unwrap();
        }
        if stage == TestStage::Finished {
            finished_tx.take().unwrap().send(()).unwrap();
        }
    }));
    let awaiter = tokio::spawn(async move {
        let result = TokioLocalFs.read_ordinary_record(read).await;
        let _ = done_tx.send(result.is_ok());
    });
    entered_rx.await.unwrap();

    awaiter.abort();
    assert!(awaiter.await.unwrap_err().is_cancelled());
    release_tx.send(()).unwrap();
    assert!(done_rx.await.is_err());
    finished_rx.await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"read data");
}
