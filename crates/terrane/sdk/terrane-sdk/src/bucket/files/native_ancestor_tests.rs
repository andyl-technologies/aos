//! Checks original ancestor ordering and later replacement on the real native lane.

#![allow(
    clippy::unwrap_used,
    reason = "Physical fixture failures are assertions"
)]

use crate::bucket::publication::receipts::RecordRead;
use crate::store::native_publication_effects::PayloadReadCapture;
use crate::store::{LocalFs, NativeOrdinaryRead, OrdinaryReadOutcome, TokioLocalFs};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;

struct Directory(PathBuf);

impl Directory {
    async fn new() -> Self {
        let random = TokioLocalFs.random_bytes(16).await.unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("terrane-captured-parents-{suffix}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }

    fn owner(&self) -> u32 {
        std::fs::symlink_metadata(&self.0).unwrap().uid()
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn native_ancestor_capture_refuses_unsafe_parent_before_missing_descendant() {
    let directory = Directory::new().await;
    let parent = directory.0.join("unsafe");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let path = parent.join("missing/leaf");

    let error = TokioLocalFs
        .read_ordinary_record(NativeOrdinaryRead::for_payload_ancestors(
            &path,
            directory.owner(),
        ))
        .await
        .err()
        .unwrap();

    // Descending first would report NotFound, hiding the original unsafe fence.
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(error.to_string(), "unsafe native physical fence");
}

#[tokio::test]
async fn native_ancestor_capture_keeps_original_parent_after_same_leaf_moves() {
    let directory = Directory::new().await;
    let parent = directory.0.join("parent");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    let path = parent.join("leaf");
    std::fs::write(&path, b"original physical payload").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let capture = PayloadReadCapture::capture(&TokioLocalFs, &path, directory.owner())
        .await
        .unwrap();
    let record = TokioLocalFs
        .read_ordinary_record(NativeOrdinaryRead::for_leaf(&path))
        .await
        .unwrap()
        .unwrap();
    let OrdinaryReadOutcome::Present(bytes, metadata) = record.into_outcome() else {
        panic!("actual original leaf was not read");
    };
    let original = (metadata.dev(), metadata.ino(), metadata.nlink());
    let observed = RecordRead::observed(path.clone(), Some(bytes), Some(metadata));
    let retained = capture.finish(&observed).unwrap();
    retained.revalidate(&TokioLocalFs).await.unwrap();

    let old = directory.0.join("old-parent");
    std::fs::rename(&parent, &old).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    std::fs::rename(old.join("leaf"), &path).unwrap();
    let moved = std::fs::symlink_metadata(&path).unwrap();

    assert_eq!((moved.dev(), moved.ino(), moved.nlink()), original);
    assert_eq!(std::fs::read(&path).unwrap(), b"original physical payload");
    assert!(retained.revalidate(&TokioLocalFs).await.is_err());
}
