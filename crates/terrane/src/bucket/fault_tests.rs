//! Injects durable-operation failures into the native filesystem binding.

#![allow(clippy::unwrap_used)]

use super::tests::{Validator, config};
use super::*;
use crate::store::{ByteRange, RefStore, TokioClock, TokioLocalFs};
use std::sync::atomic::{AtomicBool, Ordering};
use terrane_core::refs::RefRecord;

struct FaultFs {
    fail_sync: AtomicBool,
    hide_listing: bool,
}

#[async_trait::async_trait]
impl LocalFs for FaultFs {
    type Lock = crate::store::TokioFileLock;
    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        if self.hide_listing {
            Ok(Vec::new())
        } else {
            TokioLocalFs.read_dir(path).await
        }
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        if self.fail_sync.swap(false, Ordering::SeqCst) {
            return Err(std::io::Error::other("injected file-sync failure"));
        }
        TokioLocalFs.sync_file(path).await
    }
}

#[tokio::test]
async fn unsynced_temporary_write_never_changes_visible_ref() {
    let entropy = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = std::env::temp_dir().join(format!("terrane-bucket-fault-{suffix}"));
    let fs = FaultFs {
        fail_sync: AtomicBool::new(false),
        hide_listing: false,
    };
    let bucket = FileBucket::open(config(root.clone()), fs, TokioClock, Validator)
        .await
        .unwrap();
    let first = RefRecord::first([1; 32], 1, Locality::default());
    bucket
        .ref_cas("refs/heads/_/main", None, &first)
        .await
        .unwrap();
    let second = first.advance([2; 32], 2).unwrap();

    bucket.inner.fs.fail_sync.store(true, Ordering::SeqCst);
    assert!(
        bucket
            .ref_cas("refs/heads/_/main", Some(&first), &second)
            .await
            .is_err()
    );
    assert_eq!(
        bucket.ref_get("refs/heads/_/main").await.unwrap(),
        Some(first.clone())
    );
    let reopened = FileBucket::open(config(root.clone()), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    assert_eq!(
        reopened.ref_get("refs/heads/_/main").await.unwrap(),
        Some(first)
    );
    tokio::fs::remove_dir_all(root).await.unwrap();
}
