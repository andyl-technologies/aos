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
    fail_manifest: AtomicBool,
    overwrite_existing: AtomicBool,
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
        if self.overwrite_existing.load(Ordering::SeqCst) {
            return TokioLocalFs.rename(from, to).await;
        }

        if to.file_name().is_some_and(|name| name == "MANIFEST")
            && self.fail_manifest.swap(false, Ordering::SeqCst)
        {
            return Err(std::io::Error::other(
                "injected manifest publication failure",
            ));
        }
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
        fail_manifest: AtomicBool::new(false),
        overwrite_existing: AtomicBool::new(false),
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

async fn content_fixture(hide_listing: bool) -> FileBucket<FaultFs, TokioClock, Validator> {
    let entropy = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = std::env::temp_dir().join(format!("terrane-bucket-publication-{suffix}"));
    let fs = FaultFs {
        fail_sync: AtomicBool::new(false),
        hide_listing,
        fail_manifest: AtomicBool::new(false),
        overwrite_existing: AtomicBool::new(false),
    };
    FileBucket::open(config(root), fs, TokioClock, Validator)
        .await
        .unwrap()
}

#[tokio::test]
async fn startup_refuses_a_binding_that_overwrites_create_once_keys() {
    let bucket = content_fixture(false).await;
    let root = bucket.root().to_path_buf();
    drop(bucket);

    let broken = FaultFs {
        fail_sync: AtomicBool::new(false),
        hide_listing: false,
        fail_manifest: AtomicBool::new(false),
        overwrite_existing: AtomicBool::new(true),
    };
    let result = FileBucket::open(config(root.clone()), broken, TokioClock, Validator).await;

    assert!(matches!(result, Err(error) if error.kind() == &StoreErrorKind::Unsupported));
    assert!(
        FileBucket::open(config(root.clone()), TokioLocalFs, TokioClock, Validator)
            .await
            .is_err()
    );
    tokio::fs::remove_dir_all(root).await.unwrap();
}

async fn put_bytes<F: LocalFs + BucketBinding>(
    bucket: &FileBucket<F, TokioClock, Validator>,
    bytes: &[u8],
) -> Result<terrane_core::identity::Identity, StoreFailure> {
    use crate::store::{ChunkPosition, ChunkUpload, ContentStore, ContentUpload};
    use terrane_core::identity::{IdentityKind, TERRANE_V1};

    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
    let mut encoded = vec![0];
    encoded.extend_from_slice(bytes);
    bucket
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: bytes.len(),
            position: ChunkPosition::Final,
            profile: &bucket.inner.config.chunk_profile,
        }))
        .await
}

#[tokio::test]
async fn stale_directory_listing_cannot_change_content_or_ref_results() {
    use crate::store::{ContentStore, IdentityPrefix};
    use terrane_core::identity::IdentityKind;

    let bucket = content_fixture(true).await;
    let identity = put_bytes(&bucket, b"content held without listing")
        .await
        .unwrap();
    let first = RefRecord::first([1; 32], 1, Locality::default());
    bucket
        .ref_cas("refs/heads/_/main", None, &first)
        .await
        .unwrap();

    assert!(
        bucket
            .inner
            .fs
            .read_dir(bucket.root())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        bucket.has(std::slice::from_ref(&identity)).await.unwrap(),
        vec![true]
    );
    assert_eq!(
        bucket.get(&identity, None).await.unwrap(),
        b"\0content held without listing"
    );
    assert_eq!(
        bucket.ref_get("refs/heads/_/main").await.unwrap(),
        Some(first)
    );
    let identities = bucket
        .list(&IdentityPrefix {
            kind: IdentityKind::Chunk,
            digest_prefix: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(identities, vec![identity]);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn partial_generation_is_unpublished_and_retry_uses_a_fresh_generation() {
    use crate::store::ContentStore;
    use terrane_core::identity::{IdentityKind, TERRANE_V1};

    let bucket = content_fixture(false).await;
    let first = put_bytes(&bucket, b"already published").await.unwrap();
    let old_generation = bucket
        .catalog()
        .await
        .unwrap()
        .capabilities
        .generation
        .unwrap();
    bucket.inner.fs.fail_manifest.store(true, Ordering::SeqCst);
    assert!(put_bytes(&bucket, b"unacknowledged body").await.is_err());
    let missing = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"unacknowledged body")
        .unwrap();
    assert_eq!(
        bucket.has(&[first.clone(), missing.clone()]).await.unwrap(),
        vec![true, false]
    );
    assert_eq!(
        bucket.catalog().await.unwrap().capabilities.generation,
        Some(old_generation)
    );

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.has(&[first, missing.clone()]).await.unwrap(),
        vec![true, false]
    );
    assert_eq!(
        put_bytes(&reopened, b"unacknowledged body").await.unwrap(),
        missing
    );
    assert!(
        reopened
            .catalog()
            .await
            .unwrap()
            .capabilities
            .generation
            .unwrap()
            > old_generation + 1
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}
