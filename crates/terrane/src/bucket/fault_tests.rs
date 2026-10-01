//! Injects durable-operation failures into the native filesystem binding.

#![allow(clippy::unwrap_used)]

use super::tests::{PreparedCas, Selected, Validator, config};
use super::*;
use crate::store::{ByteRange, RefStore, TokioClock, TokioLocalFs};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use terrane_core::refs::RefRecord;

struct FaultFs {
    fail_sync: AtomicBool,
    hide_listing: bool,
    fail_manifest: AtomicBool,
    fail_ref_directory_sync: AtomicBool,
    overwrite_existing: AtomicBool,
    unavailable_read: Mutex<Option<PathBuf>>,
    failed_reads: AtomicUsize,
}

#[async_trait::async_trait]
impl LocalFs for FaultFs {
    type Lock = crate::store::TokioFileLock;

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, StoreFailure> {
        TokioLocalFs.initialize_publication(request).await
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        let unavailable = self.unavailable_read.lock().unwrap().as_deref() == Some(path);
        if unavailable {
            self.failed_reads.fetch_add(1, Ordering::SeqCst);
            return Err(std::io::Error::other(
                "injected dictionary backend read unavailable",
            ));
        }
        TokioLocalFs.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_new(path).await
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
        if path.ends_with("refs/heads/_")
            && self.fail_ref_directory_sync.swap(false, Ordering::SeqCst)
        {
            return Err(std::io::Error::other(
                "injected post-rename ref-directory sync failure",
            ));
        }
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
        fail_ref_directory_sync: AtomicBool::new(false),
        overwrite_existing: AtomicBool::new(false),
        unavailable_read: Mutex::new(None),
        failed_reads: AtomicUsize::new(0),
    };
    let bucket = FileBucket::open(config(root.clone()), fs, TokioClock, Validator)
        .await
        .unwrap();
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket
        .prepared_cas("refs/heads/_/main", None, &first)
        .await
        .unwrap();
    let second = first.advance([2; 32], 2).unwrap().selected();

    bucket
        .ref_log_append(
            "refs/heads/_/main",
            second.seq,
            &super::tests::log(second.clone(), Some(first.clone())),
        )
        .await
        .unwrap();
    bucket.inner.fs.fail_sync.store(true, Ordering::SeqCst);
    assert!(
        bucket
            .prepared_cas("refs/heads/_/main", Some(&first), &second)
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
        fail_ref_directory_sync: AtomicBool::new(false),
        overwrite_existing: AtomicBool::new(false),
        unavailable_read: Mutex::new(None),
        failed_reads: AtomicUsize::new(0),
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
        fail_ref_directory_sync: AtomicBool::new(false),
        overwrite_existing: AtomicBool::new(true),
        unavailable_read: Mutex::new(None),
        failed_reads: AtomicUsize::new(0),
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
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket
        .prepared_cas("refs/heads/_/main", None, &first)
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

#[tokio::test]
async fn failed_final_cas_sync_requires_authoritative_reread_after_possible_application() {
    let bucket = content_fixture(false).await;
    let name = "refs/heads/_/main";
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket.prepared_cas(name, None, &first).await.unwrap();
    let next = first.advance([2; 32], 2).unwrap().selected();
    bucket
        .ref_log_append(
            name,
            next.seq,
            &super::tests::log(next.clone(), Some(first.clone())),
        )
        .await
        .unwrap();

    bucket
        .inner
        .fs
        .fail_ref_directory_sync
        .store(true, Ordering::SeqCst);
    let failure = bucket.ref_cas(name, Some(&first), &next).await.unwrap_err();
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(bucket.ref_get(name).await.unwrap(), Some(next.clone()));
    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.ref_get(name).await.unwrap(), Some(next.clone()));
    assert_eq!(
        reopened.ref_log_read(name, 2).await.unwrap(),
        vec![super::tests::log(next.clone(), Some(first.clone()))]
    );
    assert_eq!(
        reopened.ref_cas(name, Some(&first), &next).await.unwrap(),
        crate::store::RefCasOutcome::Conflict(Some(Box::new(next)))
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn first_ref_inventory_is_durable_before_an_indeterminate_head_install() {
    let bucket = content_fixture(true).await;
    let name = "refs/heads/_/main";
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket
        .ref_log_append(name, 1, &super::tests::log(first.clone(), None))
        .await
        .unwrap();
    bucket
        .inner
        .fs
        .fail_ref_directory_sync
        .store(true, Ordering::SeqCst);
    assert_eq!(
        bucket.ref_cas(name, None, &first).await.unwrap_err().kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(bucket.ref_names().await.unwrap(), vec![name.to_string()]);
    assert_eq!(bucket.ref_get(name).await.unwrap(), Some(first.clone()));

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.ref_names().await.unwrap(), vec![name.to_string()]);
    assert_eq!(reopened.ref_get(name).await.unwrap(), Some(first));
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn dictionary_backend_unavailability_preserves_put_and_get_failure_kinds() {
    use super::content_tests::{chunk_identity, raw, upload};
    use crate::store::{ChunkPosition, ContentStore, InvalidReason};
    use std::error::Error as _;

    let bucket = content_fixture(false).await;
    let dictionary = vec![b'd'; 32768];
    let dictionary_id = chunk_identity(&dictionary);
    let profile = &bucket.inner.config.chunk_profile;
    bucket
        .put(upload(
            &raw(&dictionary),
            &dictionary_id,
            dictionary.len(),
            profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let plaintext = vec![b'd'; 65536];
    let identity = chunk_identity(&plaintext);
    let encoded =
        crate::codec::encode_chunk(&plaintext, profile.maximum(), 3, Some(&dictionary)).unwrap();
    assert_eq!(encoded[0], 2);
    bucket
        .put(upload(
            &encoded,
            &identity,
            plaintext.len(),
            profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();

    let guard = bucket.exclusive().await.unwrap();
    let catalog = bucket.catalog().await.unwrap();
    let hash = dictionary_id.terrane_v1_digest().unwrap();
    let dictionary_pack = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == &hash)
        .unwrap()
        .pack();
    drop(guard);
    let path = bucket.root().join(dictionary_pack.pack_key());
    let intact = tokio::fs::read(&path).await.unwrap();
    *bucket.inner.fs.unavailable_read.lock().unwrap() = Some(path.clone());

    // The offer is a dedup hit, but its dictionary must still be fetched and
    // checked independently. Retrieval follows the stored codec-two envelope.
    let put_error = bucket
        .put(upload(
            &encoded,
            &identity,
            plaintext.len(),
            profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap_err();
    let get_error = bucket.get(&identity, None).await.unwrap_err();
    assert_eq!(bucket.inner.fs.failed_reads.load(Ordering::SeqCst), 2);
    assert!(
        matches!(
            put_error.kind(),
            StoreErrorKind::Unavailable { retry_after: None }
        ),
        "put: {put_error}; get: {get_error}"
    );
    assert!(matches!(
        get_error.kind(),
        StoreErrorKind::Unavailable { retry_after: None }
    ));
    assert!(put_error.source().is_some());
    assert!(get_error.source().is_some());
    *bucket.inner.fs.unavailable_read.lock().unwrap() = None;
    assert_eq!(bucket.get(&identity, None).await.unwrap(), encoded);

    // Actual missing or corrupt dependency bytes remain content failures.
    tokio::fs::remove_file(&path).await.unwrap();
    assert!(matches!(
        bucket
            .put(upload(
                &encoded,
                &identity,
                plaintext.len(),
                profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "CDC-9" })
    ));
    assert!(matches!(
        bucket.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Corrupt(_)
    ));
    let mut damaged = intact.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    tokio::fs::write(&path, damaged).await.unwrap();
    assert!(matches!(
        bucket
            .put(upload(
                &encoded,
                &identity,
                plaintext.len(),
                profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "CDC-9" })
    ));
    assert!(matches!(
        bucket.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Corrupt(_)
    ));
    tokio::fs::write(&path, intact).await.unwrap();
    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.get(&identity, None).await.unwrap(), encoded);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}
