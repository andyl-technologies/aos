//! Compares native protected-record data with the complete scalar resolver.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::tests::{PreparedCas, Selected as _, Validator, config};
use crate::store::{
    ByteRange, NativeEffectFailure, NativeExclusion, NativeFsEffect, NativeProtectedRecord,
    StoreErrorKind, TokioClock, TokioFileLock, TokioLocalFs,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use terrane_core::refs::RefRecord;

#[derive(Default)]
struct ReadFs {
    native: AtomicBool,
    native_reads: AtomicUsize,
    scalar_reads: Mutex<Vec<PathBuf>>,
    effects: AtomicUsize,
    hook_error: AtomicBool,
    scalar_failure: AtomicBool,
    scalar_permission_change: AtomicBool,
    after_native_change: Mutex<Option<PathBuf>>,
}

#[async_trait::async_trait]
impl LocalFs for ReadFs {
    type Lock = TokioFileLock;

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, StoreFailure> {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(&self, held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.execute_retained_effect(effect).await
    }

    async fn read_protected_record(
        &self,
        recipe: NativeProtectedRead,
    ) -> Result<Option<NativeProtectedRecord>, StoreFailure> {
        if self.hook_error.load(Ordering::SeqCst) {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        if !self.native.load(Ordering::SeqCst) {
            return Ok(None);
        }

        self.native_reads.fetch_add(1, Ordering::SeqCst);
        let record = TokioLocalFs.read_protected_record(recipe).await?;
        let changed = self.after_native_change.lock().unwrap().take();
        if let Some(path) = changed {
            TokioLocalFs
                .set_permissions_and_sync(&path, std::fs::Permissions::from_mode(0o775))
                .await
                .map_err(files::io_failure)?;
        }
        Ok(record)
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.scalar_reads.lock().unwrap().push(path.to_owned());
        if self.scalar_failure.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected before-body read failure"));
        }
        let bytes = TokioLocalFs.read_nofollow(path).await?;
        if self.scalar_permission_change.swap(false, Ordering::SeqCst) {
            TokioLocalFs
                .set_permissions_and_sync(path, std::fs::Permissions::from_mode(0o644))
                .await?;
        }
        Ok(bytes)
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_all(path).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_new(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        TokioLocalFs.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }
}

impl ReadFs {
    fn reset(&self, native: bool) {
        self.native.store(native, Ordering::SeqCst);
        self.native_reads.store(0, Ordering::SeqCst);
        self.scalar_reads.lock().unwrap().clear();
        self.effects.store(0, Ordering::SeqCst);
    }
}

async fn fixture() -> (PathBuf, FileBucket<ReadFs, TokioClock, Validator>) {
    let nonce = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let parent = std::env::temp_dir().join(format!("terrane-control-read-{suffix}"));
    TokioLocalFs.create_dir_new(&parent).await.unwrap();
    let bucket = FileBucket::open(
        config(parent.join("bucket")),
        ReadFs::default(),
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    (parent, bucket)
}

fn assert_same_read(left: &RecordRead, right: &RecordRead) {
    assert_eq!(left.path(), right.path());
    assert_eq!(left.bytes(), right.bytes());
    let physical = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        )
    };
    assert_eq!(
        left.metadata().map(physical),
        right.metadata().map(physical)
    );
}

#[tokio::test]
async fn protected_native_consumer_preserves_complete_selected_record_transcript() {
    let (parent, bucket) = fixture().await;
    let name = "refs/heads/_/protected-read";
    let first = RefRecord::first([1; 32], 1, Default::default()).selected();
    bucket.prepared_cas(name, None, &first).await.unwrap();
    let second = RefRecord::advance(&first, [2; 32], 2).unwrap().selected();
    bucket
        .prepared_cas(name, Some(&first), &second)
        .await
        .unwrap();
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let adapter = holder.destination();
    let held = adapter.identity_proof();
    let control = Control::open(&bucket, false).await.unwrap();
    bucket.inner.fs.reset(false);
    let scalar = super::super::selection::resolve_held(&bucket, &control, &held)
        .await
        .unwrap();
    let scalar_paths = bucket.inner.fs.scalar_reads.lock().unwrap().clone();

    bucket.inner.fs.reset(true);
    let native = super::super::selection::resolve_held(&bucket, &control, &held)
        .await
        .unwrap();
    assert_eq!(scalar.state, native.state);
    assert_eq!(scalar.digest, native.digest);
    assert_eq!(scalar.logical, native.logical);
    assert_eq!(scalar.snapshot, native.snapshot);
    assert_eq!(scalar.reads.len(), native.reads.len());
    for (left, right) in scalar.reads.iter().zip(&native.reads) {
        assert_same_read(left, right);
    }

    let protected_reads = native
        .reads
        .iter()
        .filter(|read| read.path().starts_with(&control.path))
        .count();
    assert_eq!(
        bucket.inner.fs.native_reads.load(Ordering::SeqCst),
        protected_reads
    );
    let native_scalar_paths = bucket.inner.fs.scalar_reads.lock().unwrap().clone();
    assert_eq!(
        native_scalar_paths,
        scalar_paths
            .into_iter()
            .filter(|path| !path.starts_with(&control.path))
            .collect::<Vec<_>>()
    );
    assert!(native.reads.iter().any(|read| read.bytes().is_none()));
    let log = BucketKey::reflog_candidate(name, second.seq, second.candidate_id.as_ref().unwrap())
        .unwrap();
    assert!(
        native
            .reads
            .iter()
            .any(|read| read.path() == bucket.root().join(log.as_str()))
    );
    assert_eq!(bucket.inner.fs.effects.load(Ordering::SeqCst), 0);

    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn protected_native_consumer_preserves_missing_parent_and_leaf_absence() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let commits = control.path.join("publication/commits");
    let saved = control.path.join("saved-commits");

    for missing_parent in [false, true] {
        if missing_parent {
            tokio::fs::rename(&commits, &saved).await.unwrap();
        }
        bucket.inner.fs.reset(false);
        let scalar = control
            .read_record_observed(&bucket.inner.fs, "publication/commits/999")
            .await
            .unwrap();
        bucket.inner.fs.reset(true);
        let native = control
            .read_record_observed(&bucket.inner.fs, "publication/commits/999")
            .await
            .unwrap();

        assert_same_read(&scalar, &native);
        assert!(native.bytes().is_none());
        assert!(native.metadata().is_none());
        assert_eq!(bucket.inner.fs.native_reads.load(Ordering::SeqCst), 1);
        assert!(bucket.inner.fs.scalar_reads.lock().unwrap().is_empty());
        assert_eq!(bucket.inner.fs.effects.load(Ordering::SeqCst), 0);
        if missing_parent {
            tokio::fs::rename(&saved, &commits).await.unwrap();
        }
    }

    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn protected_native_consumer_rejects_unsafe_parent_before_later_missing_parent() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let publication = control.path.join("publication");
    let commits = publication.join("commits");
    let saved = control.path.join("saved-commits");
    tokio::fs::rename(&commits, &saved).await.unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&publication, std::fs::Permissions::from_mode(0o755))
        .await
        .unwrap();

    for native in [false, true] {
        bucket.inner.fs.reset(native);
        let error = control
            .read_record_observed(&bucket.inner.fs, "publication/commits/0")
            .await
            .err()
            .unwrap();
        assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
        assert!(bucket.inner.fs.scalar_reads.lock().unwrap().is_empty());
        assert_eq!(bucket.inner.fs.effects.load(Ordering::SeqCst), 0);
    }

    TokioLocalFs
        .set_permissions_and_sync(&publication, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    tokio::fs::rename(&saved, &commits).await.unwrap();
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn protected_native_consumer_checks_leaf_policy_before_body_or_fallback() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let path = control.path.join("backend-registration.cbor");
    let bytes = TokioLocalFs.read_nofollow(&path).await.unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&path, std::fs::Permissions::from_mode(0o644))
        .await
        .unwrap();
    bucket.inner.fs.scalar_failure.store(true, Ordering::SeqCst);

    for native in [false, true] {
        bucket.inner.fs.reset(native);
        let error = control
            .read_record_observed(&bucket.inner.fs, "backend-registration.cbor")
            .await
            .err()
            .unwrap();
        assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
        assert!(bucket.inner.fs.scalar_reads.lock().unwrap().is_empty());
        assert_eq!(bucket.inner.fs.effects.load(Ordering::SeqCst), 0);
    }
    assert_eq!(TokioLocalFs.read_nofollow(&path).await.unwrap(), bytes);
    TokioLocalFs
        .set_permissions_and_sync(&path, std::fs::Permissions::from_mode(0o600))
        .await
        .unwrap();

    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn protected_native_consumer_propagates_hook_errors_and_validates_keys_first() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    bucket.inner.fs.reset(true);
    bucket.inner.fs.hook_error.store(true, Ordering::SeqCst);

    let error = control
        .read_record_observed(&bucket.inner.fs, "publication/commits/00")
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    let error = control
        .read_record_observed(&bucket.inner.fs, "backend-registration.cbor")
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Capacity));
    assert!(bucket.inner.fs.scalar_reads.lock().unwrap().is_empty());
    assert_eq!(bucket.inner.fs.native_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.effects.load(Ordering::SeqCst), 0);

    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn protected_scalar_fallback_keeps_before_body_failure_and_after_body_mode_check() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let path = control.path.join("backend-registration.cbor");
    let bytes = TokioLocalFs.read_nofollow(&path).await.unwrap();
    bucket.inner.fs.reset(false);
    bucket.inner.fs.scalar_failure.store(true, Ordering::SeqCst);

    let error = control
        .read_record_observed(&bucket.inner.fs, "backend-registration.cbor")
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
    assert_eq!(
        *bucket.inner.fs.scalar_reads.lock().unwrap(),
        vec![path.clone()]
    );

    bucket.inner.fs.reset(false);
    bucket
        .inner
        .fs
        .scalar_failure
        .store(false, Ordering::SeqCst);
    bucket
        .inner
        .fs
        .scalar_permission_change
        .store(true, Ordering::SeqCst);
    let error = control
        .read_record_observed(&bucket.inner.fs, "backend-registration.cbor")
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(
        *bucket.inner.fs.scalar_reads.lock().unwrap(),
        vec![path.clone()]
    );
    assert_eq!(TokioLocalFs.read_nofollow(&path).await.unwrap(), bytes);
    assert_eq!(bucket.inner.fs.native_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.effects.load(Ordering::SeqCst), 0);
    TokioLocalFs
        .set_permissions_and_sync(&path, std::fs::Permissions::from_mode(0o600))
        .await
        .unwrap();

    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn protected_native_consumer_keeps_final_selected_resolver_physical_fence() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let adapter = holder.destination();
    let held = adapter.identity_proof();
    let control = Control::open(&bucket, false).await.unwrap();
    let registration = control.path.join("backend-registration.cbor");
    let bytes = TokioLocalFs.read_nofollow(&registration).await.unwrap();
    let permissions = TokioLocalFs
        .symlink_metadata(bucket.root())
        .await
        .unwrap()
        .permissions();
    bucket.inner.fs.reset(true);
    *bucket.inner.fs.after_native_change.lock().unwrap() = Some(bucket.root().to_owned());

    let error = super::super::selection::resolve_held(&bucket, &control, &held)
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert!(
        bucket
            .inner
            .fs
            .after_native_change
            .lock()
            .unwrap()
            .is_none()
    );
    assert!(bucket.inner.fs.native_reads.load(Ordering::SeqCst) > 1);
    assert_eq!(
        TokioLocalFs.read_nofollow(&registration).await.unwrap(),
        bytes
    );
    assert_eq!(bucket.inner.fs.effects.load(Ordering::SeqCst), 0);

    TokioLocalFs
        .set_permissions_and_sync(bucket.root(), permissions)
        .await
        .unwrap();
    let selected = super::super::selection::resolve_held(&bucket, &control, &held)
        .await
        .unwrap();
    assert_eq!(selected.state.revision, 0);
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}
