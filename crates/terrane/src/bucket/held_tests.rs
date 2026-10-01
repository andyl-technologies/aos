//! Exercises single and paired exclusions with independent handles and cancellation.

#![allow(clippy::unwrap_used, reason = "Fixture failures intentionally panic.")]

use super::content_tests::{chunk_identity, raw, upload};
use super::held::{HeldBuckets, SingleHeld};
use super::tests::{Selected, Validator, config, fixture, log};
use super::*;
use crate::store::{
    ChunkPosition, ContentStore, RefCasOutcome, RefStore, TokioClock, TokioLocalFs,
};
use std::sync::Arc;
use std::time::Duration;
use terrane_core::identity::Identity;
use terrane_core::refs::RefRecord;

// Durable writes and native lock requests share filesystem and blocking-pool
// capacity with the full package suite. Bound completion separately from the
// short assertion that an observed writer remains excluded while a guard lives.
const DURABLE_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

async fn put_bytes(store: &impl ContentStore, bytes: &[u8]) -> Result<Identity, StoreFailure> {
    let encoded = raw(bytes);
    let identity = chunk_identity(bytes);
    let profile = ChunkProfile::cdc_1m([0; 32]);
    store
        .put(upload(
            &encoded,
            &identity,
            bytes.len(),
            &profile,
            ChunkPosition::Final,
        ))
        .await
}

#[tokio::test]
async fn held_buckets_source_readonly_destination_durable_and_independent_reopen() {
    let source = fixture().await;
    let destination = fixture().await;
    let pair = HeldBuckets::acquire(&source, &destination).await.unwrap();
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    let source_adapter = pair.source();
    assert!(matches!(
        put_bytes(&source_adapter, b"source")
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::ReadOnly
    ));
    assert!(matches!(
        source_adapter
            .ref_log_append("refs/heads/_/main", 1, &log(first.clone(), None))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::ReadOnly
    ));
    assert!(matches!(
        source_adapter
            .ref_cas("refs/heads/_/main", None, &first)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::ReadOnly
    ));
    let adapter = pair.destination();
    let identity = put_bytes(&adapter, b"destination").await.unwrap();
    assert_eq!(
        adapter.get(&identity, None).await.unwrap(),
        raw(b"destination")
    );
    adapter
        .ref_log_append("refs/heads/_/main", 1, &log(first.clone(), None))
        .await
        .unwrap();
    assert!(matches!(
        adapter
            .ref_cas("refs/heads/_/main", None, &first)
            .await
            .unwrap(),
        RefCasOutcome::Applied
    ));
    assert_eq!(
        adapter
            .ref_log_read("refs/heads/_/main", 1)
            .await
            .unwrap()
            .len(),
        1
    );
    drop(source_adapter);
    drop(adapter);
    drop(pair);
    let reopened = FileBucket::open(
        config(destination.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.get(&identity, None).await.unwrap(),
        raw(b"destination")
    );
    assert_eq!(
        reopened.ref_get("refs/heads/_/main").await.unwrap(),
        Some(first)
    );
    tokio::fs::remove_dir_all(source.root()).await.unwrap();
    tokio::fs::remove_dir_all(destination.root()).await.unwrap();
}

#[tokio::test]
async fn held_buckets_inverse_transactions_finish_in_canonical_order() {
    let left = fixture().await;
    let right = fixture().await;
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let mut tasks = Vec::new();
    for (source, destination) in [(left.clone(), right.clone()), (right.clone(), left.clone())] {
        let source = FileBucket::open(
            config(source.root().to_owned()),
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await
        .unwrap();
        let destination = FileBucket::open(
            config(destination.root().to_owned()),
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await
        .unwrap();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let pair = HeldBuckets::acquire(&source, &destination).await.unwrap();
            put_bytes(&pair.destination(), b"inverse").await.unwrap();
        }));
    }
    barrier.wait().await;
    for task in tasks {
        tokio::time::timeout(DURABLE_OPERATION_TIMEOUT, task)
            .await
            .unwrap()
            .unwrap();
    }
    tokio::fs::remove_dir_all(left.root()).await.unwrap();
    tokio::fs::remove_dir_all(right.root()).await.unwrap();
}

#[tokio::test]
async fn held_buckets_reject_same_root_and_hardlinked_coordination_inode() {
    let left = fixture().await;
    let alias = FileBucket::open(
        config(left.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert!(HeldBuckets::acquire(&left, &alias).await.is_err());
    let right = fixture().await;
    let key = BucketKey::parse("CAPABILITIES").unwrap();
    let left_lock = left.root().join(key.lock_name());
    let right_lock = right.root().join(key.lock_name());
    // Deliberately construct a broken layout only while neither test bucket is held.
    tokio::fs::remove_file(&right_lock).await.unwrap();
    tokio::fs::hard_link(&left_lock, &right_lock).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), HeldBuckets::acquire(&left, &right))
            .await
            .unwrap()
            .is_err()
    );
    tokio::fs::remove_dir_all(left.root()).await.unwrap();
    tokio::fs::remove_dir_all(right.root()).await.unwrap();
}

#[tokio::test]
async fn held_buckets_cancellation_releases_both_namespace_guards() {
    let left = fixture().await;
    let right = fixture().await;
    let (ready, received) = tokio::sync::oneshot::channel();
    let task_left = left.clone();
    let task_right = right.clone();
    let task = tokio::spawn(async move {
        let _pair = HeldBuckets::acquire(&task_left, &task_right).await.unwrap();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    received.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    for bucket in [&left, &right] {
        tokio::time::timeout(
            DURABLE_OPERATION_TIMEOUT,
            put_bytes(bucket, b"after cancellation"),
        )
        .await
        .unwrap()
        .unwrap();
    }
    tokio::fs::remove_dir_all(left.root()).await.unwrap();
    tokio::fs::remove_dir_all(right.root()).await.unwrap();
}

#[tokio::test]
async fn registered_profile_uses_actual_existing_namespace_exclusion() {
    let bucket = fixture().await;
    let fs = ObservedFs::new();
    let configured = config(bucket.root().to_owned())
        .publication_control
        .unwrap();
    let root = bucket.root().to_owned();
    let held = SingleHeld::acquire(&bucket).await.unwrap();
    fs.arm();
    let reading_fs = fs.clone();
    let profile = tokio::spawn(async move {
        publication::registered_profile(&reading_fs, &root, &configured).await
    });

    tokio::time::timeout(DURABLE_OPERATION_TIMEOUT, fs.attempts.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert_eq!(fs.acquired.available_permits(), 0);
    assert!(!profile.is_finished());

    drop(held);
    let profile = tokio::time::timeout(DURABLE_OPERATION_TIMEOUT, profile)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(fs.acquired.available_permits(), 1);
    assert_eq!(profile, bucket.profile());
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(super::tests::control_path(bucket.root()))
        .await
        .unwrap();
}

#[derive(Clone)]
struct ObservedFs {
    attempts: Arc<tokio::sync::Semaphore>,
    acquired: Arc<tokio::sync::Semaphore>,
    observe: Arc<std::sync::atomic::AtomicBool>,
}

impl ObservedFs {
    fn new() -> Self {
        Self {
            attempts: Arc::new(tokio::sync::Semaphore::new(0)),
            acquired: Arc::new(tokio::sync::Semaphore::new(0)),
            observe: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    fn arm(&self) {
        self.observe
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl LocalFs for ObservedFs {
    type Lock = crate::store::TokioFileLock;

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        TokioLocalFs.execute_retained_effect(effect).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        let observed = self.observe.load(std::sync::atomic::Ordering::SeqCst);
        if observed {
            self.attempts.add_permits(1);
        }
        let guard = TokioLocalFs.lock_exclusive(path).await?;
        if observed {
            self.acquired.add_permits(1);
        }
        Ok(guard)
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        let observed = self.observe.load(std::sync::atomic::Ordering::SeqCst);
        if observed {
            self.attempts.add_permits(1);
        }
        let guard = TokioLocalFs.lock_existing_exclusive(path).await?;
        if observed {
            self.acquired.add_permits(1);
        }
        Ok(guard)
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_nofollow(path).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }

    async fn read_range(
        &self,
        path: &Path,
        range: crate::store::ByteRange,
    ) -> std::io::Result<Vec<u8>> {
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

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
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

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }
}

async fn observed_handle(
    bucket: &super::tests::Bucket,
    fs: ObservedFs,
) -> FileBucket<ObservedFs, TokioClock, Validator> {
    FileBucket::open(config(bucket.root().to_owned()), fs, TokioClock, Validator)
        .await
        .unwrap()
}

#[tokio::test]
async fn held_buckets_source_revision_cannot_change_before_destination_cas() {
    let source = fixture().await;
    let destination = fixture().await;
    let name = "refs/heads/_/main";
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    source
        .ref_log_append(name, 1, &log(first.clone(), None))
        .await
        .unwrap();
    source.ref_cas(name, None, &first).await.unwrap();
    let revoked = first.advance([2; 32], 2).unwrap().selected();
    source
        .ref_log_append(name, 2, &log(revoked.clone(), Some(first.clone())))
        .await
        .unwrap();
    let fs = ObservedFs::new();
    let independent = observed_handle(&source, fs.clone()).await;
    let pair = HeldBuckets::acquire(&source, &destination).await.unwrap();
    assert_eq!(
        pair.source().ref_get(name).await.unwrap(),
        Some(first.clone())
    );
    fs.arm();
    let task_first = first.clone();
    let task_revoked = revoked.clone();
    let task = tokio::spawn(async move {
        independent
            .ref_cas(name, Some(&task_first), &task_revoked)
            .await
            .unwrap()
    });
    fs.attempts.acquire().await.unwrap().forget();
    assert_eq!(fs.acquired.available_permits(), 0);
    assert_eq!(pair.source().ref_get(name).await.unwrap(), Some(first));
    let target = RefRecord::first([3; 32], 1, Locality::default()).selected();
    pair.destination()
        .ref_log_append(name, 1, &log(target.clone(), None))
        .await
        .unwrap();
    assert!(matches!(
        pair.destination()
            .ref_cas(name, None, &target)
            .await
            .unwrap(),
        RefCasOutcome::Applied
    ));
    assert_eq!(fs.acquired.available_permits(), 0);
    drop(pair);
    assert!(matches!(
        tokio::time::timeout(DURABLE_OPERATION_TIMEOUT, task)
            .await
            .unwrap()
            .unwrap(),
        RefCasOutcome::Applied
    ));
    assert_eq!(source.ref_get(name).await.unwrap(), Some(revoked));
    tokio::fs::remove_dir_all(source.root()).await.unwrap();
    tokio::fs::remove_dir_all(destination.root()).await.unwrap();
}

#[tokio::test]
async fn held_buckets_cancellation_while_waiting_second_releases_first() {
    use std::os::unix::fs::MetadataExt;
    let left = fixture().await;
    let right = fixture().await;
    let left_meta = TokioLocalFs.metadata(left.root()).await.unwrap();
    let right_meta = TokioLocalFs.metadata(right.root()).await.unwrap();
    let (low, high) = if (left_meta.dev(), left_meta.ino()) < (right_meta.dev(), right_meta.ino()) {
        (&left, &right)
    } else {
        (&right, &left)
    };
    let low_fs = ObservedFs::new();
    let high_fs = ObservedFs::new();
    let low_handle = observed_handle(low, low_fs.clone()).await;
    let high_handle = observed_handle(high, high_fs.clone()).await;
    let held_high = high.exclusive().await.unwrap();
    low_fs.arm();
    high_fs.arm();
    let task = tokio::spawn(async move {
        let _pair = HeldBuckets::acquire(&low_handle, &high_handle)
            .await
            .unwrap();
    });
    high_fs.attempts.acquire().await.unwrap().forget();
    assert_eq!(low_fs.acquired.available_permits(), 1);
    assert_eq!(high_fs.acquired.available_permits(), 0);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let released_low = tokio::time::timeout(DURABLE_OPERATION_TIMEOUT, low.exclusive())
        .await
        .unwrap()
        .unwrap();
    drop(released_low);
    put_bytes(low, b"released first").await.unwrap();
    drop(held_high);
    // A native blocking lock request may finish after its cancelled async waiter.
    // Its abandoned result releases that guard instead of leaking ownership.
    let released_high = tokio::time::timeout(DURABLE_OPERATION_TIMEOUT, high.exclusive())
        .await
        .unwrap()
        .unwrap();
    drop(released_high);
    put_bytes(high, b"released second").await.unwrap();
    tokio::fs::remove_dir_all(left.root()).await.unwrap();
    tokio::fs::remove_dir_all(right.root()).await.unwrap();
}

#[tokio::test]
async fn held_buckets_ordinary_invalid_refs_reject_before_locking() {
    let bucket = fixture().await;
    let fs = ObservedFs::new();
    let independent = observed_handle(&bucket, fs.clone()).await;
    fs.arm();
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    assert!(
        independent
            .ref_cas("unregistered", None, &first)
            .await
            .is_err()
    );
    assert!(
        independent
            .ref_log_append("refs/heads/_/main", 2, &log(first, None))
            .await
            .is_err()
    );
    assert!(
        independent
            .ref_log_read("refs/tags/_/release", 1)
            .await
            .is_err()
    );
    assert_eq!(fs.attempts.available_permits(), 0);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn held_buckets_identity_matches_independently_opened_physical_namespace() {
    use std::os::unix::fs::MetadataExt;
    let source = fixture().await;
    let destination = fixture().await;
    let independent_source = FileBucket::open(
        config(source.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let independent_destination = FileBucket::open(
        config(destination.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let pair = HeldBuckets::acquire(&independent_source, &independent_destination)
        .await
        .unwrap();
    let source_adapter = pair.source();
    let destination_adapter = pair.destination();
    let source_proof = source_adapter.identity_proof();
    let destination_proof = destination_adapter.identity_proof();
    assert!(!source_proof.writable());
    assert!(destination_proof.writable());
    assert_eq!(source_proof.root(), source.root());
    assert_eq!(destination_proof.root(), destination.root());

    let key = BucketKey::parse("CAPABILITIES").unwrap();
    for (bucket, actual) in [
        (&source, source_proof.physical_identity()),
        (&destination, destination_proof.physical_identity()),
    ] {
        let root = TokioLocalFs.symlink_metadata(bucket.root()).await.unwrap();
        let lock = TokioLocalFs
            .symlink_metadata(&bucket.root().join(key.lock_name()))
            .await
            .unwrap();
        assert_eq!(actual, ((root.dev(), root.ino()), (lock.dev(), lock.ino())));
    }
    assert_ne!(
        pair.source().physical_identity(),
        pair.destination().physical_identity()
    );
    drop(source_adapter);
    drop(destination_adapter);
    drop(pair);
    exercise_single_namespace(&independent_source, &source).await;
    tokio::fs::remove_dir_all(source.root()).await.unwrap();
    tokio::fs::remove_dir_all(destination.root()).await.unwrap();
}

/// Verifies the gate-selected path performs real single-namespace publication.
async fn exercise_single_namespace(
    holder_bucket: &FileBucket<TokioLocalFs, TokioClock, Validator>,
    independent: &FileBucket<TokioLocalFs, TokioClock, Validator>,
) {
    let observed_fs = ObservedFs::new();
    let writer_bucket = observed_handle(independent, observed_fs.clone()).await;
    let held = SingleHeld::acquire(holder_bucket).await.unwrap();
    let source = held.source();
    let destination = held.destination();
    assert_eq!(
        source.identity_proof().physical_identity(),
        destination.identity_proof().physical_identity()
    );
    assert!(!source.identity_proof().writable());
    assert!(destination.identity_proof().writable());
    assert_eq!(source.identity_proof().root(), independent.root());

    let name = "refs/heads/_/single";
    let record = RefRecord::first([7; 32], 1, Locality::default()).selected();
    assert_eq!(source.ref_get(name).await.unwrap(), None);
    assert!(matches!(
        source
            .ref_cas(name, None, &record)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::ReadOnly
    ));

    observed_fs.arm();
    let mut writer =
        tokio::spawn(async move { put_bytes(&writer_bucket, b"independent writer").await });
    tokio::time::timeout(DURABLE_OPERATION_TIMEOUT, observed_fs.attempts.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut writer)
            .await
            .is_err()
    );
    assert_eq!(observed_fs.acquired.available_permits(), 0);
    tokio::time::timeout(DURABLE_OPERATION_TIMEOUT, async {
        destination
            .ref_log_append(name, 1, &log(record.clone(), None))
            .await
            .unwrap();
        assert!(matches!(
            destination.ref_cas(name, None, &record).await.unwrap(),
            RefCasOutcome::Applied
        ));
        assert_eq!(source.ref_get(name).await.unwrap(), Some(record.clone()));
    })
    .await
    .unwrap();
    assert!(!writer.is_finished());
    drop(source);
    drop(destination);
    drop(held);
    tokio::time::timeout(DURABLE_OPERATION_TIMEOUT, writer)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let reopened = FileBucket::open(
        config(independent.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(reopened.ref_get(name).await.unwrap(), Some(record));
}

#[tokio::test]
async fn single_held_cancellation_releases_namespace_guard() {
    let bucket = fixture().await;
    let task_bucket = bucket.clone();
    let (ready, received) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _held = SingleHeld::acquire(&task_bucket).await.unwrap();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    received.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(
        DURABLE_OPERATION_TIMEOUT,
        put_bytes(&bucket, b"after cancellation"),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn single_held_refuses_legacy_before_coordination_effects() {
    use terrane_core::bucket::BucketCapabilities;

    let bucket = fixture().await;
    let capability_path = bucket.root().join("CAPABILITIES");
    let mut capabilities =
        BucketCapabilities::decode(&TokioLocalFs.read(&capability_path).await.unwrap()).unwrap();
    capabilities.layout_version = 1;
    capabilities.publication_protocol = None;
    capabilities.ref_names = None;
    let original = capabilities.encode().unwrap();
    tokio::fs::write(&capability_path, &original).await.unwrap();
    tokio::fs::remove_dir_all(super::tests::control_path(bucket.root()))
        .await
        .unwrap();
    tokio::fs::remove_dir_all(bucket.root().join(".terrane-locks"))
        .await
        .unwrap();
    let observed_fs = ObservedFs::new();
    let legacy = FileBucket::open_legacy_read_only(
        config(bucket.root().to_owned()),
        observed_fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    observed_fs.arm();

    let error = match SingleHeld::acquire(&legacy).await {
        Ok(_) => panic!("legacy namespace acquired writable exclusion"),
        Err(error) => error,
    };
    assert!(matches!(error.kind(), StoreErrorKind::ReadOnly));
    assert_eq!(observed_fs.attempts.available_permits(), 0);
    assert!(!bucket.root().join(".terrane-locks").exists());
    assert_eq!(TokioLocalFs.read(&capability_path).await.unwrap(), original);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}
