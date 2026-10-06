//! Measures actual held exact reads and rejects ancestry changes within a batch.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

mod burns;
mod content;
mod control_fences;

use super::{control::Control, selection};
use crate::bucket::FileBucket;
use crate::bucket::held::SingleHeld;
use crate::bucket::tests::{PreparedCas, Selected, Validator, config};
use crate::store::{
    ByteRange, Clock, LocalFs, RefCasOutcome, RefStore, StoreErrorKind, TokioClock, TokioLocalFs,
};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use terrane_core::bucket::BucketKey;
use terrane_core::gc::publication::{LogicalChange, PublicationCommit};
use terrane_core::refs::RefRecord;

struct ReadGate {
    target: PathBuf,
    entered: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

/// Pauses an actual matching read after a measured number of preceding reads.
struct CountedReadGate {
    gate: ReadGate,
    preceding_reads: usize,
}

#[derive(Default)]
struct ReadFs {
    metadata_reads: AtomicUsize,
    metadata_dispatches: AtomicUsize,
    record_reads: AtomicUsize,
    read_paths: Mutex<Vec<PathBuf>>,
    read_failure: Mutex<Option<PathBuf>>,
    leaf_replacement: Mutex<Option<PathBuf>>,
    read_gate: Mutex<Option<ReadGate>>,
    before_read_gate: Mutex<Option<CountedReadGate>>,
    writes: AtomicUsize,
    retained_effects: AtomicUsize,
    effect_permission_change: Mutex<Option<(PathBuf, PathBuf)>>,
    batch_permission_change: Mutex<Option<(PathBuf, PathBuf)>>,
    unsupported_missing_parent: Mutex<Option<PathBuf>>,
    unsupported_retention: AtomicBool,
    short_batch: AtomicBool,
    scalar_batches: AtomicBool,
    short_batch_path: Mutex<Option<PathBuf>>,
    batch_paths: Mutex<Vec<Vec<PathBuf>>>,
    permission_change: Mutex<Option<(PathBuf, PathBuf)>>,
}

#[async_trait::async_trait]
impl LocalFs for ReadFs {
    type Lock = crate::store::TokioFileLock;

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        if self.unsupported_retention.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "injected unsupported native retention",
            ));
        }
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.retained_effects.fetch_add(1, Ordering::SeqCst);
        let changed_parent = {
            let mut change = self.effect_permission_change.lock().unwrap();
            let target = match effect.fault_probe() {
                crate::store::EffectFaultProbe::Rename(path)
                | crate::store::EffectFaultProbe::RenameNoReplace(path) => Some(path),
                _ => None,
            };
            if change
                .as_ref()
                .is_some_and(|(expected, _)| target == Some(expected.as_path()))
            {
                change.take().map(|(_, parent)| parent)
            } else {
                None
            }
        };
        if let Some(parent) = changed_parent {
            TokioLocalFs
                .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o775))
                .await
                .map_err(crate::store::NativeEffectFailure::Io)?;
        }
        TokioLocalFs.execute_retained_effect(effect).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

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

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.record_reads.fetch_add(1, Ordering::SeqCst);
        self.read_paths.lock().unwrap().push(path.to_owned());
        let before_read = {
            let mut pending = self.before_read_gate.lock().unwrap();
            match pending.as_mut() {
                Some(counted) if counted.gate.target == path => {
                    if counted.preceding_reads == 0 {
                        pending.take().map(|counted| counted.gate)
                    } else {
                        counted.preceding_reads -= 1;
                        None
                    }
                }
                _ => None,
            }
        };
        if let Some(ReadGate {
            entered, release, ..
        }) = before_read
        {
            entered
                .send(())
                .map_err(|_| std::io::Error::other("before-read observer dropped"))?;
            release
                .await
                .map_err(|_| std::io::Error::other("before-read release dropped"))?;
        }
        if self.read_failure.lock().unwrap().as_deref() == Some(path) {
            return Err(std::io::Error::other("injected unavailable exact read"));
        }
        let bytes = TokioLocalFs.read_nofollow(path).await?;
        let replace_leaf = {
            let mut target = self.leaf_replacement.lock().unwrap();
            if target.as_deref() == Some(path) {
                target.take()
            } else {
                None
            }
        };
        if let Some(path) = replace_leaf {
            let temporary = path.with_extension("replacement");
            TokioLocalFs.write_new(&temporary, &bytes).await?;
            TokioLocalFs.rename(&temporary, &path).await?;
        }
        let gate = {
            let mut gate = self.read_gate.lock().unwrap();
            if gate.as_ref().is_some_and(|gate| gate.target == path) {
                gate.take()
            } else {
                None
            }
        };
        if let Some(ReadGate {
            entered, release, ..
        }) = gate
        {
            entered
                .send(())
                .map_err(|_| std::io::Error::other("read gate observer dropped"))?;
            release
                .await
                .map_err(|_| std::io::Error::other("read gate release dropped"))?;
        }
        let changed_parent = {
            let mut change = self.permission_change.lock().unwrap();
            if change.as_ref().is_some_and(|(target, _)| target == path) {
                change.take().map(|(_, parent)| parent)
            } else {
                None
            }
        };
        if let Some(parent) = changed_parent {
            TokioLocalFs
                .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o775))
                .await?;
        }
        Ok(bytes)
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_all(path).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_new(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.metadata_reads.fetch_add(1, Ordering::SeqCst);
        self.metadata_dispatches.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.metadata_reads.fetch_add(1, Ordering::SeqCst);
        self.metadata_dispatches.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        self.metadata_reads.fetch_add(paths.len(), Ordering::SeqCst);
        self.batch_paths.lock().unwrap().push(paths.to_vec());
        let mut observations = if self.scalar_batches.load(Ordering::SeqCst) {
            self.metadata_dispatches
                .fetch_add(paths.len(), Ordering::SeqCst);
            let mut observations = Vec::with_capacity(paths.len());
            for path in paths {
                observations.push(TokioLocalFs.symlink_metadata(path).await);
            }
            observations
        } else {
            if !paths.is_empty() {
                self.metadata_dispatches.fetch_add(1, Ordering::SeqCst);
            }
            TokioLocalFs.symlink_metadata_batch(paths).await?
        };
        let targeted_short = {
            let mut target = self.short_batch_path.lock().unwrap();
            if target.as_ref().is_some_and(|path| paths.contains(path)) {
                target.take();
                true
            } else {
                false
            }
        };
        if self.short_batch.swap(false, Ordering::SeqCst) || targeted_short {
            observations.pop();
        }
        if let Some(target) = self.unsupported_missing_parent.lock().unwrap().as_ref() {
            for (path, observation) in paths.iter().zip(&mut observations) {
                if path == target
                    && observation
                        .as_ref()
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                {
                    *observation = Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "injected unavailable missing parent",
                    ));
                }
            }
        }
        let changed_parent = {
            let mut change = self.batch_permission_change.lock().unwrap();
            if change
                .as_ref()
                .is_some_and(|(target, _)| paths.contains(target))
            {
                change.take().map(|(_, parent)| parent)
            } else {
                None
            }
        };
        if let Some(parent) = changed_parent {
            TokioLocalFs
                .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o775))
                .await?;
        }
        Ok(observations)
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
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
        self.writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }
}

impl ReadFs {
    fn reset_read_counters(&self) {
        self.metadata_reads.store(0, Ordering::SeqCst);
        self.metadata_dispatches.store(0, Ordering::SeqCst);
        self.record_reads.store(0, Ordering::SeqCst);
        self.read_paths.lock().unwrap().clear();
        self.writes.store(0, Ordering::SeqCst);
        self.retained_effects.store(0, Ordering::SeqCst);
        self.batch_paths.lock().unwrap().clear();
    }

    fn read_counters(&self) -> (usize, usize, usize) {
        (
            self.metadata_reads.load(Ordering::SeqCst),
            self.metadata_dispatches.load(Ordering::SeqCst),
            self.record_reads.load(Ordering::SeqCst),
        )
    }
}

async fn fixture() -> (PathBuf, FileBucket<ReadFs, TokioClock, Validator>) {
    let nonce = TokioLocalFs.random_bytes(16).await.unwrap();
    let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let parent = std::env::temp_dir().join(format!("terrane-held-reads-{name}"));
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

#[tokio::test]
async fn held_chain_reads_preserve_exact_gets_and_reduce_repeated_metadata() {
    let (parent, bucket) = fixture().await;
    let name = "refs/heads/_/measured";
    let mut previous = None;
    for sequence in 1..=3 {
        let record = match &previous {
            Some(record) => {
                RefRecord::advance(record, [sequence; 32], u64::from(sequence)).unwrap()
            }
            None => RefRecord::first([sequence; 32], u64::from(sequence), Default::default()),
        }
        .selected();
        bucket
            .prepared_cas(name, previous.as_ref(), &record)
            .await
            .unwrap();
        previous = Some(record);
    }
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let held = adapter.identity_proof();
    let control = Control::open(&bucket, false).await.unwrap();

    bucket.inner.fs.metadata_reads.store(0, Ordering::SeqCst);
    bucket.inner.fs.record_reads.store(0, Ordering::SeqCst);
    let started = TokioClock.monotonic();
    let ordinary = selection::resolve(&bucket, &control).await.unwrap();
    let ordinary_elapsed = TokioClock.monotonic().saturating_sub(started);
    let ordinary_metadata = bucket.inner.fs.metadata_reads.load(Ordering::SeqCst);
    let ordinary_records = bucket.inner.fs.record_reads.load(Ordering::SeqCst);

    bucket.inner.fs.metadata_reads.store(0, Ordering::SeqCst);
    bucket.inner.fs.record_reads.store(0, Ordering::SeqCst);
    let started = TokioClock.monotonic();
    let batched = selection::resolve_held(&bucket, &control, &held)
        .await
        .unwrap();
    let batched_elapsed = TokioClock.monotonic().saturating_sub(started);
    let batched_metadata = bucket.inner.fs.metadata_reads.load(Ordering::SeqCst);
    let batched_records = bucket.inner.fs.record_reads.load(Ordering::SeqCst);

    assert_eq!(ordinary.state, batched.state);
    assert_eq!(ordinary.digest, batched.digest);
    assert_eq!(ordinary.logical, batched.logical);
    assert_eq!(ordinary_records, batched_records);
    assert!(batched_metadata < ordinary_metadata);
    eprintln!(
        "exact records {ordinary_records}; metadata {ordinary_metadata}->{batched_metadata}; native elapsed {ordinary_elapsed:?}->{batched_elapsed:?}"
    );

    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_chain_final_check_rejects_real_ancestry_permission_change() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let held = adapter.identity_proof();
    let before = adapter.observe_publication().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let slot_path = control.path.join("publication/commits/0");
    let slot_bytes = TokioLocalFs.read_nofollow(&slot_path).await.unwrap();
    let slot = PublicationCommit::decode(&slot_bytes).unwrap();
    let transaction_path = control.path.join(slot.transaction_key);
    let transaction_bytes = TokioLocalFs.read_nofollow(&transaction_path).await.unwrap();
    *bucket.inner.fs.permission_change.lock().unwrap() =
        Some((transaction_path.clone(), parent.clone()));
    bucket.inner.fs.writes.store(0, Ordering::SeqCst);

    assert!(
        selection::resolve_held(&bucket, &control, &held)
            .await
            .is_err()
    );
    assert!(bucket.inner.fs.permission_change.lock().unwrap().is_none());
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        TokioLocalFs.read_nofollow(&slot_path).await.unwrap(),
        slot_bytes
    );
    assert_eq!(
        TokioLocalFs.read_nofollow(&transaction_path).await.unwrap(),
        transaction_bytes
    );

    TokioLocalFs
        .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());
    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_ref_reads_match_ordinary_and_refresh_after_own_publication() {
    let (parent, bucket) = fixture().await;
    let head_name = "refs/heads/_/measured";
    let notes_name = "refs/notes/memos/_/measured";
    let tag_name = "refs/tags/_/measured";
    let head = RefRecord::first([1; 32], 3, Default::default()).selected();
    let first = RefRecord::first([2; 32], 3, Default::default());
    bucket.prepared_cas(head_name, None, &head).await.unwrap();
    for name in [notes_name, tag_name] {
        assert!(matches!(
            bucket.ref_cas(name, None, &first).await.unwrap(),
            RefCasOutcome::Applied
        ));
    }
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let source = holder.source();

    for name in [head_name, notes_name, tag_name, "refs/heads/_/absent"] {
        let ordinary = bucket.ref_get_locked(name).await.unwrap();
        assert_eq!(adapter.ref_get(name).await.unwrap(), ordinary);
        assert_eq!(source.ref_get(name).await.unwrap(), ordinary);
    }
    for name in ["outside", "refs/heads/../bad", "refs/notes/unknown/_/bad"] {
        let ordinary = bucket.ref_get_locked(name).await.unwrap_err();
        assert_eq!(
            adapter.ref_get(name).await.unwrap_err().kind(),
            ordinary.kind()
        );
    }

    bucket.inner.fs.metadata_reads.store(0, Ordering::SeqCst);
    bucket.inner.fs.record_reads.store(0, Ordering::SeqCst);
    let started = TokioClock.monotonic();
    let ordinary = bucket.ref_get_locked(head_name).await.unwrap();
    let ordinary_elapsed = TokioClock.monotonic().saturating_sub(started);
    let ordinary_metadata = bucket.inner.fs.metadata_reads.load(Ordering::SeqCst);
    let ordinary_records = bucket.inner.fs.record_reads.load(Ordering::SeqCst);

    bucket.inner.fs.metadata_reads.store(0, Ordering::SeqCst);
    bucket.inner.fs.record_reads.store(0, Ordering::SeqCst);
    bucket.inner.fs.writes.store(0, Ordering::SeqCst);
    bucket
        .inner
        .fs
        .metadata_dispatches
        .store(0, Ordering::SeqCst);
    let started = TokioClock.monotonic();
    let actual = adapter.ref_get(head_name).await.unwrap();
    let held_elapsed = TokioClock.monotonic().saturating_sub(started);
    let held_metadata = bucket.inner.fs.metadata_reads.load(Ordering::SeqCst);
    let held_records = bucket.inner.fs.record_reads.load(Ordering::SeqCst);
    let held_dispatches = bucket.inner.fs.metadata_dispatches.load(Ordering::SeqCst);
    assert_eq!(actual, ordinary);
    assert!(held_records < ordinary_records);
    assert!(held_metadata < ordinary_metadata);
    assert!(held_dispatches < held_metadata);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    eprintln!(
        "held ref_get records {ordinary_records}->{held_records}; metadata entries {ordinary_metadata}->{held_metadata}; actual native metadata dispatches {held_dispatches} for {held_metadata} entries; native elapsed {ordinary_elapsed:?}->{held_elapsed:?}"
    );

    let second = first.advance([3; 32], 4).unwrap();
    assert!(matches!(
        adapter
            .ref_cas(notes_name, Some(&first), &second)
            .await
            .unwrap(),
        RefCasOutcome::Applied
    ));
    assert_eq!(
        adapter.ref_get(notes_name).await.unwrap(),
        Some(second.clone())
    );
    assert_eq!(
        source.ref_get(notes_name).await.unwrap(),
        Some(second.clone())
    );

    let observed = adapter.observe_publication().await.unwrap();
    adapter
        .publish_raw(
            &observed,
            vec![LogicalChange {
                key: format!("{notes_name}:record"),
                expected: Some(second.encode().unwrap()),
                new: Some(b"opaque advisory bytes".to_vec()),
            }],
        )
        .await
        .unwrap();
    let ordinary = bucket.ref_get_locked(notes_name).await.unwrap_err();
    assert_eq!(
        adapter.ref_get(notes_name).await.unwrap_err().kind(),
        ordinary.kind()
    );

    drop(observed);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_ref_read_rechecks_ancestry_with_unchanged_selected_bytes() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let name = "refs/heads/_/absent";
    assert_eq!(adapter.ref_get(name).await.unwrap(), None);
    let before = adapter.observe_publication().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let slot_path = control.path.join("publication/commits/0");
    let slot_bytes = TokioLocalFs.read_nofollow(&slot_path).await.unwrap();
    let slot = PublicationCommit::decode(&slot_bytes).unwrap();
    let transaction_path = control.path.join(slot.transaction_key);
    let transaction_bytes = TokioLocalFs.read_nofollow(&transaction_path).await.unwrap();
    *bucket.inner.fs.permission_change.lock().unwrap() =
        Some((transaction_path.clone(), parent.clone()));
    bucket.inner.fs.writes.store(0, Ordering::SeqCst);

    assert!(adapter.ref_get(name).await.is_err());
    assert!(bucket.inner.fs.permission_change.lock().unwrap().is_none());
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        TokioLocalFs.read_nofollow(&slot_path).await.unwrap(),
        slot_bytes
    );
    assert_eq!(
        TokioLocalFs.read_nofollow(&transaction_path).await.unwrap(),
        transaction_bytes
    );

    TokioLocalFs
        .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    assert_eq!(adapter.ref_get(name).await.unwrap(), None);
    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());
    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn short_native_metadata_batch_is_rejected_before_selected_reads_or_effects() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    bucket.inner.fs.short_batch.store(true, Ordering::SeqCst);
    bucket.inner.fs.record_reads.store(0, Ordering::SeqCst);
    bucket.inner.fs.writes.store(0, Ordering::SeqCst);

    let error = adapter.ref_get("refs/heads/_/absent").await.unwrap_err();
    assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    assert!(!bucket.inner.fs.short_batch.load(Ordering::SeqCst));
    assert_eq!(bucket.inner.fs.record_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);

    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());
    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn unsafe_native_ancestor_precedes_later_missing_path_error() {
    let (parent, bucket) = fixture().await;
    let missing_root = parent.join("missing");
    let configured = bucket.inner.config.publication_control.as_ref().unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o775))
        .await
        .unwrap();
    bucket.inner.fs.record_reads.store(0, Ordering::SeqCst);
    bucket.inner.fs.writes.store(0, Ordering::SeqCst);

    let error = Control::open_existing_config(&bucket.inner.fs, &missing_root, configured)
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(bucket.inner.fs.record_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);

    TokioLocalFs
        .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let error = Control::open_existing_config(&bucket.inner.fs, &missing_root, configured)
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn record_parent_batches_preserve_entries_duplicates_and_exact_gets() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let observed = adapter.observe_publication().await.unwrap();
    let held = adapter.identity_proof();
    let control = Control::open(&bucket, false).await.unwrap();
    let reads = control.held_reads(&bucket.inner.fs, &held).await.unwrap();
    let fs = &bucket.inner.fs;
    let protected_key = "publication/commits/0";

    fs.scalar_batches.store(true, Ordering::SeqCst);
    fs.reset_read_counters();
    let scalar = reads.read(protected_key).await.unwrap();
    let scalar_counts = fs.read_counters();

    fs.scalar_batches.store(false, Ordering::SeqCst);
    fs.reset_read_counters();
    let batched = reads.read(protected_key).await.unwrap();
    let batched_counts = fs.read_counters();
    assert_eq!(scalar, batched);
    assert_eq!(scalar_counts, (6, 6, 1));
    assert_eq!(batched_counts, (6, 3, 1));
    assert_eq!(
        *fs.batch_paths.lock().unwrap(),
        vec![vec![
            control.path.join("publication"),
            control.path.join("publication"),
            control.path.join("publication/commits"),
            control.path.join("publication/commits"),
        ]]
    );
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    reads.finish().await.unwrap();

    let payload_key = BucketKey::parse(&observed.selected.snapshot.key).unwrap();
    let mut path = bucket.inner.config.root.clone();
    let mut expected_parents = Vec::new();
    for part in Path::new(payload_key.as_str())
        .parent()
        .unwrap()
        .components()
    {
        path.push(part);
        expected_parents.push(path.clone());
    }
    fs.scalar_batches.store(true, Ordering::SeqCst);
    fs.reset_read_counters();
    let scalar = bucket.read_optional(&payload_key).await.unwrap();
    let scalar_payload_counts = fs.read_counters();

    fs.scalar_batches.store(false, Ordering::SeqCst);
    fs.reset_read_counters();
    let batched = bucket.read_optional(&payload_key).await.unwrap();
    let batched_payload_counts = fs.read_counters();
    assert_eq!(scalar, batched);
    assert_eq!(
        scalar_payload_counts,
        (expected_parents.len() + 2, expected_parents.len() + 2, 1)
    );
    assert_eq!(batched_payload_counts, (expected_parents.len() + 2, 3, 1));
    assert_eq!(*fs.batch_paths.lock().unwrap(), vec![expected_parents]);
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    eprintln!(
        "protected parent metadata entries/dispatches/GETs {scalar_counts:?}->{batched_counts:?}; payload {scalar_payload_counts:?}->{batched_payload_counts:?}"
    );

    drop(observed);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn record_parent_short_batches_refuse_before_exact_reads_or_effects() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    let held = adapter.identity_proof();
    let control = Control::open(&bucket, false).await.unwrap();
    let reads = control.held_reads(&bucket.inner.fs, &held).await.unwrap();
    let fs = &bucket.inner.fs;

    *fs.short_batch_path.lock().unwrap() = Some(control.path.join("publication"));
    fs.reset_read_counters();
    let error = reads.read("publication/commits/0").await.unwrap_err();
    assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    assert!(fs.short_batch_path.lock().unwrap().is_none());
    assert_eq!(fs.read_counters(), (4, 1, 0));
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    reads.finish().await.unwrap();

    let key = BucketKey::parse(&before.selected.snapshot.key).unwrap();
    let first_parent = Path::new(key.as_str()).components().next().unwrap();
    *fs.short_batch_path.lock().unwrap() = Some(bucket.inner.config.root.join(first_parent));
    fs.reset_read_counters();
    let error = bucket.read_optional(&key).await.unwrap_err();
    assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    assert!(fs.short_batch_path.lock().unwrap().is_none());
    assert_eq!(fs.record_reads.load(Ordering::SeqCst), 0);
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);

    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());
    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn unsafe_protected_record_parent_precedes_later_missing_parent() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let publication = control.path.join("publication");
    let missing_key = format!("publication/guards/{}", "ff".repeat(32));
    assert!(
        control
            .read(&bucket.inner.fs, &missing_key)
            .await
            .unwrap()
            .is_none()
    );
    TokioLocalFs
        .set_permissions_and_sync(&publication, std::fs::Permissions::from_mode(0o775))
        .await
        .unwrap();
    bucket.inner.fs.reset_read_counters();

    let error = control
        .read(&bucket.inner.fs, &missing_key)
        .await
        .unwrap_err();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(bucket.inner.fs.record_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);

    TokioLocalFs
        .set_permissions_and_sync(&publication, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    assert!(
        control
            .read(&bucket.inner.fs, &missing_key)
            .await
            .unwrap()
            .is_none()
    );
    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());
    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn unsafe_payload_record_parent_precedes_later_metadata_failure() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    let key = BucketKey::parse(&before.selected.snapshot.key).unwrap();
    let first_parent = Path::new(key.as_str()).components().next().unwrap();
    let unsafe_parent = bucket.inner.config.root.join(first_parent);
    let saved_parent = bucket.inner.config.root.join("saved-parent");
    TokioLocalFs
        .rename(&unsafe_parent, &saved_parent)
        .await
        .unwrap();
    TokioLocalFs
        .write_new(&unsafe_parent, b"regular parent")
        .await
        .unwrap();
    bucket.inner.fs.reset_read_counters();

    let error = bucket.read_optional(&key).await.unwrap_err();
    assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    assert_eq!(bucket.inner.fs.record_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);

    TokioLocalFs.remove_file(&unsafe_parent).await.unwrap();
    TokioLocalFs
        .rename(&saved_parent, &unsafe_parent)
        .await
        .unwrap();
    assert!(bucket.read_optional(&key).await.unwrap().is_some());
    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());
    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn payload_parent_batch_final_check_rejects_ancestry_change_after_exact_read() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    let key = BucketKey::parse(&before.selected.snapshot.key).unwrap();
    let snapshot_path = bucket.path(&key);
    let bytes = TokioLocalFs.read_nofollow(&snapshot_path).await.unwrap();
    *bucket.inner.fs.permission_change.lock().unwrap() =
        Some((snapshot_path.clone(), parent.clone()));
    bucket.inner.fs.reset_read_counters();

    assert!(adapter.ref_get("refs/heads/_/absent").await.is_err());
    assert!(bucket.inner.fs.permission_change.lock().unwrap().is_none());
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        TokioLocalFs.read_nofollow(&snapshot_path).await.unwrap(),
        bytes
    );

    TokioLocalFs
        .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());
    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn unavailable_retention_allows_only_existing_read_only_holds() {
    let (parent, bucket) = fixture().await;
    bucket
        .inner
        .fs
        .unsupported_retention
        .store(true, Ordering::SeqCst);
    bucket.inner.fs.reset_read_counters();

    let error = SingleHeld::acquire(&bucket).await.err().unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(bucket.inner.fs.record_reads.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);

    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let source = holder.source();
    assert_eq!(source.ref_get("refs/heads/_/absent").await.unwrap(), None);
    let observed = source.observe_publication().await.unwrap();
    assert!(!observed.identity().writable());
    assert!(matches!(
        observed
            .identity()
            .retained_namespace()
            .err()
            .unwrap()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(matches!(
        holder
            .destination()
            .retained_namespace()
            .err()
            .unwrap()
            .kind(),
        StoreErrorKind::Unsupported
    ));
    let record = RefRecord::first([1; 32], 1, Default::default());
    let error = holder
        .destination()
        .ref_cas("refs/notes/memos/_/absent", None, &record)
        .await
        .unwrap_err();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);

    drop(observed);
    drop(holder);
    bucket
        .inner
        .fs
        .unsupported_retention
        .store(false, Ordering::SeqCst);
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    assert!(holder.destination().retained_namespace().is_ok());
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn raw_repair_and_candidate_logs_use_only_actual_retained_effects() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    let fs = &bucket.inner.fs;
    let capabilities = bucket.root().join("CAPABILITIES");
    let selected_capabilities = before
        .logical()
        .get("CAPABILITIES")
        .unwrap()
        .as_ref()
        .unwrap();
    TokioLocalFs.remove_file(&capabilities).await.unwrap();
    fs.reset_read_counters();

    crate::store::native_publication_effects::repair(fs, &before)
        .await
        .unwrap();
    assert_eq!(
        TokioLocalFs.read_nofollow(&capabilities).await.unwrap(),
        *selected_capabilities
    );
    assert!(fs.retained_effects.load(Ordering::SeqCst) > 0);
    assert_eq!(
        fs.writes.load(Ordering::SeqCst),
        fs.retained_effects.load(Ordering::SeqCst)
    );

    let name = "refs/heads/_/retained-log";
    let record = RefRecord::first([3; 32], 1, Default::default()).selected();
    let log = crate::bucket::tests::log(record.clone(), None);
    fs.reset_read_counters();
    assert_eq!(
        adapter.ref_log_append(name, 1, &log).await.unwrap(),
        crate::store::RefLogAppendOutcome::Appended
    );
    let key = BucketKey::reflog_candidate(name, 1, &record.candidate_id.unwrap()).unwrap();
    let installed = TokioLocalFs
        .read_nofollow(&bucket.root().join(key.as_str()))
        .await
        .unwrap();
    assert_eq!(installed, log.encode().unwrap());
    assert!(fs.retained_effects.load(Ordering::SeqCst) > 0);
    assert_eq!(
        fs.writes.load(Ordering::SeqCst),
        fs.retained_effects.load(Ordering::SeqCst)
    );

    let mut replacement = log.clone();
    replacement.record.commit = [4; 32];
    assert_eq!(
        adapter.ref_log_append(name, 1, &replacement).await.unwrap(),
        crate::store::RefLogAppendOutcome::Exists
    );
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&bucket.root().join(key.as_str()))
            .await
            .unwrap(),
        installed
    );
    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());

    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn raw_cache_repair_refuses_actual_ancestry_change_before_rename() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    let capabilities = bucket.root().join("CAPABILITIES");
    TokioLocalFs.remove_file(&capabilities).await.unwrap();
    let fs = &bucket.inner.fs;
    *fs.effect_permission_change.lock().unwrap() =
        Some((capabilities.clone(), bucket.root().to_owned()));

    assert!(
        crate::store::native_publication_effects::repair(fs, &before)
            .await
            .is_err()
    );
    assert!(fs.effect_permission_change.lock().unwrap().is_none());
    assert_eq!(
        TokioLocalFs
            .symlink_metadata(&capabilities)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    TokioLocalFs
        .set_permissions_and_sync(bucket.root(), std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());

    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn raw_ref_cas_selects_only_raw_proof_through_retained_effects() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let name = "refs/heads/_/raw-slot";
    let record = RefRecord::first([5; 32], 1, Default::default()).selected();
    adapter
        .ref_log_append(
            name,
            record.seq,
            &crate::bucket::tests::log(record.clone(), None),
        )
        .await
        .unwrap();
    let before = adapter.observe_publication().await.unwrap();
    bucket.inner.fs.reset_read_counters();

    assert_eq!(
        adapter.ref_cas(name, None, &record).await.unwrap(),
        RefCasOutcome::Applied
    );
    assert!(bucket.inner.fs.retained_effects.load(Ordering::SeqCst) > 0);
    assert_eq!(
        bucket.inner.fs.writes.load(Ordering::SeqCst),
        bucket.inner.fs.retained_effects.load(Ordering::SeqCst)
    );
    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp().0, before.stamp().0 + 1);
    assert_eq!(after.state().guard, before.state().guard);
    assert!(after.state().sources.is_empty());
    assert_eq!(adapter.ref_get(name).await.unwrap(), Some(record));
    let control = Control::open(&bucket, false).await.unwrap();
    let slot = PublicationCommit::decode(
        &control
            .read(
                &bucket.inner.fs,
                &format!("publication/commits/{}", after.stamp().0),
            )
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let transaction = terrane_core::gc::publication::PublicationTransaction::decode(
        &control
            .read(&bucket.inner.fs, &slot.transaction_key)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        transaction.proof,
        terrane_core::gc::publication::PublicationProof::Raw
    );
    assert_eq!(transaction.old.as_ref(), Some(before.state()));
    assert_eq!(&transaction.new, after.state());

    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn raw_slot_refuses_actual_control_change_after_transaction_staging() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let before = adapter.observe_publication().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let slot = control
        .path
        .join(format!("publication/commits/{}", before.stamp().0 + 1));
    *bucket.inner.fs.effect_permission_change.lock().unwrap() =
        Some((slot.clone(), control.path.clone()));

    assert!(adapter.publish_raw(&before, Vec::new()).await.is_err());
    assert!(
        bucket
            .inner
            .fs
            .effect_permission_change
            .lock()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        TokioLocalFs
            .symlink_metadata(&slot)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    TokioLocalFs
        .set_permissions_and_sync(&control.path, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let after = adapter.observe_publication().await.unwrap();
    assert_eq!(after.stamp(), before.stamp());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.logical(), before.logical());

    drop(after);
    drop(before);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

fn assert_retirement_associations_preserved(before: &super::Selected, after: &super::Selected) {
    use terrane_core::bucket::GenerationManifest;
    let manifest = |selected: &super::Selected| {
        let generation = super::projection::capabilities(&selected.logical)
            .unwrap()
            .generation
            .unwrap();
        GenerationManifest::decode(
            super::projection::value(
                &selected.logical,
                &format!("objects/index/{generation}/MANIFEST"),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let previous = manifest(before);
    let next = manifest(after);
    assert_eq!(next.exclusions, previous.exclusions);
    assert_eq!(next.burns, previous.burns);
    assert_eq!(after.state.burn_owners, before.state.burn_owners);
}

#[tokio::test]
async fn content_admission_and_catalog_selection_use_only_retained_effects() {
    use crate::bucket::content_tests::{chunk_identity, raw, upload};
    use crate::store::{ChunkPosition, ContentStore};
    let (parent, bucket) = fixture().await;
    let before = bucket.selected_publication_locked().await.unwrap();
    let encoded = raw(b"retained admitted content");
    let identity = chunk_identity(b"retained admitted content");
    let profile = terrane_core::chunking::ChunkProfile::cdc_1m([0; 32]);
    bucket.inner.fs.reset_read_counters();

    assert_eq!(
        bucket
            .put(upload(
                &encoded,
                &identity,
                b"retained admitted content".len(),
                &profile,
                ChunkPosition::Final
            ))
            .await
            .unwrap(),
        identity
    );
    assert!(bucket.inner.fs.retained_effects.load(Ordering::SeqCst) > 0);
    assert_eq!(
        bucket.inner.fs.writes.load(Ordering::SeqCst),
        bucket.inner.fs.retained_effects.load(Ordering::SeqCst)
    );
    let after = bucket.selected_publication_locked().await.unwrap();
    assert_retirement_associations_preserved(&before, &after);
    assert_eq!(after.state.revision, before.state.revision + 1);
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    assert_eq!(bucket.get(&identity, None).await.unwrap(), encoded);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn quarantine_loss_selection_uses_only_actual_retained_effects() {
    use crate::bucket::content_tests::{chunk_identity, raw, upload};
    use crate::store::{ChunkPosition, ContentStore};
    let (parent, bucket) = fixture().await;
    let encoded = raw(b"retained quarantine");
    let identity = chunk_identity(b"retained quarantine");
    let profile = terrane_core::chunking::ChunkProfile::cdc_1m([0; 32]);
    bucket
        .put(upload(
            &encoded,
            &identity,
            b"retained quarantine".len(),
            &profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let before = bucket.selected_publication_locked().await.unwrap();
    bucket.inner.fs.reset_read_counters();

    bucket.exclude(&identity).await.unwrap();
    assert!(bucket.inner.fs.retained_effects.load(Ordering::SeqCst) > 0);
    assert_eq!(
        bucket.inner.fs.writes.load(Ordering::SeqCst),
        bucket.inner.fs.retained_effects.load(Ordering::SeqCst)
    );
    let after = bucket.selected_publication_locked().await.unwrap();
    assert_retirement_associations_preserved(&before, &after);
    assert_eq!(after.state.revision, before.state.revision + 1);
    assert_eq!(
        after.state.loss_generation,
        before.state.loss_generation + 1
    );
    assert_eq!(after.state.guard, before.state.guard);
    assert!(after.state.sources.is_empty());
    assert!(matches!(
        bucket.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Absent(_)
    ));
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn retained_frame_batches_every_present_parent_without_skipping_metadata_or_gets() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let observed = adapter.observe_publication().await.unwrap();
    let mut expected = Vec::new();
    for read in observed
        .physical_reads()
        .iter()
        .take_while(|read| read.bytes().is_some())
    {
        let mut paths: Vec<_> = read
            .path()
            .parent()
            .unwrap()
            .ancestors()
            .map(Path::to_owned)
            .collect();
        paths.reverse();
        expected.extend(paths);
    }
    assert!(expected.len() > observed.physical_reads().len());
    let fs = &bucket.inner.fs;
    fs.scalar_batches.store(true, Ordering::SeqCst);
    fs.reset_read_counters();
    crate::store::native_publication_effects::repair(fs, &observed)
        .await
        .unwrap();
    let scalar = fs.read_counters();
    let scalar_effects = fs.retained_effects.load(Ordering::SeqCst);

    fs.scalar_batches.store(false, Ordering::SeqCst);
    fs.reset_read_counters();
    crate::store::native_publication_effects::repair(fs, &observed)
        .await
        .unwrap();
    let batched = fs.read_counters();
    assert_eq!(batched.0, scalar.0);
    assert_eq!(batched.2, scalar.2);
    assert!(batched.1 < scalar.1);
    assert_eq!(fs.retained_effects.load(Ordering::SeqCst), scalar_effects);
    assert!(fs.batch_paths.lock().unwrap().contains(&expected));
    observed.revalidate().await.unwrap();
    eprintln!("retained frame entries/dispatches/GETs {scalar:?}->{batched:?}");

    drop(observed);
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn retained_frame_short_parent_batch_refuses_before_any_effect() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let observed = adapter.observe_publication().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let fs = &bucket.inner.fs;
    *fs.short_batch_path.lock().unwrap() = Some(control.path.join("publication/commits"));
    fs.reset_read_counters();

    let error = crate::store::native_publication_effects::repair(fs, &observed)
        .await
        .unwrap_err();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert!(fs.short_batch_path.lock().unwrap().is_none());
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    observed.revalidate().await.unwrap();
    drop(observed);
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn retained_frame_parent_change_after_batch_refuses_unchanged_records() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let observed = adapter.observe_publication().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let commits = control.path.join("publication/commits");
    let slot = commits.join(observed.stamp().0.to_string());
    let original = TokioLocalFs.read_nofollow(&slot).await.unwrap();
    let fs = &bucket.inner.fs;
    *fs.batch_permission_change.lock().unwrap() = Some((commits.clone(), commits.clone()));
    fs.reset_read_counters();

    assert!(
        crate::store::native_publication_effects::repair(fs, &observed)
            .await
            .is_err()
    );
    assert!(fs.batch_permission_change.lock().unwrap().is_none());
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    assert_eq!(TokioLocalFs.read_nofollow(&slot).await.unwrap(), original);
    TokioLocalFs
        .set_permissions_and_sync(&commits, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    observed.revalidate().await.unwrap();
    drop(observed);
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn retained_frame_earlier_unsafe_parent_precedes_later_missing_parent_failure() {
    let (parent, bucket) = fixture().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let observed = adapter.observe_publication().await.unwrap();
    let control = Control::open(&bucket, false).await.unwrap();
    let commits = control.path.join("publication/commits");
    let snapshots = bucket.root().join("publication/snapshots");
    let saved = bucket.root().join("saved-snapshots");
    TokioLocalFs.rename(&snapshots, &saved).await.unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&commits, std::fs::Permissions::from_mode(0o775))
        .await
        .unwrap();
    let fs = &bucket.inner.fs;
    *fs.unsupported_missing_parent.lock().unwrap() = Some(snapshots.clone());
    fs.reset_read_counters();

    let error = crate::store::native_publication_effects::repair(fs, &observed)
        .await
        .unwrap_err();
    // The genuine earlier unsafe ancestor produces Unavailable. The injected
    // typed missing-parent capability refusal would instead produce Unsupported.
    assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    assert!(
        fs.batch_paths
            .lock()
            .unwrap()
            .iter()
            .any(|paths| paths.contains(&commits) && paths.contains(&snapshots))
    );
    TokioLocalFs
        .set_permissions_and_sync(&commits, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    TokioLocalFs.rename(&saved, &snapshots).await.unwrap();
    *fs.unsupported_missing_parent.lock().unwrap() = None;
    observed.revalidate().await.unwrap();
    drop(observed);
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}
