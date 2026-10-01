//! Exercises genuine existing-Active startup probes and canceled worker retention.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::*;
use crate::bucket::tests::{
    PreparedCas, Selected as SelectedRecord, Validator, config, control_path, fixture,
};
use crate::store::{
    ByteRange, EffectFaultProbe, NativeEffectFailure, NativeExclusion, NativeFsEffect, RefStore,
    TokioClock, TokioLocalFs,
};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use terrane_core::gc::publication::{PublicationState, RawDigest};
use terrane_core::refs::RefRecord;

struct Gate {
    arrived: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[derive(Default)]
struct State {
    ordinary_effects: AtomicUsize,
    retained_effects: AtomicUsize,
    probes: Mutex<Vec<PathBuf>>,
    ranges: AtomicUsize,
    noop: Mutex<Option<PathBuf>>,
    wrong_range: AtomicBool,
    replace_range_leaf: AtomicBool,
    unsafe_range_parent: AtomicBool,
    unavailable_retention: AtomicBool,
    gate: Mutex<Option<Gate>>,
}

#[derive(Clone, Default)]
struct ActiveFs(Arc<State>);

#[async_trait::async_trait]
impl LocalFs for ActiveFs {
    type Lock = crate::store::TokioFileLock;

    fn retain_native_exclusion(&self, held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        if self.0.unavailable_retention.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "injected unavailable native retention",
            ));
        }
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        mut effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        self.0.retained_effects.fetch_add(1, Ordering::SeqCst);
        let probe = match effect.fault_probe() {
            EffectFaultProbe::WriteNew(path)
                if path.file_name().is_some_and(|name| {
                    name == "CAPABILITIES" || name == "backend-registration.cbor"
                }) =>
            {
                Some(path.to_owned())
            }
            _ => None,
        };
        if let Some(path) = probe {
            self.0.probes.lock().unwrap().push(path.clone());
            if self.0.noop.lock().unwrap().as_deref() == Some(path.as_path()) {
                return Ok(());
            }
            if path.file_name().is_some_and(|name| name == "CAPABILITIES") {
                let gate = self.0.gate.lock().unwrap().take();
                if let Some(Gate { arrived, release }) = gate {
                    effect =
                        crate::store::native_publication_effects::gate_active_cap_probe_for_test(
                            effect, arrived, release,
                        )
                        .map_err(NativeEffectFailure::Rejected)?;
                }
            }
        }
        TokioLocalFs.execute_retained_effect(effect).await
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        self.0.ranges.fetch_add(1, Ordering::SeqCst);
        assert_eq!(path.file_name().unwrap(), "CAPABILITIES");
        assert_eq!(
            range,
            ByteRange {
                start: 0,
                length: 1
            }
        );
        let mut bytes = TokioLocalFs.read_range(path, range).await?;
        if self.0.replace_range_leaf.load(Ordering::SeqCst) {
            let complete = TokioLocalFs.read_nofollow(path).await?;
            let replacement = path.with_extension("active-range-replacement");
            TokioLocalFs.write_new(&replacement, &complete).await?;
            TokioLocalFs.rename(&replacement, path).await?;
        }
        if self.0.unsafe_range_parent.load(Ordering::SeqCst) {
            use std::os::unix::fs::PermissionsExt;
            TokioLocalFs
                .set_permissions_and_sync(
                    path.parent().unwrap(),
                    std::fs::Permissions::from_mode(0o775),
                )
                .await?;
        }
        if self.0.wrong_range.load(Ordering::SeqCst) {
            bytes[0] ^= 1;
        }
        Ok(bytes)
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_all(path).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
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

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.remove_file(path).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.sync_directory(path).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }
}

async fn selected<F: LocalFs + BucketBinding>(
    bucket: &FileBucket<F, TokioClock, Validator>,
) -> ((u64, RawDigest), PublicationState) {
    let holder = SingleHeld::acquire_read_only(bucket).await.unwrap();
    let source = holder.source();
    let observed = source.observe_for_read().await.unwrap();
    (observed.stamp(), observed.state().clone())
}

async fn remove(root: &Path) {
    tokio::fs::remove_dir_all(root).await.unwrap();
    tokio::fs::remove_dir_all(control_path(root)).await.unwrap();
}

#[tokio::test]
async fn active_open_runs_real_fixed_probes_and_preserves_registered_selection() {
    let bucket = fixture().await;
    let name = "refs/heads/_/active-open";
    let record = RefRecord::first([1; 32], 3, Default::default()).selected();
    bucket.prepared_cas(name, None, &record).await.unwrap();
    let root = bucket.root().to_owned();
    let before = selected(&bucket).await;
    let registration_path = control_path(&root).join("backend-registration.cbor");
    let registration = TokioLocalFs
        .read_nofollow(&registration_path)
        .await
        .unwrap();
    let fs = ActiveFs::default();

    let reopened = FileBucket::open(config(root.clone()), fs.clone(), TokioClock, Validator)
        .await
        .unwrap();
    let after = selected(&reopened).await;
    assert_eq!(after.1.binding, before.1.binding);
    assert_eq!(after.1.branches, before.1.branches);
    assert_eq!(after.1.sources, before.1.sources);
    assert_eq!(after.1.guard, before.1.guard);
    assert_eq!(after.1.burn_owners, before.1.burn_owners);
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&registration_path)
            .await
            .unwrap(),
        registration
    );
    assert_eq!(
        *fs.0.probes.lock().unwrap(),
        vec![root.join("CAPABILITIES"), registration_path]
    );
    assert_eq!(fs.0.ranges.load(Ordering::SeqCst), 1);
    assert_eq!(fs.0.ordinary_effects.load(Ordering::SeqCst), 0);
    assert_eq!(reopened.ref_get(name).await.unwrap(), Some(record));
    remove(&root).await;
}

#[tokio::test]
async fn active_open_refuses_noop_create_probes_despite_unchanged_present_bytes() {
    for target in ["CAPABILITIES", "backend-registration.cbor"] {
        let bucket = fixture().await;
        let root = bucket.root().to_owned();
        let before = selected(&bucket).await;
        let path = if target == "CAPABILITIES" {
            root.join(target)
        } else {
            control_path(&root).join(target)
        };
        let present = TokioLocalFs.read_nofollow(&path).await.unwrap();
        let fs = ActiveFs::default();
        *fs.0.noop.lock().unwrap() = Some(path.clone());

        let error = FileBucket::open(config(root.clone()), fs.clone(), TokioClock, Validator)
            .await
            .err()
            .unwrap();
        assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
        assert!(fs.0.probes.lock().unwrap().contains(&path));
        assert_eq!(TokioLocalFs.read_nofollow(&path).await.unwrap(), present);
        assert_eq!(selected(&bucket).await, before);
        assert_eq!(fs.0.ordinary_effects.load(Ordering::SeqCst), 0);
        remove(&root).await;
    }
}

#[tokio::test]
async fn active_open_refuses_wrong_binding_range_before_selected_timestamp_publication() {
    let bucket = fixture().await;
    let root = bucket.root().to_owned();
    let before = selected(&bucket).await;
    let cap = TokioLocalFs
        .read_nofollow(&root.join("CAPABILITIES"))
        .await
        .unwrap();
    let fs = ActiveFs::default();
    fs.0.wrong_range.store(true, Ordering::SeqCst);

    let error = FileBucket::open(config(root.clone()), fs.clone(), TokioClock, Validator)
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(fs.0.probes.lock().unwrap().len(), 2);
    assert_eq!(fs.0.ranges.load(Ordering::SeqCst), 1);
    assert_eq!(selected(&bucket).await, before);
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&root.join("CAPABILITIES"))
            .await
            .unwrap(),
        cap
    );
    assert_eq!(fs.0.ordinary_effects.load(Ordering::SeqCst), 0);
    remove(&root).await;
}

#[tokio::test]
async fn active_open_refuses_cap_replacement_and_unsafe_ancestry_after_range_read() {
    use std::os::unix::fs::PermissionsExt;

    for replacement in [true, false] {
        let bucket = fixture().await;
        let root = bucket.root().to_owned();
        let before = selected(&bucket).await;
        let cap = TokioLocalFs
            .read_nofollow(&root.join("CAPABILITIES"))
            .await
            .unwrap();
        let fs = ActiveFs::default();
        fs.0.replace_range_leaf.store(replacement, Ordering::SeqCst);
        fs.0.unsafe_range_parent
            .store(!replacement, Ordering::SeqCst);

        assert!(
            FileBucket::open(config(root.clone()), fs.clone(), TokioClock, Validator)
                .await
                .is_err()
        );
        assert_eq!(fs.0.ranges.load(Ordering::SeqCst), 1);
        if !replacement {
            TokioLocalFs
                .set_permissions_and_sync(&root, std::fs::Permissions::from_mode(0o700))
                .await
                .unwrap();
        }
        assert_eq!(
            TokioLocalFs
                .read_nofollow(&root.join("CAPABILITIES"))
                .await
                .unwrap(),
            cap
        );
        assert_eq!(selected(&bucket).await, before);
        assert_eq!(fs.0.ordinary_effects.load(Ordering::SeqCst), 0);
        remove(&root).await;
    }
}

#[tokio::test]
async fn active_open_missing_coordination_or_registration_creates_nothing() {
    for registration in [false, true] {
        let bucket = fixture().await;
        let root = bucket.root().to_owned();
        let missing = if registration {
            control_path(&root).join("backend-registration.cbor")
        } else {
            root.join(BucketKey::parse("CAPABILITIES").unwrap().lock_name())
        };
        tokio::fs::remove_file(&missing).await.unwrap();
        let fs = ActiveFs::default();

        assert!(
            FileBucket::open(config(root.clone()), fs.clone(), TokioClock, Validator)
                .await
                .is_err()
        );
        assert_eq!(
            TokioLocalFs
                .symlink_metadata(&missing)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(fs.0.ordinary_effects.load(Ordering::SeqCst), 0);
        assert_eq!(fs.0.retained_effects.load(Ordering::SeqCst), 0);
        assert_eq!(fs.0.ranges.load(Ordering::SeqCst), 0);
        remove(&root).await;
    }
}

#[tokio::test]
async fn active_open_unavailable_retention_refuses_before_repair_or_probe() {
    let bucket = fixture().await;
    let root = bucket.root().to_owned();
    let before = selected(&bucket).await;
    tokio::fs::write(root.join("CAPABILITIES"), b"repair remains pending")
        .await
        .unwrap();
    let fs = ActiveFs::default();
    fs.0.unavailable_retention.store(true, Ordering::SeqCst);

    let error = FileBucket::open(config(root.clone()), fs.clone(), TokioClock, Validator)
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(fs.0.ordinary_effects.load(Ordering::SeqCst), 0);
    assert_eq!(fs.0.retained_effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&root.join("CAPABILITIES"))
            .await
            .unwrap(),
        b"repair remains pending"
    );
    assert_eq!(selected(&bucket).await, before);
    remove(&root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_active_open_probe_retains_real_exclusion_until_worker_completion() {
    let bucket = fixture().await;
    let root = bucket.root().to_owned();
    let before = selected(&bucket).await;
    let fs = ActiveFs::default();
    let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *fs.0.gate.lock().unwrap() = Some(Gate {
        arrived: arrived_tx,
        release: release_rx,
    });
    let opening_root = root.clone();
    let opening = tokio::spawn(async move {
        FileBucket::open(config(opening_root), fs, TokioClock, Validator).await
    });
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || arrived_rx.recv().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();

    let lock = root.join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let mut competitor = tokio::spawn(async move {
        started_tx.send(()).unwrap();
        TokioLocalFs.lock_existing_exclusive(&lock).await.unwrap()
    });
    started_rx.await.unwrap();
    opening.abort();
    assert!(opening.await.err().unwrap().is_cancelled());
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let path = root.join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        let named = TokioLocalFs.symlink_metadata(&path).await.unwrap();
        let opened = contender.metadata().unwrap();
        assert_eq!((opened.dev(), opened.ino()), (named.dev(), named.ino()));
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut competitor)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    let guard = tokio::time::timeout(Duration::from_secs(30), competitor)
        .await
        .unwrap()
        .unwrap();
    drop(guard);
    assert_eq!(selected(&bucket).await, before);
    remove(&root).await;
}

#[tokio::test]
async fn active_probe_stale_whole_cap_preimage_refuses_a_valid_successor_without_effects() {
    let bucket = fixture().await;
    let root = bucket.root().to_owned();
    let fs = ActiveFs::default();
    let reopened = FileBucket::open(config(root.clone()), fs.clone(), TokioClock, Validator)
        .await
        .unwrap();
    let holder = SingleHeld::acquire(&reopened).await.unwrap();
    let destination = holder.destination();
    let observed = destination.observe_for_read().await.unwrap();
    let before = (observed.stamp(), observed.state().clone());
    let cap = projection::value(observed.logical(), "CAPABILITIES").unwrap();
    let mut stale = cap.to_vec();
    stale.push(0);
    let mut successor = projection::capabilities(observed.logical()).unwrap();
    successor.probed_at += 1;
    reopened.validate_layout(&successor).unwrap();
    let successor = successor.encode().unwrap();
    assert_ne!(successor, cap);
    assert!(BucketCapabilities::decode(&successor).is_ok());
    fs.0.ordinary_effects.store(0, Ordering::SeqCst);
    fs.0.retained_effects.store(0, Ordering::SeqCst);

    let error = destination
        .prepare_raw(
            &observed,
            vec![LogicalChange {
                key: "CAPABILITIES".into(),
                expected: Some(stale),
                new: Some(successor),
            }],
        )
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
    observed.revalidate().await.unwrap();
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&root.join("CAPABILITIES"))
            .await
            .unwrap(),
        cap
    );
    let next = control_path(&root).join(format!("publication/commits/{}", observed.stamp().0 + 1));
    assert_eq!(
        TokioLocalFs
            .symlink_metadata(&next)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(fs.0.ordinary_effects.load(Ordering::SeqCst), 0);
    assert_eq!(fs.0.retained_effects.load(Ordering::SeqCst), 0);
    drop(observed);
    drop(destination);
    drop(holder);
    assert_eq!(selected(&reopened).await, before);
    remove(&root).await;
}
