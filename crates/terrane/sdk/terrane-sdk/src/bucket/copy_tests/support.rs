//! Shares real publication setup and byte-for-byte portable copy helpers.

use super::super::*;
use crate::ref_advance::{
    native_fixture::NativeFixture,
    tests::{Validator, fixture, request_file, token},
};
use crate::store::{
    ByteRange, NativeEffectFailure, NativeExclusion, NativeFsEffect,
    NativePublicationInitialization, NativePublicationInitializationOutcome, TokioClock,
    TokioFileLock, TokioLocalFs,
};
use std::collections::BTreeMap;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use terrane_format::gc::publication::{
    BackendBinding, PortableCurrent, PortableSnapshot, ProjectionEntry, SelectedHistory,
};
use terrane_format::refs::RefRecord;

/// Names the real native bucket used by copy fixtures.
pub(super) type Bucket = FileBucket<TokioLocalFs, TokioClock, Validator>;
/// Names the ordinary branch selected by the source publication.
pub(super) const NAME: &str = "refs/heads/tenant/main";
/// Supplies the exact chunk body retained by the source publication.
pub(super) const BODY: &[u8] = b"portable copy exact native body";

/// Creates a real repository publication with its selected commit and log.
///
/// # Panics
/// Panics if native fixture creation, authorization, or publication fails.
pub(super) async fn source() -> (NativeFixture<TokioLocalFs>, RefRecord) {
    let native = fixture().await;
    let mut session = native.begin(NAME, &token(), "sdk").await.unwrap();
    let head = native
        .advance(&mut session, request_file(Vec::new(), BODY))
        .await
        .unwrap();
    (native, head)
}

/// Copies the complete physical payload recursively without importing control.
///
/// # Panics
/// Panics if an enumerated directory or file cannot be copied.
pub(super) async fn copy_dir(source: &Path, destination: &Path) {
    let mut pending = vec![(source.to_owned(), destination.to_owned())];
    while let Some((source, target)) = pending.pop() {
        tokio::fs::create_dir_all(&target).await.unwrap();
        let mut entries = tokio::fs::read_dir(&source).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let output = target.join(entry.file_name());
            if entry.file_type().await.unwrap().is_dir() {
                pending.push((entry.path(), output));
            } else {
                tokio::fs::copy(entry.path(), output).await.unwrap();
            }
        }
    }
}

/// Creates an exact payload copy configured for independent destination control.
///
/// # Panics
/// Panics if entropy, configured control, or physical copying is unavailable.
pub(super) async fn destination(bucket: &Bucket) -> FileBucketConfig {
    let nonce = TokioLocalFs.random_bytes(16).await.unwrap();
    let tag: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut config = bucket.inner.config.clone();
    config.root = bucket.root().with_extension(format!("copy-{tag}"));
    config.publication_control.as_mut().unwrap().control = None;
    copy_dir(bucket.root(), &config.root).await;
    config
}

/// Resolves the configured destination-specific external control location.
///
/// # Panics
/// Panics if the fixture has missing or invalid publication configuration.
pub(super) fn control(config: &FileBucketConfig) -> PathBuf {
    super::super::publication::configured_location(
        &config.root,
        config.publication_control.as_ref().unwrap(),
    )
    .unwrap()
    .1
}

/// Runs the explicit native portable-copy initializer.
///
/// # Errors
/// Returns the initializer's exact closure, registration, or durability failure.
pub(super) async fn initialize(config: FileBucketConfig) -> Result<Bucket, StoreFailure> {
    FileBucket::initialize_portable_copy(config, TokioLocalFs, TokioClock, Validator).await
}

/// Runs ordinary open, including exact retained Pending recovery.
///
/// # Errors
/// Returns ordinary open's exact binding, recovery, or storage failure.
pub(super) async fn reopen(config: FileBucketConfig) -> Result<Bucket, StoreFailure> {
    FileBucket::open(config, TokioLocalFs, TokioClock, Validator).await
}

/// Reads the complete selected projection under real read-only exclusion.
///
/// # Panics
/// Panics if exclusion or the selected projection cannot be verified.
pub(super) async fn logical(bucket: &Bucket) -> BTreeMap<String, Option<Vec<u8>>> {
    let held = super::super::held::SingleHeld::acquire_read_only(bucket)
        .await
        .unwrap();
    held.destination()
        .observe_for_read()
        .await
        .unwrap()
        .logical()
        .clone()
}

/// Retains portable selected keys and records the logical source lease as absent.
///
/// # Panics
/// Panics if the source's selected projection cannot be read.
pub(super) async fn portable(bucket: &Bucket) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut values = logical(bucket).await;
    values.retain(|key, _| {
        matches!(
            key.as_str(),
            "CAPABILITIES" | "publication/SELECTED-HISTORY" | "gc/lease"
        ) || key.starts_with("objects/index/")
            || key.starts_with("refs/")
    });
    values.insert("gc/lease".into(), None);
    values
}

/// Encodes an independent complete ordinary checkpoint for isolated data cases.
///
/// # Panics
/// Panics if entropy, canonical encoding, or either physical write fails.
pub(super) async fn checkpoint(
    root: &Path,
    logical: &BTreeMap<String, Option<Vec<u8>>>,
    origin: BackendBinding,
    revision: u64,
) -> PortableCurrent {
    let nonce = TokioLocalFs.random_bytes(32).await.unwrap();
    let tag: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let bytes = PortableSnapshot {
        revision,
        origin,
        predecessor: None,
        projection: logical
            .iter()
            .map(|(key, value)| ProjectionEntry {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
    }
    .encode()
    .unwrap();
    let pointer = PortableCurrent {
        key: format!("publication/snapshots/{revision}:{tag}"),
        digest: *blake3::hash(&bytes).as_bytes(),
    };
    tokio::fs::write(root.join(&pointer.key), bytes)
        .await
        .unwrap();
    tokio::fs::write(root.join("publication/PORTABLE"), pointer.encode().unwrap())
        .await
        .unwrap();
    pointer
}

/// Extracts the exact source origin from selected-history bytes.
///
/// # Panics
/// Panics if the projection lacks valid present selected-history bytes.
pub(super) fn origin(logical: &BTreeMap<String, Option<Vec<u8>>>) -> BackendBinding {
    SelectedHistory::decode(logical["publication/SELECTED-HISTORY"].as_deref().unwrap())
        .unwrap()
        .origin
}

/// Removes the completed fixture's payload and independent external control.
///
/// # Panics
/// Panics if configured paths cannot be resolved or removed.
pub(super) async fn remove(config: &FileBucketConfig) {
    tokio::fs::remove_dir_all(&config.root).await.unwrap();
    let path = control(config);
    if path.exists() {
        tokio::fs::remove_dir_all(path).await.unwrap();
    }
}

#[derive(Default)]
struct State {
    reads: Mutex<Vec<PathBuf>>,
    temporary_paths: Mutex<Vec<PathBuf>>,
    effects: AtomicUsize,
    unavailable: Mutex<Option<PathBuf>>,
    retention: AtomicBool,
    changed: Mutex<Option<(PathBuf, Vec<u8>, usize)>>,
    fault: Mutex<Option<(PathBuf, bool)>>,
}

/// Tracks exact native reads and effects while injecting isolated fixture failures.
#[derive(Clone, Default)]
pub(super) struct ReadFs(Arc<State>);

impl ReadFs {
    /// Makes the exact configured read return a typed physical unavailability.
    ///
    /// # Panics
    /// Panics if fixture synchronization was poisoned.
    pub(super) fn unavailable(&self, path: PathBuf) {
        *self.0.unavailable.lock().unwrap() = Some(path);
    }

    /// Refuses native receipt retention before any initializer effect.
    pub(super) fn deny_retention(&self) {
        self.0.retention.store(true, Ordering::SeqCst);
    }

    /// Changes physical bytes after returning their first original read.
    ///
    /// # Panics
    /// Panics if fixture synchronization was poisoned.
    pub(super) fn change_after_read(&self, path: PathBuf, bytes: Vec<u8>) {
        self.change_after_read_number(path, bytes, 1);
    }

    /// Changes physical bytes after the exact numbered read returns its preimage.
    ///
    /// # Panics
    /// Panics if fixture synchronization was poisoned.
    pub(super) fn change_after_read_number(
        &self,
        path: PathBuf,
        bytes: Vec<u8>,
        occurrence: usize,
    ) {
        *self.0.changed.lock().unwrap() = Some((path, bytes, occurrence));
    }

    /// Fails the exact rename before application or before its directory sync.
    ///
    /// # Panics
    /// Panics if fixture synchronization was poisoned.
    pub(super) fn fault(&self, path: PathBuf, after: bool) {
        *self.0.fault.lock().unwrap() = Some((path, after));
    }

    /// Counts actual submitted effects independently of recorded reads.
    pub(super) fn effects(&self) -> usize {
        self.0.effects.load(Ordering::SeqCst)
    }

    /// Returns every actual complete read, preserving order and duplicates.
    ///
    /// # Panics
    /// Panics if fixture synchronization was poisoned.
    pub(super) fn reads(&self) -> Vec<PathBuf> {
        self.0.reads.lock().unwrap().clone()
    }

    /// Returns temporary names from real retained create-new effects.
    ///
    /// # Panics
    /// Panics if fixture synchronization was poisoned.
    pub(super) fn temporary_paths(&self) -> Vec<PathBuf> {
        self.0.temporary_paths.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl LocalFs for ReadFs {
    type Lock = TokioFileLock;

    async fn initialize_publication(
        &self,
        request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(&self, held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        if self.0.retention.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "fixture retention unavailable",
            ));
        }
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        mut effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        self.0.effects.fetch_add(1, Ordering::SeqCst);
        if let crate::store::EffectFaultProbe::WriteNew(path) = effect.fault_probe()
            && path
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().starts_with(b".terrane-tmp:"))
        {
            self.0.temporary_paths.lock().unwrap().push(path.to_owned());
        }
        let fault = {
            let mut fault = self.0.fault.lock().unwrap();
            let target = match effect.fault_probe() {
                crate::store::EffectFaultProbe::Rename(path)
                | crate::store::EffectFaultProbe::RenameNoReplace(path) => Some(path),
                _ => None,
            };
            if fault
                .as_ref()
                .is_some_and(|(path, _)| target == Some(path.as_path()))
            {
                fault.take()
            } else {
                None
            }
        };
        if let Some((_, after)) = fault {
            if !after {
                return Err(std::io::Error::other("fixture before exact projection rename").into());
            }
            effect =
                effect.inject_test_faults(vec![crate::store::EffectFault::BeforeDirectorySync]);
        }
        TokioLocalFs.execute_retained_effect(effect).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.read_nofollow(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        let occurrence = {
            let mut reads = self.0.reads.lock().unwrap();
            reads.push(path.to_owned());
            reads.iter().filter(|read| read.as_path() == path).count()
        };
        if self.0.unavailable.lock().unwrap().as_deref() == Some(path) {
            return Err(std::io::Error::other("fixture exact read unavailable"));
        }
        let bytes = TokioLocalFs.read_nofollow(path).await?;
        let change = {
            let mut changed = self.0.changed.lock().unwrap();
            if changed
                .as_ref()
                .is_some_and(|(target, _, selected)| target == path && *selected == occurrence)
            {
                changed.take()
            } else {
                None
            }
        };
        if let Some((target, replacement, _)) = change {
            tokio::fs::write(target, replacement).await?;
        }
        Ok(bytes)
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_exclusive(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.0.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.0.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_all(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        panic!("copy acquisition must not list {}", path.display());
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.0.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.sync_directory(path).await
    }
}
