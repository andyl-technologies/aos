//! Supplies operation-local counters and scalar fault boundaries for file reads.

#![allow(clippy::unwrap_used, reason = "fixture failures are test assertions")]

use crate::bucket::{FileBucket, Inner};
use crate::store::{ByteRange, LocalFs, TokioClock, TokioLocalFs};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

/// Selects the binding result without selecting another backend.
#[derive(Clone, Copy)]
pub(super) enum Mode {
    /// Executes the actual native recipe.
    Native,
    /// Returns unsupported optimization without filesystem I/O.
    Scalar,
    /// Returns the supported hook error without scalar retry.
    Error(std::io::ErrorKind),
}

/// Names the scalar observation boundary that retains its injected error.
#[derive(Clone, Copy)]
pub(super) enum Fault {
    /// Leaves scalar observations unchanged.
    None,
    /// Fails the scalar named-before metadata observation.
    Before(std::io::ErrorKind),
    /// Fails the scalar complete-body read.
    Body(std::io::ErrorKind),
    /// Fails the scalar named-after metadata observation.
    After(std::io::ErrorKind),
    /// Returns too few parent observations.
    ShortBatch,
    /// Fails the last parent after earlier real observations.
    LaterParent(std::io::ErrorKind),
}

/// Counts actual optimization and scalar boundaries independently.
pub(super) struct Probe {
    /// Selects native execution or an explicit scalar/error result.
    pub(super) mode: Mode,
    /// Retains the scalar fault boundary for this operation.
    pub(super) fault: Fault,
    /// Counts supported hook attempts, including explicit errors.
    pub(super) hooks: AtomicUsize,
    /// Counts scalar named metadata observations.
    pub(super) leaves: AtomicUsize,
    /// Counts scalar complete-body attempts.
    pub(super) bodies: AtomicUsize,
    /// Counts caller parent batches.
    pub(super) batches: AtomicUsize,
    /// Retains one physical parent replacement after the named whole read.
    pub(super) change_parent: Mutex<Option<(PathBuf, PathBuf, PathBuf)>>,
}

impl Probe {
    /// Constructs zeroed operation-local counters and immutable fault policy.
    pub(super) fn new(mode: Mode, fault: Fault) -> Self {
        Self {
            mode,
            fault,
            hooks: AtomicUsize::new(0),
            leaves: AtomicUsize::new(0),
            bodies: AtomicUsize::new(0),
            batches: AtomicUsize::new(0),
            change_parent: Mutex::new(None),
        }
    }

    /// Snapshots the parent, hook, leaf and scalar-body counts in that order.
    pub(super) fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.batches.load(Ordering::SeqCst),
            self.hooks.load(Ordering::SeqCst),
            self.leaves.load(Ordering::SeqCst),
            self.bodies.load(Ordering::SeqCst),
        )
    }
}

/// Combines operation-local probes with the real bucket validator and clock.
pub(super) type Bucket = FileBucket<Probe, TokioClock, crate::bucket::tests::Validator>;

/// Borrows an initialized namespace through an independent probing binding.
pub(super) fn bucket(source: &crate::bucket::tests::Bucket, mode: Mode, fault: Fault) -> Bucket {
    FileBucket {
        inner: Arc::new(Inner {
            config: source.inner.config.clone(),
            fs: Probe::new(mode, fault),
            clock: TokioClock,
            validator: crate::bucket::tests::Validator,
            capabilities: source.inner.capabilities.clone(),
            access: source.inner.access,
            content_observation: Arc::default(),
        }),
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for Probe {
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
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        TokioLocalFs.execute_retained_effect(effect).await
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

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.bodies.fetch_add(1, Ordering::SeqCst);
        if let Fault::Body(kind) = self.fault {
            return Err(std::io::Error::from(kind));
        }
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_ordinary_record(
        &self,
        read: crate::store::NativeOrdinaryRead,
    ) -> std::io::Result<Option<crate::store::NativeOrdinaryRecord>> {
        self.hooks.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            Mode::Native => {
                let path = read.path_for_test().map(Path::to_owned);
                let record = TokioLocalFs.read_ordinary_record(read).await?;
                let mut change = self.change_parent.lock().unwrap();
                if change
                    .as_ref()
                    .is_some_and(|(leaf, _, _)| Some(leaf) == path.as_ref())
                {
                    let (_, parent, moved) = change.take().unwrap();
                    std::fs::rename(&parent, &moved)?;
                    std::os::unix::fs::symlink(&moved, &parent)?;
                }
                Ok(record)
            }
            Mode::Scalar => Ok(None),
            Mode::Error(kind) => Err(std::io::Error::from(kind)),
        }
    }

    async fn read_protected_record(
        &self,
        read: crate::store::NativeProtectedRead,
    ) -> Result<Option<crate::store::NativeProtectedRecord>, crate::store::StoreFailure> {
        TokioLocalFs.read_protected_record(read).await
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

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        let observation = self.leaves.fetch_add(1, Ordering::SeqCst);
        match self.fault {
            Fault::Before(kind) if observation == 0 => return Err(std::io::Error::from(kind)),
            Fault::After(kind) if observation == 1 => return Err(std::io::Error::from(kind)),
            _ => {}
        }
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        self.batches.fetch_add(1, Ordering::SeqCst);
        if matches!(self.fault, Fault::ShortBatch) {
            return Ok(Vec::new());
        }
        let mut observations = TokioLocalFs.symlink_metadata_batch(paths).await?;
        if let Fault::LaterParent(kind) = self.fault {
            *observations.last_mut().unwrap() = Err(std::io::Error::from(kind));
        }
        Ok(observations)
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

/// Preserves the actual trait default without forwarding the optimization.
pub(super) struct DefaultFs(
    /// Retains scalar interceptions without implementing the ordinary hook.
    pub(super) Probe,
);

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for DefaultFs {
    type Lock = crate::store::TokioFileLock;

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        self.0.initialize_publication(request).await
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        self.0.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        self.0.execute_retained_effect(effect).await
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        self.0.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.0.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.0.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.0.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.0.try_lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.0.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.0.read_nofollow(path).await
    }

    async fn read_protected_record(
        &self,
        read: crate::store::NativeProtectedRead,
    ) -> Result<Option<crate::store::NativeProtectedRecord>, crate::store::StoreFailure> {
        self.0.read_protected_record(read).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        self.0.read_range(path, range).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.0.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.0.create_dir_all(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        self.0.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.0.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.0.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        self.0.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.0.sync_directory(path).await
    }
}
