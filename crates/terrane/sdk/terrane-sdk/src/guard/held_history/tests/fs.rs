//! Observes and faults real filesystem reads without supplying authority.

use crate::store::{
    ByteRange, LocalFs, NativeEffectFailure, NativeExclusion, NativeFsEffect, NativeOrdinaryRead,
    NativeOrdinaryRecord, NativePayloadRangeRead, NativePayloadRangeRecord,
    NativePublicationInitialization, NativePublicationInitializationOutcome, StoreFailure,
    TokioFileLock, TokioLocalFs,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod native_ranges;

/// Forwards real native storage while observing scalar controls and native DATA.
#[derive(Clone, Default)]
pub(super) struct ReadFs {
    /// Records actual nofollow read attempts in their original order.
    pub(super) paths: Arc<Mutex<Vec<PathBuf>>>,
    /// Records only native DATA range attempts, excluding capture, probe and check.
    pub(super) native_paths: Arc<Mutex<Vec<PathBuf>>>,
    /// Pauses one genuine DATA range request before native forwarding.
    pub(super) pause: Arc<Mutex<Option<ReadPause>>>,
    /// Observes one genuine submitted closing worker before its physical checks.
    pub(super) projection_pause: Arc<Mutex<Option<ProjectionPause>>>,
    /// Makes a configured native optimization fail for one genuine path.
    pub(super) native_failure: Arc<Mutex<Option<PathBuf>>>,
    /// Injects one whole-body or incarnation failure at an actual read.
    pub(super) fault: Arc<Mutex<Option<(PathBuf, Fault)>>>,
}

/// Hands a caller the actual read boundary without supplying a successful result.
pub(super) struct ReadPause {
    /// Names the already observed real artifact.
    pub(super) target: PathBuf,
    /// Signals that the actual read reached the boundary.
    pub(super) entered: tokio::sync::oneshot::Sender<()>,
    /// Keeps that same read pending until the test releases it.
    pub(super) released: tokio::sync::oneshot::Receiver<()>,
}

/// Pauses only a submitted native projection while its worker owns exclusion.
pub(super) struct ProjectionPause {
    /// Signals entry from inside the actual blocking projection worker.
    pub(super) entered: tokio::sync::oneshot::Sender<()>,
    /// Releases that worker without modifying its recipe or checked result.
    pub(super) released: std::sync::mpsc::Receiver<()>,
}

/// Names adversarial changes applied only to isolated genuine fixture artifacts.
#[derive(Clone, Copy)]
pub(super) enum Fault {
    /// Preserves a real read error instead of treating it as native decline.
    Unavailable,
    /// Corrupts the actual whole file before genuine native capture.
    Corrupt,
    /// Installs equal bytes under a newly named leaf incarnation.
    ReplaceLeaf,
    /// Replaces the actual containing directory while preserving its contents.
    ReplaceParent,
}

impl ReadFs {
    /// Clears read attempts at a quiescent fixture boundary.
    ///
    /// # Panics
    /// Panics if the isolated observer mutex was poisoned.
    pub(super) fn reset(&self) {
        self.paths.lock().unwrap().clear();
        self.native_paths.lock().unwrap().clear();
    }

    /// Copies all observed actual read paths for independent assertions.
    ///
    /// # Panics
    /// Panics if the isolated observer mutex was poisoned.
    pub(super) fn paths(&self) -> Vec<PathBuf> {
        self.paths.lock().unwrap().clone()
    }

    /// Copies genuine native DATA range attempts without including capture or checks.
    ///
    /// # Panics
    /// Panics if the isolated native DATA observer mutex was poisoned.
    pub(super) fn native_paths(&self) -> Vec<PathBuf> {
        self.native_paths.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl LocalFs for ReadFs {
    type Lock = TokioFileLock;

    async fn read_ordinary_record(
        &self,
        mut read: NativeOrdinaryRead,
    ) -> std::io::Result<Option<NativeOrdinaryRecord>> {
        // Closing projections require the genuine native checked result. Ordinary
        // leaves retain scalar observations; native DATA uses its range observer.
        if read.path_for_test().is_none() {
            let pause = self.projection_pause.lock().unwrap().take();
            if let Some(pause) = pause {
                read.observe_projection_entry_for_test(move || {
                    let _ = pause.entered.send(());
                    let _ = pause.released.recv();
                })?;
            }
            return TokioLocalFs.read_ordinary_record(read).await;
        }

        if self
            .native_failure
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|target| read.path_for_test() == Some(target.as_path()))
        {
            return Err(std::io::Error::other(
                "configured native held reader failure",
            ));
        }
        Ok(None)
    }

    async fn read_payload_ranges(
        &self,
        request: NativePayloadRangeRead,
    ) -> std::io::Result<Option<NativePayloadRangeRecord>> {
        self.forward_native_ranges(request).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.paths.lock().unwrap().push(path.to_owned());
        TokioLocalFs.read_nofollow(path).await
    }

    async fn initialize_publication(
        &self,
        request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(&self, held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
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

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
        TokioLocalFs.read_link(path).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_new(path).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_file(path).await
    }

    async fn remove_dir(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_dir(path).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn sync_file_nofollow(
        &self,
        path: &Path,
        expected: &std::fs::Metadata,
    ) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.sync_file_nofollow(path, expected).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn hard_link(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.hard_link(from, to).await
    }

    async fn symlink(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.symlink(from, to).await
    }

    async fn set_permissions(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        TokioLocalFs.set_permissions(path, permissions).await
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
}
