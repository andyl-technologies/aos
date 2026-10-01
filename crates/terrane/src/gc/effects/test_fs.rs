//! Pauses actual collector native workers without replacing their retained frames.

#![allow(
    clippy::unwrap_used,
    reason = "Bounded native fixture assertions intentionally panic."
)]

use super::super::super::{TestGate, TestGatePhase};
/// Exposes the actual test binding through its owning native descendant.
pub(crate) use crate::store::native_clock::gc_test_clock::TestClock;

use crate::store::{ByteRange, LocalFs, TokioLocalFs};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

#[derive(Default)]
struct State {
    effects: AtomicUsize,
    gate: Mutex<Option<(PathBuf, TestGate)>>,
    expire_after_sync: Mutex<Option<(PathBuf, TestClock)>>,
}

/// Preserves the real native binding and its actual queued worker behavior.
#[derive(Clone, Default)]
pub(crate) struct TestFs {
    state: Arc<State>,
}

impl TestFs {
    /// Counts genuine submitted effects since the last reset.
    pub(crate) fn effects(&self) -> usize {
        self.state.effects.load(Ordering::SeqCst)
    }

    /// Starts the zero-effect refusal observation after trusted fixture setup.
    pub(crate) fn reset(&self) {
        self.state.effects.store(0, Ordering::SeqCst);
    }

    /// Pauses the actual selected-slot worker before final checks.
    pub(crate) fn before_slot(&self, path: PathBuf) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        self.pause(path, TestGatePhase::BeforeChecks)
    }

    /// Pauses the actual selected-slot worker after rename and before directory sync.
    pub(crate) fn after_slot(&self, path: PathBuf) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        self.pause(path, TestGatePhase::AfterRename)
    }

    /// Advances the real injected clock after the actual final directory sync.
    pub(crate) fn expire_after_root_sync(&self, root: PathBuf, clock: TestClock) {
        *self.state.expire_after_sync.lock().unwrap() = Some((root, clock));
    }

    fn pause(&self, path: PathBuf, phase: TestGatePhase) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, received) = mpsc::channel();
        let (release, released) = mpsc::channel();
        *self.state.gate.lock().unwrap() = Some((
            path,
            TestGate {
                phase,
                arrived,
                release: released,
            },
        ));
        (received, release)
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for TestFs {
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
        mut effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        self.state.effects.fetch_add(1, Ordering::SeqCst);
        let path = match effect.fault_probe() {
            crate::store::EffectFaultProbe::RenameNoReplace(path) => Some(path),
            _ => None,
        };
        let gate = {
            let mut pending = self.state.gate.lock().unwrap();
            if pending
                .as_ref()
                .is_some_and(|(expected, _)| path == Some(expected.as_path()))
            {
                pending.take().map(|(_, gate)| gate)
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            effect.gates.push(gate);
        }
        let expire = {
            let mut pending = self.state.expire_after_sync.lock().unwrap();
            let root = match effect.fault_probe() {
                crate::store::EffectFaultProbe::DirectorySync(path) => Some(path),
                _ => None,
            };
            if pending
                .as_ref()
                .is_some_and(|(expected, _)| root == Some(expected.as_path()))
            {
                pending.take().map(|(_, clock)| clock)
            } else {
                None
            }
        };
        TokioLocalFs.execute_retained_effect(effect).await?;
        if let Some(clock) = expire {
            clock.set(120, 20);
        }
        Ok(())
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

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.state.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.state.effects.fetch_add(1, Ordering::SeqCst);
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

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        TokioLocalFs.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.state.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.state.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.state.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_nofollow(path).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        self.state.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_new(path).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        self.state.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }
}
