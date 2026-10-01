//! Intercepts only actual fixed bootstrap effects and forwards native reads.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture interception assertions intentionally panic."
)]

use super::super::super::super::{TestGate, TestGatePhase};
use crate::store::{
    ByteRange, EffectFaultProbe, LocalFs, NativeEffectFailure, NativeExclusion, NativeFsEffect,
    StoreErrorKind, StoreFailure, TokioFileLock, TokioLocalFs,
};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

pub(in super::super) enum Stop {
    BeforeSlot,
    AfterSlot,
}

pub(in super::super) struct Gate {
    pub(in super::super) arrived: std::sync::mpsc::Sender<()>,
    pub(in super::super) release: std::sync::mpsc::Receiver<()>,
}

#[derive(Default)]
struct State {
    stop: Mutex<Option<Stop>>,
    gate: Mutex<Option<Gate>>,
    ordinary_effects: AtomicUsize,
    wrong_range: AtomicBool,
    noop_probe: AtomicBool,
}

#[derive(Clone, Default)]
pub(in super::super) struct ProbeFs(Arc<State>);

impl ProbeFs {
    pub(in super::super) fn stop(&self, stop: Stop) {
        *self.0.stop.lock().unwrap() = Some(stop);
    }

    pub(in super::super) fn gate(&self, gate: Gate) {
        *self.0.gate.lock().unwrap() = Some(gate);
    }

    pub(in super::super) fn ordinary_effects(&self) -> usize {
        self.0.ordinary_effects.load(Ordering::SeqCst)
    }

    pub(in super::super) fn wrong_range(&self) {
        self.0.wrong_range.store(true, Ordering::SeqCst);
    }

    pub(in super::super) fn noop_probe(&self) {
        self.0.noop_probe.store(true, Ordering::SeqCst);
    }
}

fn unavailable() -> NativeEffectFailure {
    NativeEffectFailure::Rejected(StoreFailure::new(StoreErrorKind::Unavailable {
        retry_after: None,
    }))
}

#[async_trait::async_trait]
impl LocalFs for ProbeFs {
    type Lock = TokioFileLock;

    // The default initialization hook deliberately remains Unsupported.
    fn retain_native_exclusion(&self, held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        mut effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let is_slot = matches!(effect.fault_probe(), EffectFaultProbe::RenameNoReplace(to)
            if to.ends_with("publication/commits/0"));
        let is_activation = matches!(effect.fault_probe(), EffectFaultProbe::Rename(to)
            if to.file_name().is_some_and(|name| name == "backend-registration.cbor"));
        let stopped = matches!(*self.0.stop.lock().unwrap(), Some(Stop::BeforeSlot)) && is_slot
            || matches!(*self.0.stop.lock().unwrap(), Some(Stop::AfterSlot)) && is_activation;
        if stopped {
            return Err(unavailable());
        }
        if is_slot && let Some(Gate { arrived, release }) = self.0.gate.lock().unwrap().take() {
            effect.gates.push(TestGate {
                phase: TestGatePhase::BeforeChecks,
                arrived,
                release,
            });
        }
        if self.0.noop_probe.load(Ordering::SeqCst)
            && matches!(effect.fault_probe(), EffectFaultProbe::WriteNew(path)
                if path.file_name().is_some_and(|name| name == "CAPABILITIES"))
        {
            return Ok(());
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
        let mut bytes = TokioLocalFs.read_range(path, range).await?;
        if self.0.wrong_range.load(Ordering::SeqCst) {
            bytes.push(0);
        }
        Ok(bytes)
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

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_all(path).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.sync_directory(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }
}
