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

#[path = "test_fs/permanent.rs"]
mod permanent;

#[path = "test_fs/gc_proposal.rs"]
mod gc_proposal;

/// Selects real permanent native requests and their existing test boundaries.
pub(crate) use permanent::{PermanentBoundary, PermanentPhase};

#[derive(Default)]
struct State {
    effects: AtomicUsize,
    noop_pair: std::sync::atomic::AtomicBool,
    pack_seal_gate: Mutex<Option<(PathBuf, TestGate)>>,
    pack_seal_path: Mutex<Option<PathBuf>>,
    retirement_gate: Mutex<Option<(PathBuf, TestGate)>>,
    retirement: Mutex<Option<(RetirementPhase, Option<crate::store::EffectFault>, bool)>>,
    gate: Mutex<Option<(PathBuf, TestGate)>>,
    expire_after_sync: Mutex<Option<(PathBuf, TestClock)>>,
    forbidden_data_reads: Mutex<std::collections::BTreeSet<PathBuf>>,
    data_read_attempts: AtomicUsize,
    permanent: permanent::PermanentHooks,
    gc_proposal: gc_proposal::GcProposalHooks,
}

/// Selects an actual closed native retirement or Trash creator request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetirementPhase {
    /// Matches the selected exclusion durability worker.
    Barrier,
    /// Matches the protected Trash Pending durability worker.
    Pending,
    /// Matches the actual Trash descriptor seal worker.
    Artifact,
    /// Matches the actual protected Trash Committed worker.
    Commit,
}

/// Preserves the real native binding and its actual queued worker behavior.
#[derive(Clone, Default)]
pub(crate) struct TestFs {
    state: Arc<State>,
}

impl TestFs {
    /// Refuses reads of independently identified data-pack paths after setup.
    ///
    /// # Errors
    /// Reports poisoned fixture observation synchronization.
    pub(crate) fn forbid_data_body_reads(&self, paths: &[PathBuf]) -> std::io::Result<()> {
        *self
            .state
            .forbidden_data_reads
            .lock()
            .map_err(|_| std::io::Error::other("poisoned data-read observation"))? =
            paths.iter().cloned().collect();
        self.state.data_read_attempts.store(0, Ordering::SeqCst);
        Ok(())
    }

    /// Counts whole, ranged and nofollow read attempts on forbidden data packs.
    pub(crate) fn data_body_read_attempts(&self) -> usize {
        self.state.data_read_attempts.load(Ordering::SeqCst)
    }

    fn check_data_read(&self, path: &Path) -> std::io::Result<()> {
        if self
            .state
            .forbidden_data_reads
            .lock()
            .map_err(|_| std::io::Error::other("poisoned data-read observation"))?
            .contains(path)
        {
            self.state.data_read_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(std::io::Error::other("forbidden data-pack body read"));
        }
        Ok(())
    }

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

    /// Acknowledges the next pair request without native execution.
    pub(crate) fn noop_next_current_pair(&self) {
        self.state.noop_pair.store(true, Ordering::SeqCst);
    }

    /// Holds the actual pair worker at its open or bounded-read boundary.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned.
    pub(crate) fn pause_current_pair(
        &self,
        path: PathBuf,
        after_read: bool,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        self.pause(
            path,
            if after_read {
                TestGatePhase::AfterCurrentPairIndexRead
            } else {
                TestGatePhase::AfterOpen
            },
        )
    }

    /// Holds a subsequent retained effect after its actual root-directory sync.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned.
    pub(crate) fn pause_current_pair_root_sync(
        &self,
        path: PathBuf,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        self.pause(path, TestGatePhase::AfterDirectorySync)
    }

    /// Requires the registered native handoff to have actually been submitted.
    ///
    /// # Panics
    /// Panics for an unconsumed hook or poisoned fixture observation.
    pub(crate) fn assert_current_pair_hook_consumed(&self) {
        assert!(self.state.gate.lock().unwrap().is_none());
        assert!(!self.state.noop_pair.load(Ordering::SeqCst));
    }

    /// Holds the next canonical pack seal after its same-descriptor file sync.
    ///
    /// The actual native worker supplies the path. The hook leaves its Pending,
    /// artifact seal and final Committed result channels entirely unchanged.
    ///
    /// # Panics
    /// Panics if a previous hook is unconsumed or synchronization is poisoned.
    pub(crate) fn pause_next_pack_seal(
        &self,
        root: PathBuf,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, received) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let mut pending = self.state.pack_seal_gate.lock().unwrap();
        assert!(pending.is_none());
        *self.state.pack_seal_path.lock().unwrap() = None;
        *pending = Some((
            root,
            TestGate {
                phase: TestGatePhase::AfterSourceSync,
                arrived,
                release: released,
            },
        ));
        (received, release)
    }

    /// Returns the actual canonical pack path selected by the native seal hook.
    ///
    /// # Panics
    /// Panics if the hook has not been submitted or synchronization is poisoned.
    pub(crate) fn paused_pack_seal_path(&self) -> PathBuf {
        self.state.pack_seal_path.lock().unwrap().clone().unwrap()
    }

    /// Requires the next-pack hook to have selected an actual submitted seal.
    ///
    /// The witness separately waits for its native AfterSourceSync arrival.
    ///
    /// # Panics
    /// Panics for an unconsumed hook, absent selected path or poisoned observation.
    pub(crate) fn assert_pack_seal_hook_consumed(&self) {
        assert!(self.state.pack_seal_gate.lock().unwrap().is_none());
        assert!(self.state.pack_seal_path.lock().unwrap().is_some());
    }

    /// Holds only the actual barrier worker after its directory sync.
    ///
    /// # Panics
    /// Panics if an earlier barrier gate remains or synchronization is poisoned.
    pub(crate) fn pause_retirement_barrier(
        &self,
        path: PathBuf,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, received) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let mut gate = self.state.retirement_gate.lock().unwrap();
        assert!(gate.is_none());
        *gate = Some((
            path,
            TestGate {
                phase: TestGatePhase::AfterDirectorySync,
                arrived,
                release: released,
            },
        ));
        (received, release)
    }

    /// Makes one actual selected barrier callback return success without execution.
    ///
    /// # Panics
    /// Panics if a prior hook is unconsumed or synchronization is poisoned.
    pub(crate) fn noop_next_retirement_barrier(&self) {
        let mut hook = self.state.retirement.lock().unwrap();
        assert!(hook.is_none());
        *hook = Some((RetirementPhase::Barrier, None, false));
    }

    /// Injects one real worker fault, optionally swallowing its unit-return failure.
    ///
    /// # Panics
    /// Panics if a prior hook is unconsumed or synchronization is poisoned.
    pub(crate) fn fail_next_retirement(
        &self,
        phase: RetirementPhase,
        fault: crate::store::EffectFault,
        swallow: bool,
    ) {
        let mut hook = self.state.retirement.lock().unwrap();
        assert!(hook.is_none());
        *hook = Some((phase, Some(fault), swallow));
    }

    /// Requires the registered retirement fault to reach its actual worker.
    ///
    /// # Panics
    /// Panics if the hook was not consumed or observation is poisoned.
    pub(crate) fn assert_retirement_hook_consumed(&self) {
        assert!(self.state.retirement.lock().unwrap().is_none());
        assert!(self.state.retirement_gate.lock().unwrap().is_none());
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
        self.state.gc_proposal.prepare(&mut effect);
        let permanent = self.state.permanent.prepare(&mut effect);
        if matches!(
            effect.fault_probe(),
            crate::store::EffectFaultProbe::ObserveCurrentPair(_)
        ) && self.state.noop_pair.swap(false, Ordering::SeqCst)
        {
            return Ok(());
        }
        if let crate::store::EffectFaultProbe::SealArtifact(path) = effect.fault_probe() {
            let selected = {
                let mut pending = self.state.pack_seal_gate.lock().unwrap();
                let matches = pending.as_ref().is_some_and(|(root, _)| {
                    path.strip_prefix(root)
                        .ok()
                        .and_then(Path::to_str)
                        .is_some_and(|key| {
                            terrane_core::bucket::BucketKey::parse(key).is_ok()
                                && key.starts_with("objects/pack/")
                                && key.ends_with(".pack")
                        })
                });
                if matches {
                    *self.state.pack_seal_path.lock().unwrap() = Some(path.to_owned());
                    pending.take().map(|(_, gate)| gate)
                } else {
                    None
                }
            };
            if let Some(gate) = selected {
                effect.gates.push(gate);
            }
        }
        if let crate::store::EffectFaultProbe::SealRetirementBarrier(path) = effect.fault_probe() {
            let mut pending = self.state.retirement_gate.lock().unwrap();
            if pending
                .as_ref()
                .is_some_and(|(expected, _)| expected == path)
            {
                let (_, gate) = pending.take().unwrap();
                effect.gates.push(gate);
            }
        }
        let phase = match effect.fault_probe() {
            crate::store::EffectFaultProbe::SealRetirementBarrier(_) => {
                Some(RetirementPhase::Barrier)
            }
            crate::store::EffectFaultProbe::SealPendingCreation(_) => {
                Some(RetirementPhase::Pending)
            }
            crate::store::EffectFaultProbe::SealArtifact(_) => Some(RetirementPhase::Artifact),
            crate::store::EffectFaultProbe::CommitCreation(_) => Some(RetirementPhase::Commit),
            _ => None,
        };
        let hook = {
            let mut pending = self.state.retirement.lock().unwrap();
            if pending
                .as_ref()
                .is_some_and(|(expected, _, _)| Some(*expected) == phase)
            {
                pending.take()
            } else {
                None
            }
        };
        let mut swallow = false;
        if let Some((_, fault, swallow_failure)) = hook {
            match fault {
                Some(fault) => effect.faults.push(fault),
                None => return Ok(()),
            }
            swallow = swallow_failure;
        }
        let path = match effect.fault_probe() {
            crate::store::EffectFaultProbe::RenameNoReplace(path)
            | crate::store::EffectFaultProbe::DirectorySync(path)
            | crate::store::EffectFaultProbe::ObserveCurrentPair(path)
            | crate::store::EffectFaultProbe::SealRetirementBarrier(path) => Some(path),
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
        let result = if let Some((phase, path)) = permanent {
            // The observation task outlives a canceled waiter, just as the real
            // native worker does. It records completion only after that worker
            // returns; submission and gate arrival cannot stand in for it.
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                let result = TokioLocalFs.execute_retained_effect(effect).await;
                state.permanent.complete(phase, path, result.is_ok());
                result
            })
            .await
            .map_err(std::io::Error::other)?
        } else {
            TokioLocalFs.execute_retained_effect(effect).await
        };
        if swallow {
            let error = match result {
                Err(error) => error,
                Ok(()) => panic!("injected native retirement fault did not execute"),
            };
            assert!(
                error.to_string().contains("injected creation"),
                "unexpected swallowed native error: {error}"
            );
            return Ok(());
        }
        result?;
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
        self.check_data_read(path)?;
        TokioLocalFs.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        self.check_data_read(path)?;
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
        self.check_data_read(path)?;
        TokioLocalFs.read_nofollow(path).await
    }

    async fn list_xattrs(&self, path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
        TokioLocalFs.list_xattrs(path).await
    }

    async fn get_xattr(
        &self,
        path: &Path,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<Option<Vec<u8>>> {
        TokioLocalFs.get_xattr(path, name).await
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
