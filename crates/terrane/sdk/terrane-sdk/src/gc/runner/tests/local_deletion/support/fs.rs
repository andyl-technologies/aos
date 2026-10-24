//! Delegates real native effects with finite phase-targeted fault observation.

use super::super::{TestGate, TestGatePhase};
use crate::store::native_publication_effects::collection::test_fs::TestFs;
use crate::store::{
    ByteRange, EffectFault, EffectFaultProbe, LocalFs, NativeEffectFailure, NativeFsEffect,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use terrane_format::gc::DeletePhase;

fn required<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("native deletion observer failed: {error:?}"),
    }
}

/// Selects an existing native syscall handoff solely for fault observation.
#[derive(Clone, Copy)]
pub(crate) enum DeletionBoundary {
    /// Queues immediately before the actual mutation.
    BeforeOpen,
    /// Queues after same-descriptor source synchronization.
    AfterSourceSync,
    /// Queues immediately before directory synchronization.
    BeforeDirectorySync,
    /// Queues after actual directory synchronization.
    AfterDirectorySync,
}

impl DeletionBoundary {
    fn native(self) -> TestGatePhase {
        match self {
            Self::BeforeOpen => TestGatePhase::BeforeOpen,
            Self::AfterSourceSync => TestGatePhase::AfterSourceSync,
            Self::BeforeDirectorySync => TestGatePhase::BeforeDirectorySync,
            Self::AfterDirectorySync => TestGatePhase::AfterDirectorySync,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Selection {
    Deletion(DeletePhase),
    FirstOwnership(u8),
}

enum Hook {
    Fault(EffectFault),
    Gate(TestGate),
    Noop,
    Swallow(EffectFault),
}

#[derive(Default)]
struct State {
    submitted: Mutex<Vec<(DeletePhase, PathBuf)>>,
    completed: Mutex<Vec<DeletePhase>>,
    hook: Mutex<Option<(Selection, Hook)>>,
}

/// Retains the genuine native binding with a finite actual phase observer.
#[derive(Clone)]
pub(crate) struct DeletionFs {
    inner: TestFs,
    state: Arc<State>,
}

impl DeletionFs {
    /// Retains the fixture's unchanged real filesystem executor.
    pub(crate) fn new(inner: TestFs) -> Self {
        Self {
            inner,
            state: Arc::new(State::default()),
        }
    }

    /// Registers failure at one actual native phase.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned or its hook invariant fails.
    pub(crate) fn fault(&self, phase: DeletePhase, fault: EffectFault) {
        assert!(
            required(self.state.hook.lock())
                .replace((Selection::Deletion(phase), Hook::Fault(fault)))
                .is_none()
        );
    }

    /// Registers a real first-ownership sync failure at its existing boundary.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned or its hook invariant fails.
    pub(crate) fn fault_first_ownership(&self, boundary: u8, fault: EffectFault) {
        assert!(
            required(self.state.hook.lock())
                .replace((Selection::FirstOwnership(boundary), Hook::Fault(fault)))
                .is_none()
        );
    }

    /// Registers faulty unit success without executing the selected native phase.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned or its hook invariant fails.
    pub(crate) fn noop(&self, phase: DeletePhase) {
        assert!(
            required(self.state.hook.lock())
                .replace((Selection::Deletion(phase), Hook::Noop))
                .is_none()
        );
    }

    /// Registers a wrapper swallowing one genuine executor I/O failure.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned or its hook invariant fails.
    pub(crate) fn swallow(&self, phase: DeletePhase, fault: EffectFault) {
        assert!(
            required(self.state.hook.lock())
                .replace((Selection::Deletion(phase), Hook::Swallow(fault)))
                .is_none()
        );
    }

    /// Queues one genuine native worker at an existing syscall handoff.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned or its hook invariant fails.
    pub(crate) fn pause(
        &self,
        phase: DeletePhase,
        boundary: DeletionBoundary,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, arrival) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let gate = TestGate {
            phase: boundary.native(),
            arrived,
            release: released,
        };
        assert!(
            required(self.state.hook.lock())
                .replace((Selection::Deletion(phase), Hook::Gate(gate)))
                .is_none()
        );
        (arrival, release)
    }

    /// Copies actual submitted native phase and protected operation paths.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned or its hook invariant fails.
    pub(crate) fn submitted(&self) -> Vec<(DeletePhase, PathBuf)> {
        required(self.state.submitted.lock()).clone()
    }

    /// Copies actual successfully returned native phases.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned or its hook invariant fails.
    pub(crate) fn completed(&self) -> Vec<DeletePhase> {
        required(self.state.completed.lock()).clone()
    }

    /// Requires the precise selected real worker to have consumed its hook.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned or its hook invariant fails.
    pub(crate) fn assert_consumed(&self) {
        assert!(required(self.state.hook.lock()).is_none());
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for DeletionFs {
    type Lock = crate::store::TokioFileLock;

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        self.inner.initialize_publication(request).await
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        self.inner.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        mut effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let selected = match effect.fault_probe() {
            EffectFaultProbe::LocalDeletion(path, phase) => {
                required(self.state.submitted.lock()).push((phase, path.to_owned()));
                Some(Selection::Deletion(phase))
            }
            EffectFaultProbe::LocalFirstOwnership(_, boundary) => {
                Some(Selection::FirstOwnership(boundary))
            }
            _ => None,
        };
        let hook = {
            let mut pending = required(self.state.hook.lock());
            if pending
                .as_ref()
                .is_some_and(|(phase, _)| Some(*phase) == selected)
            {
                pending.take().map(|(_, hook)| hook)
            } else {
                None
            }
        };
        let mut swallow = None;
        match hook {
            Some(Hook::Fault(fault)) => effect = effect.inject_test_faults(vec![fault]),
            Some(Hook::Gate(gate)) => effect.gates.push(gate),
            Some(Hook::Noop) => return Ok(()),
            Some(Hook::Swallow(fault)) => {
                let expected = match fault {
                    EffectFault::BeforeFileSync => "injected creation file sync failure",
                    _ => panic!("swallowed failure lacks an exact registered source oracle"),
                };
                effect = effect.inject_test_faults(vec![fault]);
                swallow = Some(expected);
            }
            None => {}
        }
        let result = self.inner.execute_retained_effect(effect).await;
        if result.is_ok()
            && let Some(Selection::Deletion(phase)) = selected
        {
            required(self.state.completed.lock()).push(phase);
        }
        if let Some(expected) = swallow {
            match result {
                Err(NativeEffectFailure::Io(error)) => assert_eq!(error.to_string(), expected),
                other => panic!("expected the exact injected native I/O failure: {other:?}"),
            }
            Ok(())
        } else {
            result
        }
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        self.inner.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.inner.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.inner.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.inner.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.inner.try_lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.inner.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        self.inner.read_range(path, range).await
    }

    async fn read_payload_ranges(
        &self,
        request: crate::store::NativePayloadRangeRead,
    ) -> std::io::Result<Option<crate::store::NativePayloadRangeRecord>> {
        // Keep the inner fixture's body-read trap on both reads and closing
        // replays without changing the sealed native request or error source.
        self.inner.read_payload_ranges(request).await
    }

    async fn read_ordinary_record(
        &self,
        read: crate::store::NativeOrdinaryRead,
    ) -> std::io::Result<Option<crate::store::NativeOrdinaryRecord>> {
        // Ordinary leaves retain scalar observation hooks. Physical closing
        // projections must execute their original native descriptor checks.
        if read.path_for_test().is_some() {
            return Ok(None);
        }

        self.inner.read_ordinary_record(read).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.inner.create_dir_all(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        self.inner.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.inner.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.inner.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        self.inner.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.inner.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.inner.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.inner.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.inner.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.inner.sync_directory(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.inner.read_nofollow(path).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        self.inner.create_dir_new(path).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        self.inner.set_permissions_and_sync(path, permissions).await
    }
}
