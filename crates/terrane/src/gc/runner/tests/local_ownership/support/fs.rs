//! Observes real ownership workers and queues bounded native authority changes.

use super::super::super::{TestGate, TestGatePhase};
use super::*;
use crate::store::native_publication_effects::collection::test_fs::TestFs;
use crate::store::{ByteRange, EffectFault, EffectFaultProbe, LocalFs, NativeFsEffect};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn required<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("native observer failed: {error:?}"),
    }
}

/// Selects one actual closed worker without constructing its permission.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerSelection {
    /// Selects the real metadata-only triple observation.
    Triple,
    /// Selects one actual whole-lease acknowledgment by submission number.
    Renewal(usize),
    /// Selects the fixed Authorized, owner-journal or Invalidated boundary.
    Ownership(u8),
}

/// Selects an existing native effect handoff solely for fault observation.
#[derive(Clone, Copy)]
pub(crate) enum OwnershipPhase {
    /// Holds the checked worker immediately before its actual mutation.
    BeforeOpen,
    /// Holds the same-descriptor source sync before any directory effect.
    AfterSourceSync,
    /// Holds the actual directory effect immediately before its syscall.
    BeforeDirectorySync,
}

impl OwnershipPhase {
    fn native(self) -> TestGatePhase {
        match self {
            Self::BeforeOpen => TestGatePhase::BeforeOpen,
            Self::AfterSourceSync => TestGatePhase::AfterSourceSync,
            Self::BeforeDirectorySync => TestGatePhase::BeforeDirectorySync,
        }
    }
}

enum Hook {
    Fault(EffectFault),
    Gates(Vec<TestGate>),
}

struct ReadGate {
    arrived: mpsc::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

#[derive(Default)]
struct State {
    renewals: AtomicUsize,
    completed_renewals: AtomicUsize,
    triples: AtomicUsize,
    triple_paths: Mutex<Vec<PathBuf>>,
    ownership: Mutex<Vec<(u8, PathBuf)>>,
    hook: Mutex<Option<(WorkerSelection, Hook)>>,
    final_read: Mutex<Option<ReadGate>>,
    final_path: Mutex<Option<PathBuf>>,
}

/// Delegates every operation to the genuine native binding with finite observers.
#[derive(Clone)]
pub(crate) struct OwnershipFs {
    inner: TestFs,
    state: Arc<State>,
}

impl OwnershipFs {
    /// Retains the fixture's actual native executor and data-read fence.
    pub(crate) fn new(inner: TestFs) -> Self {
        Self {
            inner,
            state: Arc::new(State::default()),
        }
    }

    /// Counts actual submitted whole-lease acknowledgment workers.
    pub(crate) fn renewals(&self) -> usize {
        self.state.renewals.load(Ordering::SeqCst)
    }

    /// Counts actual successful whole-lease native worker completions.
    pub(crate) fn completed_renewals(&self) -> usize {
        self.state.completed_renewals.load(Ordering::SeqCst)
    }

    /// Counts actual submitted descriptor-triple workers.
    pub(crate) fn triples(&self) -> usize {
        self.state.triples.load(Ordering::SeqCst)
    }

    /// Copies the actual pack paths submitted to native triple observation.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned.
    pub(crate) fn triple_paths(&self) -> Vec<PathBuf> {
        required(self.state.triple_paths.lock()).clone()
    }

    /// Copies actual first-ownership boundary and destination observations.
    ///
    /// # Panics
    /// Panics if the finite observer is poisoned.
    pub(crate) fn ownership(&self) -> Vec<(u8, PathBuf)> {
        required(self.state.ownership.lock()).clone()
    }

    /// Registers one exact real native durability fault.
    ///
    /// # Panics
    /// Panics if another hook remains or the observer is poisoned.
    pub(crate) fn fault(&self, selection: WorkerSelection, fault: EffectFault) {
        self.install(selection, Hook::Fault(fault));
    }

    /// Pauses one actual worker at an existing native handoff.
    ///
    /// # Panics
    /// Panics if another hook remains or the observer is poisoned.
    pub(crate) fn pause(
        &self,
        selection: WorkerSelection,
        phase: OwnershipPhase,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, receiver) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        self.install(
            selection,
            Hook::Gates(vec![TestGate {
                phase: phase.native(),
                arrived,
                release: resume,
            }]),
        );
        (receiver, release)
    }

    /// Queues a second handoff which proves whether a later directory effect occurred.
    ///
    /// # Panics
    /// Panics if another hook remains or the observer is poisoned.
    pub(crate) fn pause_with_later_directory(
        &self,
        boundary: u8,
        phase: OwnershipPhase,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>, mpsc::Receiver<()>) {
        let (arrived, receiver) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let (later, later_receiver) = mpsc::channel();
        let (_later_release, later_resume) = mpsc::channel();
        self.install(
            WorkerSelection::Ownership(boundary),
            Hook::Gates(vec![
                TestGate {
                    phase: phase.native(),
                    arrived,
                    release: resume,
                },
                TestGate {
                    phase: TestGatePhase::AfterDirectorySync,
                    arrived: later,
                    release: later_resume,
                },
            ]),
        );
        (receiver, release, later_receiver)
    }

    /// Pauses the first actual Frame read after durable Invalidated acknowledgment.
    ///
    /// # Panics
    /// Panics if a final-read hook remains or the observer is poisoned.
    pub(crate) fn pause_final_read(
        &self,
    ) -> (mpsc::Receiver<()>, tokio::sync::oneshot::Sender<()>) {
        let (arrived, receiver) = mpsc::channel();
        let (release, resume) = tokio::sync::oneshot::channel();
        let mut pending = required(self.state.final_read.lock());
        assert!(pending.is_none());
        *pending = Some(ReadGate {
            arrived,
            release: resume,
        });
        (receiver, release)
    }

    fn install(&self, selection: WorkerSelection, hook: Hook) {
        let mut pending = required(self.state.hook.lock());
        assert!(pending.is_none());
        *pending = Some((selection, hook));
    }

    /// Requires the precise registered hook to have reached its genuine worker.
    ///
    /// # Panics
    /// Panics if any selected hook remains or the observer is poisoned.
    pub(crate) fn assert_consumed(&self) {
        assert!(required(self.state.hook.lock()).is_none());
        assert!(required(self.state.final_read.lock()).is_none());
    }

    /// Refuses actual data-pack body reads after independently identifying their paths.
    ///
    /// # Errors
    /// Reports poisoned native fixture observation.
    pub(crate) fn forbid_data_body_reads(&self, paths: &[PathBuf]) -> io::Result<()> {
        self.inner.forbid_data_body_reads(paths)
    }

    /// Counts attempts to read actual data-pack bodies.
    pub(crate) fn data_body_read_attempts(&self) -> usize {
        self.inner.data_body_read_attempts()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for OwnershipFs {
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
        let selection = match effect.fault_probe() {
            EffectFaultProbe::SealLeasePublication(_) => Some(WorkerSelection::Renewal(
                self.state.renewals.fetch_add(1, Ordering::SeqCst) + 1,
            )),
            EffectFaultProbe::ObserveLocalTriple(path) => {
                required(self.state.triple_paths.lock()).push(path.to_owned());
                self.state.triples.fetch_add(1, Ordering::SeqCst);
                Some(WorkerSelection::Triple)
            }
            EffectFaultProbe::LocalFirstOwnership(path, boundary) => {
                required(self.state.ownership.lock()).push((boundary, path.to_owned()));
                if boundary == 4 {
                    *required(self.state.final_path.lock()) = Some(path.to_owned());
                }
                Some(WorkerSelection::Ownership(boundary))
            }
            _ => None,
        };
        let hook = {
            let mut pending = required(self.state.hook.lock());
            if pending
                .as_ref()
                .is_some_and(|(expected, _)| Some(*expected) == selection)
            {
                pending.take().map(|(_, hook)| hook)
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            match hook {
                Hook::Fault(fault) => effect = effect.inject_test_faults(vec![fault]),
                Hook::Gates(gates) => effect.gates.extend(gates),
            }
        }
        let result = self.inner.execute_retained_effect(effect).await;
        if result.is_ok() && matches!(selection, Some(WorkerSelection::Renewal(_))) {
            self.state.completed_renewals.fetch_add(1, Ordering::SeqCst);
        }
        result
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
        let gate = {
            let matches = required(self.state.final_path.lock()).as_deref() == Some(path);
            if matches {
                required(self.state.final_read.lock()).take()
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            gate.arrived.send(()).map_err(io::Error::other)?;
            gate.release.await.map_err(io::Error::other)?;
        }
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
