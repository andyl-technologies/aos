//! Forwards real native effects and intercepts only finite observation/failure boundaries.

use super::support::required;
use crate::store::{
    ByteRange, EffectFault, EffectFaultProbe, LocalFs, NativeEffectFailure, NativeFsEffect,
    NativePublicationInitialization, NativePublicationInitializationOutcome, StoreFailure,
    TokioFileLock, TokioLocalFs,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, mpsc},
};
use terrane_format::gc::{CreationJournal, JournalState};

/// Selects one fault in the actual final Raw acknowledgment worker.
pub(super) enum RawMode {
    /// Executes all real native synchronization and refresh operations.
    Real,
    /// Models a binding returning unit success without executing this fixed request.
    Noop,
    /// Executes the real worker and swallows its actual injected failure.
    Swallow(EffectFault),
    /// Pauses at the actual native before-directory-sync boundary.
    Pause(mpsc::Sender<()>, mpsc::Receiver<()>, mpsc::Sender<()>),
}

/// Reports only observations actually made at this adapter's named boundaries.
#[derive(Clone, Debug, Default)]
pub(super) struct Observations {
    /// Counts actual submitted Raw acknowledgment requests.
    pub(super) raw: usize,
    /// Records actual submitted Raw selecting slots before native execution.
    pub(super) raw_slots: Vec<PathBuf>,
    /// Records Pending bytes after the native Pending synchronization succeeds.
    pub(super) pending: Vec<(PathBuf, CreationJournal)>,
    /// Records Committed bytes after the native creation acknowledgment succeeds.
    pub(super) committed: Vec<(PathBuf, CreationJournal)>,
    /// Counts artifact staging writes preceded by actual protected Pending bytes.
    pub(super) artifact_writes: usize,
    /// Records an actual swallowed worker error, rather than wrapper selection alone.
    pub(super) swallowed: Vec<String>,
    /// Counts exact injected nofollow-read errors returned by this adapter.
    pub(super) unavailable_reads: usize,
    /// Records actual lengths successfully returned by native secure entropy.
    pub(super) entropy_lengths: Vec<usize>,
}

#[derive(Default)]
struct State {
    mode: Option<RawMode>,
    unavailable: Option<PathBuf>,
    observations: Observations,
}

/// Shares finite fixture controls while retaining real native locks and worker execution.
#[derive(Clone, Default)]
pub(super) struct ProbeFs(Arc<Mutex<State>>);

impl ProbeFs {
    fn state(&self) -> MutexGuard<'_, State> {
        match self.0.lock() {
            Ok(state) => state,
            Err(error) => panic!("fixture state poisoned: {error}"),
        }
    }

    /// Resets observations after setup, without changing native backend state.
    ///
    /// # Panics
    /// Panics when another fixture operation poisoned its shared state.
    pub(super) fn reset(&self) {
        *self.state() = State::default();
    }

    /// Installs one finite strategy for the next actual Raw acknowledgment request.
    ///
    /// # Panics
    /// Panics on poisoned state or an unconsumed earlier strategy.
    pub(super) fn arm(&self, mode: RawMode) {
        let mut state = self.state();
        assert!(state.mode.is_none(), "unconsumed Raw strategy");
        state.mode = Some(mode);
    }

    /// Makes one exact artifact's nofollow read genuinely unavailable to the caller.
    ///
    /// # Panics
    /// Panics on poisoned fixture state.
    pub(super) fn unavailable(&self, path: PathBuf) {
        self.state().unavailable = Some(path);
    }

    /// Checks strategy consumption and returns the actual adapter observations.
    ///
    /// # Panics
    /// Panics on an unconsumed registered strategy or poisoned state.
    pub(super) fn observations(&self) -> Observations {
        let state = self.state();
        assert!(state.mode.is_none(), "registered Raw hook never executed");
        state.observations.clone()
    }
}

#[async_trait::async_trait]
impl LocalFs for ProbeFs {
    type Lock = TokioFileLock;

    async fn initialize_publication(
        &self,
        request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> io::Result<crate::store::NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let (raw_slot, pending, committed, artifact_write) = match effect.fault_probe() {
            EffectFaultProbe::SealRawPublication(path) => (Some(path.to_owned()), None, None, None),
            EffectFaultProbe::SealPendingCreation(path) => {
                (None, Some(path.to_owned()), None, None)
            }
            EffectFaultProbe::CommitCreation(path) => (None, None, Some(path.to_owned()), None),
            EffectFaultProbe::WriteNew(path)
                if path.to_string_lossy().contains("/objects/pack/") =>
            {
                (None, None, None, Some(path.to_owned()))
            }
            _ => (None, None, None, None),
        };
        if let Some(path) = artifact_write {
            let pending = self.state().observations.pending.clone();
            let selected = pending.iter().any(|(journal_path, old)| {
                let bytes = required(std::fs::read(journal_path));
                let current = required(CreationJournal::decode(&bytes));
                current.key == old.key
                    && current.nonce == old.nonce
                    && matches!(current.state, JournalState::Pending)
                    && path.parent().is_some_and(|parent| {
                        parent.ends_with(required(
                            Path::new(&current.key).parent().ok_or("artifact parent"),
                        ))
                    })
            });
            assert!(
                selected,
                "artifact staging write lacks actual synchronized Pending"
            );
            self.state().observations.artifact_writes += 1;
        }
        let mode = if let Some(path) = raw_slot {
            let mut state = self.state();
            state.observations.raw += 1;
            state.observations.raw_slots.push(path);
            state.mode.take()
        } else {
            None
        };
        match mode {
            Some(RawMode::Noop) => return Ok(()),
            Some(RawMode::Swallow(fault)) => {
                let expected = match &fault {
                    EffectFault::BeforeFileSync => "injected creation file sync failure",
                    EffectFault::AfterFileSync => "injected creation failure after file sync",
                    EffectFault::BeforeDirectorySyncAt(_) => {
                        "injected creation directory sync failure"
                    }
                    EffectFault::AfterDirectorySyncAt(_) => {
                        "injected creation failure after directory sync"
                    }
                    _ => panic!("unsupported finite Raw sync fault"),
                };
                let outcome = TokioLocalFs
                    .execute_retained_effect(effect.inject_test_faults(vec![fault]))
                    .await;
                let error = match outcome {
                    Err(error) => error,
                    Ok(()) => panic!("registered inner sync fault did not fire"),
                };
                match &error {
                    NativeEffectFailure::Io(cause) => {
                        assert_eq!(cause.kind(), io::ErrorKind::Other);
                        assert_eq!(
                            cause.to_string(),
                            expected,
                            "registered inner fault was not reached"
                        );
                    }
                    NativeEffectFailure::Rejected(cause) => {
                        panic!("unrelated producer refusal before fault: {cause:?}");
                    }
                }
                self.state().observations.swallowed.push(error.to_string());
                return Ok(());
            }
            Some(RawMode::Pause(before, release, after)) => {
                return TokioLocalFs
                    .execute_retained_effect(
                        effect.test_directory_sync_handoff(before, release, after),
                    )
                    .await;
            }
            Some(RawMode::Real) | None => {}
        }
        TokioLocalFs.execute_retained_effect(effect).await?;
        if let Some(path) = pending {
            let journal = required(CreationJournal::decode(&required(std::fs::read(&path))));
            assert!(matches!(journal.state, JournalState::Pending));
            self.state().observations.pending.push((path, journal));
        }
        if let Some(path) = committed {
            let journal = required(CreationJournal::decode(&required(std::fs::read(&path))));
            assert!(matches!(journal.state, JournalState::Committed { .. }));
            self.state().observations.committed.push((path, journal));
        }
        Ok(())
    }

    async fn read_nofollow(&self, path: &Path) -> io::Result<Vec<u8>> {
        let unavailable = self.state().unavailable.as_deref() == Some(path);
        if unavailable {
            self.state().observations.unavailable_reads += 1;
            return Err(io::Error::other(
                "missing-placement fixture exact nofollow read unavailable",
            ));
        }
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_payload_ranges(
        &self,
        request: crate::store::NativePayloadRangeRead,
    ) -> io::Result<Option<crate::store::NativePayloadRangeRecord>> {
        // Native retained readers must keep the same unavailable-artifact hook
        // as scalar reads, including fresh closing checks of consumed ranges.
        let unavailable = {
            let mut state = self.state();
            let unavailable = state.unavailable.as_deref().is_some_and(|path| {
                request
                    .read_data_range()
                    .is_some_and(|(actual, _)| actual == path)
                    || request
                        .closing_data_ranges_for_test()
                        .is_some_and(|mut ranges| ranges.any(|(actual, _)| actual == path))
            });
            if unavailable {
                state.observations.unavailable_reads += 1;
            }
            unavailable
        };
        if unavailable {
            return Err(io::Error::other(
                "missing-placement fixture exact nofollow read unavailable",
            ));
        }

        TokioLocalFs.read_payload_ranges(request).await
    }

    async fn read_ordinary_record(
        &self,
        read: crate::store::NativeOrdinaryRead,
    ) -> io::Result<Option<crate::store::NativeOrdinaryRecord>> {
        // Preserve the scalar nofollow failure hook for ordinary leaves. Held
        // signed admission requires the unchanged native closing projection;
        // its checked observation supplies no Raw mutation acknowledgment.
        if read.path_for_test().is_some() {
            return Ok(None);
        }

        TokioLocalFs.read_ordinary_record(read).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_exclusive(path).await
    }

    async fn lock_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn random_bytes(&self, length: usize) -> io::Result<Vec<u8>> {
        let bytes = TokioLocalFs.random_bytes(length).await?;
        assert_eq!(bytes.len(), length);
        self.state().observations.entropy_lengths.push(length);
        Ok(bytes)
    }

    async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> io::Result<()> {
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_new(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.create_dir_new(path).await
    }

    async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
    }

    async fn metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn remove_file(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> io::Result<()> {
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_directory(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }

    async fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn sync_file(&self, path: &Path) -> io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }
}
