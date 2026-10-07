//! Observes genuine submitted effects and forwards all native I/O and exclusions.

use super::support::required;
use crate::store::{
    ByteRange, EffectFault, EffectFaultProbe, LocalFs, NativeEffectFailure, NativeFsEffect,
    NativePublicationInitialization, NativePublicationInitializationOutcome, StoreFailure,
    TestClock, TokioFileLock, TokioLocalFs,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, mpsc},
};
use terrane_core::gc::{
    CreationJournal, JournalState,
    publication::{PublicationCommit, PublicationProof, PublicationTransaction},
};

/// Selects a real fixed request without constructing a receipt or replacement plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    /// The real protected Pending durability request.
    Pending,
    /// The real same-descriptor artifact seal.
    Artifact,
    /// The real creation commitment after sealing.
    Committed,
    /// The real backend-only selected catalog acknowledgment.
    Raw,
    /// The real final Candidate acknowledgment whose transaction changes the main ref.
    Mutation,
}

/// Defines finite behavior at one actual already-sealed effect.
pub(super) enum Action {
    /// Returns unit success without executing the genuine request.
    Noop,
    /// Runs the real executor and preserves or swallows one actual injected error.
    Fault {
        /// The actual fixed native fault injected into the existing executor.
        fault: EffectFault,
        /// Whether the adapter returns unit success after observing that real error.
        swallow: bool,
    },
    /// Changes the originally injected worker clock before actual checks.
    Expire(TestClock),
    /// Pauses at the existing actual before/after-directory-sync handoff.
    Pause {
        /// Reports arrival at the real existing pre-sync handoff.
        arrived: mpsc::Sender<()>,
        /// Retains the original existing handoff until the test releases it.
        release: mpsc::Receiver<()>,
        /// Reports the real existing post-sync handoff if that syscall occurs.
        after: mpsc::Sender<()>,
    },
}

/// Records an actual selecting slot already installed before its final durability request.
///
/// These decoded observations select finite test hooks only; they confer no authority.
#[derive(Clone, Debug)]
pub(super) struct MutationObservation {
    /// The actual fixed request path borrowed from the submitted executor plan.
    pub(super) path: PathBuf,
    /// The exact already-installed canonical slot observed at that path.
    pub(super) slot: PublicationCommit,
    /// The exact canonical transaction bound by that slot's key and digest.
    pub(super) transaction: PublicationTransaction,
}

/// Observes the already-installed association without replacing any native checks.
///
/// # Panics
/// Panics if the genuine submitted request lacks its already-installed canonical outputs.
fn mutation_observation(path: &Path) -> MutationObservation {
    let slot = required(PublicationCommit::decode(&required(std::fs::read(path))));
    let control = required(
        path.parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or("actual control root"),
    );
    let bytes = required(std::fs::read(control.join(&slot.transaction_key)));
    required(slot.check_transaction(&format!("publication/commits/{}", slot.revision), &bytes));
    MutationObservation {
        path: path.to_owned(),
        slot,
        transaction: required(PublicationTransaction::decode(&bytes)),
    }
}

/// Records only boundaries actually submitted to or completed by the native binding.
#[derive(Clone, Debug, Default)]
pub(super) struct Observations {
    /// Actual final Raw slots submitted, in submission order.
    pub(super) raw: Vec<PathBuf>,
    /// Every actual Guard/Candidate durability request, in submission order.
    pub(super) mutations: Vec<MutationObservation>,
    /// Actual synchronized Pending records observed after real worker success.
    pub(super) pending: Vec<(PathBuf, CreationJournal)>,
    /// Actual synchronized Committed records observed after real worker success.
    pub(super) committed: Vec<(PathBuf, CreationJournal)>,
    /// Actual secure entropy request lengths returned by the native binding.
    pub(super) entropy_lengths: Vec<usize>,
    /// Actual errors returned by injected real workers, even if swallowed outwardly.
    pub(super) errors: Vec<String>,
    /// The armed phases genuinely reached by submitted requests.
    pub(super) reached: Vec<Phase>,
}

#[derive(Default)]
struct State {
    hook: Option<(Phase, Action)>,
    unavailable: Option<PathBuf>,
    observations: Observations,
}

/// Retains actual native kernel exclusion and finite test observations only.
#[derive(Clone, Default)]
pub(super) struct ProbeFs(Arc<Mutex<State>>);

impl ProbeFs {
    fn state(&self) -> MutexGuard<'_, State> {
        match self.0.lock() {
            Ok(state) => state,
            Err(error) => panic!("native batch observer poisoned: {error}"),
        }
    }

    /// Resets observations outside an armed operation without modifying storage.
    ///
    /// # Panics
    /// Panics if state is poisoned or an earlier genuine request has not consumed its hook.
    pub(super) fn reset(&self) {
        let mut state = self.state();
        assert!(state.hook.is_none(), "unconsumed native batch strategy");
        *state = State::default();
    }

    /// Arms one finite actual phase, preserving every ordinary native operation.
    ///
    /// # Panics
    /// Panics on poisoned state or an earlier unconsumed hook.
    pub(super) fn arm(&self, phase: Phase, action: Action) {
        let mut state = self.state();
        assert!(state.hook.is_none(), "unconsumed native batch strategy");
        state.hook = Some((phase, action));
    }

    /// Injects an exact unavailable nofollow read while leaving other I/O native.
    ///
    /// # Panics
    /// Panics if the finite fixture instrumentation is poisoned.
    pub(super) fn unavailable(&self, path: PathBuf) {
        self.state().unavailable = Some(path);
    }

    /// Returns genuine observations and requires the registered hook to have run.
    ///
    /// # Panics
    /// Panics on poisoned state or an unconsumed hook.
    pub(super) fn observations(&self) -> Observations {
        let state = self.state();
        assert!(
            state.hook.is_none(),
            "registered native batch phase never ran"
        );
        state.observations.clone()
    }

    /// Arms the existing real native directory-sync pause without changing its deadline.
    ///
    /// # Panics
    /// Panics on an unconsumed hook or poisoned instrumentation.
    pub(super) fn pause(
        &self,
        phase: Phase,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>, mpsc::Receiver<()>) {
        let (arrived, before) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let (after, completed) = mpsc::channel();
        self.arm(
            phase,
            Action::Pause {
                arrived,
                release: resume,
                after,
            },
        );
        (before, release, completed)
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
        mut effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let mut mutation = None;
        let (phase, path) = match effect.fault_probe() {
            EffectFaultProbe::SealPendingCreation(path) => {
                (Some(Phase::Pending), Some(path.to_owned()))
            }
            EffectFaultProbe::SealArtifact(path) => (Some(Phase::Artifact), Some(path.to_owned())),
            EffectFaultProbe::CommitCreation(path) => {
                (Some(Phase::Committed), Some(path.to_owned()))
            }
            EffectFaultProbe::SealRawPublication(path) => (Some(Phase::Raw), Some(path.to_owned())),
            EffectFaultProbe::SealMutationPublication(path) => {
                let observed = mutation_observation(path);
                let candidate =
                    matches!(&observed.transaction.proof, PublicationProof::Candidate(_))
                        && observed.transaction.changes.iter().any(|change| {
                            change.key == "refs/heads/_/main:record" && change.new.is_some()
                        });
                mutation = Some(observed);
                (candidate.then_some(Phase::Mutation), Some(path.to_owned()))
            }
            _ => (None, None),
        };
        let hook = {
            let mut state = self.state();
            if let Some(path) = &path {
                if phase == Some(Phase::Raw) {
                    state.observations.raw.push(path.clone());
                }
            }
            if let Some(observed) = mutation {
                state.observations.mutations.push(observed);
            }
            if state
                .hook
                .as_ref()
                .is_some_and(|(wanted, _)| Some(*wanted) == phase)
            {
                let (actual, action) = required(state.hook.take().ok_or("selected hook"));
                state.observations.reached.push(actual);
                Some(action)
            } else {
                None
            }
        };
        let mut swallow = false;
        match hook {
            Some(Action::Noop) => return Ok(()),
            Some(Action::Fault {
                fault,
                swallow: requested,
            }) => {
                effect = effect.inject_test_faults(vec![fault]);
                swallow = requested;
            }
            Some(Action::Expire(clock)) => clock.set(2_000_000_031, 31),
            Some(Action::Pause {
                arrived,
                release,
                after,
            }) => {
                effect = effect.test_directory_sync_handoff(arrived, release, after);
            }
            None => {}
        }
        if let Err(error) = TokioLocalFs.execute_retained_effect(effect).await {
            self.state().observations.errors.push(error.to_string());
            if swallow {
                assert!(
                    matches!(&error, NativeEffectFailure::Io(cause) if cause.kind() == io::ErrorKind::Other && cause.to_string().starts_with("injected creation")),
                    "unrelated failure before real injected sync: {error:?}"
                );
                return Ok(());
            }
            return Err(error);
        }
        assert!(!swallow, "registered real sync failure was not reached");
        if let Some(path) = path {
            if phase == Some(Phase::Pending) || phase == Some(Phase::Committed) {
                let journal = required(CreationJournal::decode(&required(std::fs::read(&path))));
                let mut state = self.state();
                if phase == Some(Phase::Pending) {
                    assert!(matches!(journal.state, JournalState::Pending));
                    state.observations.pending.push((path, journal));
                } else {
                    assert!(matches!(journal.state, JournalState::Committed { .. }));
                    state.observations.committed.push((path, journal));
                }
            }
        }
        Ok(())
    }

    async fn random_bytes(&self, length: usize) -> io::Result<Vec<u8>> {
        let result = TokioLocalFs.random_bytes(length).await?;
        assert_eq!(result.len(), length);
        self.state().observations.entropy_lengths.push(length);
        Ok(result)
    }

    async fn read_nofollow(&self, path: &Path) -> io::Result<Vec<u8>> {
        if self.state().unavailable.as_deref() == Some(path) {
            return Err(io::Error::other(
                "batch fixture exact nofollow read unavailable",
            ));
        }
        TokioLocalFs.read_nofollow(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn lock_exclusive(&self, path: &Path) -> io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
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
