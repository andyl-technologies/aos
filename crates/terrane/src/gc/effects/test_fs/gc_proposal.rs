//! Pauses actual immutable GC proposal staging before native retained checks.
//!
//! The hook selects a genuine registered cycle path supplied by a native rename
//! request. It neither predicts entropy nor changes effect or acknowledgment
//! channels. Only the existing native test gate supplies the pause.

use super::{Mutex, PathBuf, TestFs, TestGate, TestGatePhase, mpsc};
use crate::store::{EffectFaultProbe, NativeFsEffect};

/// Keeps a once-only proposal hook and its independently observed actual path.
#[derive(Default)]
pub(super) struct GcProposalHooks {
    pending: Mutex<Option<(PathBuf, TestGate)>>,
    observed: Mutex<Option<PathBuf>>,
}

impl GcProposalHooks {
    /// Attaches the gate only to the next registered immutable cycle proposal.
    ///
    /// # Panics
    /// Panics if fixture observation synchronization is poisoned.
    pub(super) fn prepare(&self, effect: &mut NativeFsEffect) {
        let EffectFaultProbe::RenameNoReplace(path) = effect.fault_probe() else {
            return;
        };
        let mut pending = self.pending.lock().unwrap();
        let matches = pending.as_ref().is_some_and(|(root, _)| {
            let Some(key) = path.strip_prefix(root).ok().and_then(|key| key.to_str()) else {
                return false;
            };
            if terrane_core::bucket::BucketKey::parse(key).is_err() {
                return false;
            }

            let mut segments = key.split('/');
            if segments.next() != Some("gc") {
                return false;
            }
            let Some(cycle) = segments.next() else {
                return false;
            };
            cycle
                .parse::<u64>()
                .is_ok_and(|parsed| parsed.to_string() == cycle)
                && segments.next().is_some()
        });
        if !matches {
            return;
        }

        *self.observed.lock().unwrap() = Some(path.to_owned());
        if let Some((_, gate)) = pending.take() {
            effect.gates.push(gate);
        }
    }
}

impl TestFs {
    /// Pauses the next actual cycle-proposal rename before its retained checks.
    ///
    /// The actual native path must be registered under this configured root.
    /// Lease writes and unrelated effects cannot consume this once-only hook.
    ///
    /// # Panics
    /// Panics if another proposal hook remains or synchronization is poisoned.
    pub(crate) fn pause_next_gc_proposal(
        &self,
        root: PathBuf,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, received) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let hooks = &self.state.gc_proposal;
        let mut pending = hooks.pending.lock().unwrap();
        assert!(pending.is_none());
        *hooks.observed.lock().unwrap() = None;
        *pending = Some((
            root,
            TestGate {
                phase: TestGatePhase::BeforeChecks,
                arrived,
                release: released,
            },
        ));
        (received, release)
    }

    /// Returns the genuine proposal path only after its hook was consumed.
    ///
    /// # Panics
    /// Panics if the actual hook was not consumed or synchronization is poisoned.
    pub(crate) fn gc_proposal_path(&self) -> PathBuf {
        let hooks = &self.state.gc_proposal;
        assert!(hooks.pending.lock().unwrap().is_none());
        hooks.observed.lock().unwrap().clone().unwrap()
    }
}
