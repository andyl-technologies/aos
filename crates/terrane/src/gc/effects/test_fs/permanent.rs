//! Observes real permanent native workers across faults and canceled waiters.
//!
//! Hooks select existing closed requests only. Actual native execution retains
//! its exclusion and result channels; neither submission nor a gate fabricates
//! a completion receipt or authorizes another family target.

use super::{Mutex, PathBuf, TestFs, TestGate, TestGatePhase, mpsc};
use crate::store::{EffectFault, EffectFaultProbe, NativeFsEffect};

/// Identifies an existing closed permanent native request for test observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PermanentPhase {
    /// Matches an actual family observation or collector extraction request.
    Observation,
    /// Matches an actual selected Planned family reclaim request.
    Reclaim,
    /// Matches durability of an actual selected permanent progress event.
    Progress,
}

/// Selects a boundary already implemented inside the real native worker.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PermanentBoundary {
    /// Pauses before the worker's final retained target comparison.
    BeforeOpen,
    /// Pauses after preceding mutations and before parent directory durability.
    BeforeDirectorySync,
    /// Pauses after parent directory durability and before final acknowledgment.
    AfterDirectorySync,
}

#[derive(Default)]
/// Retains pending hooks and separately recorded actual native observations.
pub(super) struct PermanentHooks {
    gate: Mutex<Option<(PermanentPhase, Option<PathBuf>, TestGate)>>,
    fault: Mutex<Option<(PermanentPhase, Option<PathBuf>, EffectFault)>>,
    submitted: Mutex<Vec<(PermanentPhase, PathBuf)>>,
    completed: Mutex<Vec<(PermanentPhase, PathBuf, bool)>>,
}

impl PermanentHooks {
    /// Attaches matching hooks to an existing closed request before forwarding it.
    ///
    /// # Panics
    /// Panics if test observation synchronization is poisoned.
    pub(super) fn prepare(&self, effect: &mut NativeFsEffect) -> Option<(PermanentPhase, PathBuf)> {
        let (phase, path) = match effect.fault_probe() {
            EffectFaultProbe::PermanentLocalObservation(path) => {
                (PermanentPhase::Observation, path.to_owned())
            }
            EffectFaultProbe::PermanentLocalReclaim(path) => {
                (PermanentPhase::Reclaim, path.to_owned())
            }
            EffectFaultProbe::PermanentLocalProgress(path) => {
                (PermanentPhase::Progress, path.to_owned())
            }
            _ => return None,
        };
        let matches = |expected_phase: PermanentPhase, expected_path: &Option<PathBuf>| {
            expected_phase == phase
                && expected_path
                    .as_ref()
                    .is_none_or(|expected| expected == &path)
        };
        {
            let mut pending = self.gate.lock().unwrap();
            if pending
                .as_ref()
                .is_some_and(|(expected, path, _)| matches(*expected, path))
            {
                let (_, _, gate) = pending.take().unwrap();
                effect.gates.push(gate);
            }
        }
        {
            let mut pending = self.fault.lock().unwrap();
            if pending
                .as_ref()
                .is_some_and(|(expected, path, _)| matches(*expected, path))
            {
                let (_, _, fault) = pending.take().unwrap();
                effect.faults.push(fault);
            }
        }
        self.submitted.lock().unwrap().push((phase, path.clone()));
        Some((phase, path))
    }

    /// Records the actual worker return independently of its operation waiter.
    ///
    /// # Panics
    /// Panics if test observation synchronization is poisoned.
    pub(super) fn complete(&self, phase: PermanentPhase, path: PathBuf, success: bool) {
        self.completed.lock().unwrap().push((phase, path, success));
    }
}

impl TestFs {
    /// Pauses the next matching actual permanent worker at its native boundary.
    ///
    /// `None` selects the next request of this phase; `Some` requires its exact
    /// native path. Fresh event nonces need not be predicted by the fixture.
    ///
    /// # Panics
    /// Panics if a previous gate remains or observation synchronization is poisoned.
    pub(crate) fn pause_permanent(
        &self,
        phase: PermanentPhase,
        path: Option<PathBuf>,
        boundary: PermanentBoundary,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let boundary = match boundary {
            PermanentBoundary::BeforeOpen => TestGatePhase::BeforeOpen,
            PermanentBoundary::BeforeDirectorySync => TestGatePhase::BeforeDirectorySync,
            PermanentBoundary::AfterDirectorySync => TestGatePhase::AfterDirectorySync,
        };
        let (arrived, received) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let mut pending = self.state.permanent.gate.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some((
            phase,
            path,
            TestGate {
                phase: boundary,
                arrived,
                release: released,
            },
        ));
        (received, release)
    }

    /// Injects one failure inside the next matching actual permanent worker.
    ///
    /// The real worker must reach the requested fault boundary. This binding
    /// forwards its actual failure and never supplies a success acknowledgment.
    ///
    /// # Panics
    /// Panics if a previous fault remains or observation synchronization is poisoned.
    pub(crate) fn fail_next_permanent(
        &self,
        phase: PermanentPhase,
        path: Option<PathBuf>,
        fault: EffectFault,
    ) {
        let mut pending = self.state.permanent.fault.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some((phase, path, fault));
    }

    /// Requires both permanent hooks to have matched actual submitted requests.
    ///
    /// This assertion does not prove native completion or physical durability.
    ///
    /// # Panics
    /// Panics for unconsumed hooks or poisoned observation synchronization.
    pub(crate) fn assert_permanent_hooks_consumed(&self) {
        assert!(self.state.permanent.gate.lock().unwrap().is_none());
        assert!(self.state.permanent.fault.lock().unwrap().is_none());
    }

    /// Returns the actual request paths handed to the permanent native binding.
    ///
    /// # Panics
    /// Panics if observation synchronization is poisoned.
    pub(crate) fn permanent_submitted_paths(&self, phase: PermanentPhase) -> Vec<PathBuf> {
        self.state
            .permanent
            .submitted
            .lock()
            .unwrap()
            .iter()
            .filter(|(selected, _)| *selected == phase)
            .map(|(_, path)| path.clone())
            .collect()
    }

    /// Returns actual terminal native paths and their success or failure outcomes.
    ///
    /// Completion remains observable after the operation's waiter is canceled.
    /// A successful native return still does not replace a producer's typed receipt.
    ///
    /// # Panics
    /// Panics if observation synchronization is poisoned.
    pub(crate) fn permanent_completed(&self, phase: PermanentPhase) -> Vec<(PathBuf, bool)> {
        self.state
            .permanent
            .completed
            .lock()
            .unwrap()
            .iter()
            .filter(|(selected, _, _)| *selected == phase)
            .map(|(_, path, success)| (path.clone(), *success))
            .collect()
    }
}
