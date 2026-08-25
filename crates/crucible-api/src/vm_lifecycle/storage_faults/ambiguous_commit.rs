//! Fail-closed handling for ambiguous 9p shared-memory publication.

use super::*;

/// Poisons a runtime after a 9p operation crosses its shared-memory commit point.
pub(super) trait AmbiguousNinepCommitRuntime {
    fn poison_ambiguous_ninep_commit(&mut self);
}

impl AmbiguousNinepCommitRuntime for ProductionFaultRuntime {
    fn poison_ambiguous_ninep_commit(&mut self) {
        self.poison();
    }
}

/// Marks the canonical continuation unusable before returning a post-commit error.
pub(super) fn fail_after_shared_ninep_commit<R: AmbiguousNinepCommitRuntime>(
    runtime: &Arc<Mutex<R>>,
    error: DeviceRuntimeError,
) -> DeviceRuntimeError {
    // A poisoned mutex is already fail-closed because every production access
    // maps lock acquisition failure to a terminal coordinator error.
    if let Ok(mut runtime) = runtime.lock() {
        runtime.poison_ambiguous_ninep_commit();
    }
    error
}
