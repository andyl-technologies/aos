//! Session-wide explicit evaluator option accessors for `TreeWalkOptions`.

use super::*;

impl TreeWalkOptions {
    /// Enables or disables the default-off session evaluator experiment.
    ///
    /// The first admitted operation fuses exact `genList` element-selection
    /// chains while retaining ordinary memoizing thunk publication. Broader
    /// force/eval/apply operations can join the same session executor after
    /// they have measured primary-workload coverage.
    pub fn set_stg_session_enabled(&mut self, enabled: bool) {
        self.stg_session_enabled = enabled;
    }

    /// Returns whether the default-off session evaluator is enabled.
    pub const fn stg_session_enabled(&self) -> bool {
        self.stg_session_enabled
    }
}
