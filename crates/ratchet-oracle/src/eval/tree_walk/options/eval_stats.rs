//! Evaluation work-volume statistics-dump option accessors for `TreeWalkOptions`.
//!
//! Groups the toggle that records whether a caller owning an evaluation outcome
//! should emit the evaluator's work counters (thunks, attribute sets, values,
//! function calls, hash-cons reuse, symbols, imports) for comparison against
//! C++ Nix's `NIX_SHOW_STATS`.

use super::*;

impl TreeWalkOptions {
    /// Enables or disables end-of-evaluation work-volume statistics dumping.
    ///
    /// When enabled, callers that own the evaluation outcome (for example the
    /// `aos-nix` native instantiate path) emit the evaluator's `EvalStats` as a
    /// single JSON object so a native evaluation's work volume can be compared
    /// against C++ Nix's `NIX_SHOW_STATS`. The evaluator itself does no
    /// printing; this flag only records the caller's intent.
    pub fn set_eval_stats_dump(&mut self, eval_stats_dump: bool) {
        self.eval_stats_dump = eval_stats_dump;
    }

    /// Returns whether end-of-evaluation statistics dumping is enabled.
    pub const fn eval_stats_dump(&self) -> bool {
        self.eval_stats_dump
    }

    /// Enables or disables the exact `genList` selected-child shape census.
    ///
    /// This diagnostic is effective only when [`Self::eval_stats_dump`] is
    /// also enabled. It admits the guarded `GenListElemAtAddOne` force path
    /// during that stats run so the child selected by `elemAt` can be
    /// classified immediately before forcing.
    pub fn set_genlist_selected_child_census_enabled(&mut self, enabled: bool) {
        self.genlist_selected_child_census_enabled = enabled;
    }

    /// Returns whether the exact `genList` selected-child census is active.
    pub const fn genlist_selected_child_census_enabled(&self) -> bool {
        self.eval_stats_dump && self.genlist_selected_child_census_enabled
    }
}
