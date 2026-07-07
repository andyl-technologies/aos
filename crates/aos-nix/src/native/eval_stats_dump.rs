//! Optional end-of-evaluation work-volume statistics dumping.
//!
//! Gated on the `AOS_NIX_EVAL_STATS=1` environment knob (plumbed through
//! `TreeWalkOptions::eval_stats_dump`), the native instantiate path emits the
//! tree-walk evaluator's work counters as
//! a single JSON object to stderr so a native evaluation can be compared,
//! work-for-work, against C++ Nix's `NIX_SHOW_STATS`.
//!
//! The emitted object has the shape:
//!
//! ```text
//! {"aos_nix_eval_stats":{"thunks_allocated":22013,"thunks_forced":21880,
//!  "attrsets_built":6042,"attrs_entries_total":38110,"values_allocated":24901,
//!  "function_calls":16233,"hashcons_attempts":31044,"hashcons_hits":6143,
//!  "symbols_interned":4021,"imports_evaluated":37,"root_cutoffs":0,
//!  "inline_cache_hits":0,"inline_cache_misses":0}}
//! ```

use super::*;

impl NixNative {
    /// Emits evaluator work-volume statistics to stderr when dumping is enabled.
    ///
    /// This is a no-op unless `TreeWalkOptions::eval_stats_dump` is set (via
    /// the `AOS_NIX_EVAL_STATS=1` knob). When set, it writes a single JSON
    /// object describing the work performed by a native instantiate — thunks,
    /// attribute sets, values, function calls, hash-cons reuse, symbols, and
    /// imports — for comparison against C++ Nix's `NIX_SHOW_STATS`.
    pub(super) fn maybe_dump_eval_stats(&self, stats: &EvalStats) {
        if !self.options.eval_stats_dump() {
            return;
        }
        eprintln!(
            "{{\"aos_nix_eval_stats\":{{\
\"thunks_allocated\":{},\
\"thunks_forced\":{},\
\"attrsets_built\":{},\
\"attrs_entries_total\":{},\
\"values_allocated\":{},\
\"function_calls\":{},\
\"hashcons_attempts\":{},\
\"hashcons_hits\":{},\
\"symbols_interned\":{},\
\"imports_evaluated\":{},\
\"root_cutoffs\":{},\
\"inline_cache_hits\":{},\
\"inline_cache_misses\":{}\
}}}}",
            stats.thunks_allocated(),
            stats.thunks_forced(),
            stats.attrsets_built(),
            stats.attrs_entries_total(),
            stats.values_allocated(),
            stats.function_calls(),
            stats.hashcons_attempts(),
            stats.hashcons_hits(),
            stats.symbols_interned(),
            stats.imports_evaluated(),
            stats.root_cutoffs(),
            stats.inline_cache_hits(),
            stats.inline_cache_misses(),
        );
    }
}
