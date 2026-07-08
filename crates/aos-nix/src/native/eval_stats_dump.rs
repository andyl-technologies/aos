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
//!  "inline_cache_hits":0,"inline_cache_misses":0,
//!  "tier1_promoted":0,"tier1_dispatched":0,"tier1_deopted":0,
//!  "tier1_blacklisted":0,
//!  "memo_l0_hits":0,"memo_l0_misses":0,"memo_l0_admissions":0,
//!  "memo_l0_declines":0,"memo_l1_hits":0,"memo_l1_misses":0,
//!  "memo_l1_admissions":0,"memo_l1_declines":0}}
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
\"inline_cache_misses\":{},\
\"tier1_promoted\":{},\
\"tier1_dispatched\":{},\
\"tier1_deopted\":{},\
\"tier1_blacklisted\":{},\
\"memo_l0_hits\":{},\
\"memo_l0_misses\":{},\
\"memo_l0_admissions\":{},\
\"memo_l0_declines\":{},\
\"memo_l1_hits\":{},\
\"memo_l1_misses\":{},\
\"memo_l1_admissions\":{},\
\"memo_l1_declines\":{}\
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
            stats.tier1_promoted(),
            stats.tier1_dispatched(),
            stats.tier1_deopted(),
            stats.tier1_blacklisted(),
            stats.memo_l0_hits(),
            stats.memo_l0_misses(),
            stats.memo_l0_admissions(),
            stats.memo_l0_declines(),
            stats.memo_l1_hits(),
            stats.memo_l1_misses(),
            stats.memo_l1_admissions(),
            stats.memo_l1_declines(),
        );
    }
}
