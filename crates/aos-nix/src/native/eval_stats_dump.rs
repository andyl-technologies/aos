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
//! {"aos_nix_eval_stats":{"thunks_allocated":22013,"thunks_elided":12,
//!  "binding_assembly_elisions":0,"thunks_forced":21880,
//!  "attrsets_built":6042,"attrs_entries_total":38110,"values_allocated":24901,
//!  "function_calls":16233,"hashcons_attempts":31044,"hashcons_hits":6143,
//!  "symbols_interned":4021,"imports_evaluated":37,"root_cutoffs":0,
//!  "inline_cache_hits":0,"inline_cache_misses":0,
//!  "thunks_shed":0,"gc_sweeps":0,"gc_records_swept":0,
//!  "gc_sweeps_skipped_nonquiescent":0,
//!  "tier1_promoted":0,"tier1_dispatched":0,"tier1_deopted":0,
//!  "tier1_blacklisted":0,
//!  "tier2_promoted":0,"tier2_dispatched":0,"tier2_deopted":0,
//!  "tier2_blacklisted":0,
//!  "memo_l0_hits":0,"memo_l0_misses":0,"memo_l0_admissions":0,
//!  "memo_l0_declines":0,"memo_l1_hits":0,"memo_l1_misses":0,
//!  "memo_l1_admissions":0,"memo_l1_declines":0,
//!  "memo_l2_secondary_hits":0,"memo_l2_secondary_misses":0,
//!  "memo_l2_promotions":0,"memo_l2_reval_failures":0,
//!  "memo_net_hits":0,"memo_net_misses":0,"memo_net_errors":0,
//!  "memo_net_reval_failures":0,
//!  "campaign":{"record_probes_string":0,"record_probes_path":0,
//!  "record_probes_list":0,"record_probes_attrs":0,"record_probes_lambda":0,
//!  "record_probes_primop":0,"record_probes_thunk":0,"record_probes_other":0,
//!  "flat_string_resolutions":0,"flat_path_resolutions":0,
//!  "flat_list_resolutions":0,"flat_attrs_resolutions":0,
//!  "payload_arc_clones":0,"env_captures":0,"env_capture_frame_handles":0,
//!  "with_env_captures":0,"with_env_capture_scopes":0,
//!  "scoped_global_env_captures":0,"scoped_global_env_capture_scopes":0,
//!  "env_frame_allocs":0,"env_frame_slot_bytes":0,"string_payload_bytes":0,
//!  "string_store_path_payload_bytes":0,"path_payload_bytes":0,
//!  "list_payload_elements":0,"record_table_records":0,"flat_objects":0}}}
//! ```
//!
//! The nested `campaign` object carries the RFC-0007 doc 30 FV-0 flat-value
//! campaign counters: record-table dereference probes by value kind, flat
//! store resolutions, payload `Arc` clones, environment capture-copy and
//! frame-allocation volume, and per-kind payload byte mass.

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
\"thunks_elided\":{},\
\"binding_assembly_elisions\":{},\
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
\"thunks_shed\":{},\
\"gc_sweeps\":{},\
\"gc_records_swept\":{},\
\"gc_sweeps_skipped_nonquiescent\":{},\
\"tier1_promoted\":{},\
\"tier1_dispatched\":{},\
\"tier1_deopted\":{},\
\"tier1_blacklisted\":{},\
\"tier2_promoted\":{},\
\"tier2_dispatched\":{},\
\"tier2_deopted\":{},\
\"tier2_blacklisted\":{},\
\"memo_l0_hits\":{},\
\"memo_l0_misses\":{},\
\"memo_l0_admissions\":{},\
\"memo_l0_declines\":{},\
\"memo_l1_hits\":{},\
\"memo_l1_misses\":{},\
\"memo_l1_admissions\":{},\
\"memo_l1_declines\":{},\
\"memo_l2_secondary_hits\":{},\
\"memo_l2_secondary_misses\":{},\
\"memo_l2_promotions\":{},\
\"memo_l2_reval_failures\":{},\
\"memo_net_hits\":{},\
\"memo_net_misses\":{},\
\"memo_net_errors\":{},\
\"memo_net_reval_failures\":{},\
\"campaign\":{{\
\"record_probes_string\":{},\
\"record_probes_path\":{},\
\"record_probes_list\":{},\
\"record_probes_attrs\":{},\
\"record_probes_lambda\":{},\
\"record_probes_primop\":{},\
\"record_probes_thunk\":{},\
\"record_probes_other\":{},\
\"flat_string_resolutions\":{},\
\"flat_path_resolutions\":{},\
\"flat_list_resolutions\":{},\
\"flat_attrs_resolutions\":{},\
\"payload_arc_clones\":{},\
\"env_captures\":{},\
\"env_capture_frame_handles\":{},\
\"with_env_captures\":{},\
\"with_env_capture_scopes\":{},\
\"scoped_global_env_captures\":{},\
\"scoped_global_env_capture_scopes\":{},\
\"env_frame_allocs\":{},\
\"env_frame_slot_bytes\":{},\
\"string_payload_bytes\":{},\
\"string_store_path_payload_bytes\":{},\
\"path_payload_bytes\":{},\
\"list_payload_elements\":{},\
\"record_table_records\":{},\
\"flat_objects\":{}\
}}\
}}}}",
            stats.thunks_allocated(),
            stats.thunks_elided(),
            stats.binding_assembly_elisions(),
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
            stats.thunks_shed(),
            stats.gc_sweeps(),
            stats.gc_records_swept(),
            stats.gc_sweeps_skipped_nonquiescent(),
            stats.tier1_promoted(),
            stats.tier1_dispatched(),
            stats.tier1_deopted(),
            stats.tier1_blacklisted(),
            stats.tier2_promoted(),
            stats.tier2_dispatched(),
            stats.tier2_deopted(),
            stats.tier2_blacklisted(),
            stats.memo_l0_hits(),
            stats.memo_l0_misses(),
            stats.memo_l0_admissions(),
            stats.memo_l0_declines(),
            stats.memo_l1_hits(),
            stats.memo_l1_misses(),
            stats.memo_l1_admissions(),
            stats.memo_l1_declines(),
            stats.memo_l2_secondary_hits(),
            stats.memo_l2_secondary_misses(),
            stats.memo_l2_promotions(),
            stats.memo_l2_reval_failures(),
            stats.memo_net_hits(),
            stats.memo_net_misses(),
            stats.memo_net_errors(),
            stats.memo_net_reval_failures(),
            stats.campaign().record_probes_string,
            stats.campaign().record_probes_path,
            stats.campaign().record_probes_list,
            stats.campaign().record_probes_attrs,
            stats.campaign().record_probes_lambda,
            stats.campaign().record_probes_primop,
            stats.campaign().record_probes_thunk,
            stats.campaign().record_probes_other,
            stats.campaign().flat_string_resolutions,
            stats.campaign().flat_path_resolutions,
            stats.campaign().flat_list_resolutions,
            stats.campaign().flat_attrs_resolutions,
            stats.campaign().payload_arc_clones,
            stats.campaign().env_captures,
            stats.campaign().env_capture_frame_handles,
            stats.campaign().with_env_captures,
            stats.campaign().with_env_capture_scopes,
            stats.campaign().scoped_global_env_captures,
            stats.campaign().scoped_global_env_capture_scopes,
            stats.campaign().env_frame_allocs,
            stats.campaign().env_frame_slot_bytes,
            stats.campaign().string_payload_bytes,
            stats.campaign().string_store_path_payload_bytes,
            stats.campaign().path_payload_bytes,
            stats.campaign().list_payload_elements,
            stats.campaign().record_table_records,
            stats.campaign().flat_objects,
        );
    }
}
