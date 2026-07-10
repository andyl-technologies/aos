//! Flat-value campaign counters (RFC-0007 doc 30, stage FV-0).
//!
//! One nested, `Copy` block of work-volume counters attached to
//! [`super::EvalStats`]: the dereference-chain probes, capture copies, and
//! environment allocations that doc 30 §11.1 flagged as session-profiled and
//! unreproducible. With this block, the campaign's before/after claims come
//! from a stock build via the `AOS_NIX_EVAL_STATS=1` JSON dump.
//!
//! Sources, assembled by `TreeWalk::stats_snapshot`:
//!
//! - record-probe / flat-resolution / payload and state `Arc`-clone counts from the serial
//!   evaluator heap (`eval::heap`, per-heap `Cell` counters);
//! - capture-copy and frame-allocation counts from the process-wide
//!   `eval::env::capture_stats` atomics, as a delta from the evaluator's
//!   construction snapshot;
//! - per-kind payload byte mass from the heap allocation counters, with
//!   strings split by the `/nix/store/` store-path shape (the doc 30 §7.3
//!   sizing probe).

/// Flat-value campaign work-volume counters for one evaluation.
///
/// All fields are monotonic totals for the evaluation that produced the
/// enclosing [`super::EvalStats`]. Byte fields count payload storage, not
/// allocator overhead.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CampaignCounters {
    /// Record-table address probes issued for string handles.
    pub record_probes_string: u64,
    /// Record-table address probes issued for path handles.
    pub record_probes_path: u64,
    /// Record-table address probes issued for list handles.
    pub record_probes_list: u64,
    /// Record-table address probes issued for attrset handles.
    pub record_probes_attrs: u64,
    /// Record-table address probes issued for lambda handles.
    pub record_probes_lambda: u64,
    /// Record-table address probes issued for partially applied builtins.
    pub record_probes_primop: u64,
    /// Record-table address probes issued for thunk handles.
    pub record_probes_thunk: u64,
    /// Record-table address probes issued under any other tag.
    pub record_probes_other: u64,
    /// String resolutions served by the flat store without a record probe.
    pub flat_string_resolutions: u64,
    /// Path resolutions served by the flat store without a record probe.
    pub flat_path_resolutions: u64,
    /// List resolutions served by the flat store without a record probe.
    pub flat_list_resolutions: u64,
    /// Attrset resolutions served by the flat store without a record probe.
    pub flat_attrs_resolutions: u64,
    /// Thunk resolutions served by the flat closure store (doc 30 FV-3).
    pub flat_thunk_resolutions: u64,
    /// Lambda resolutions served by the flat closure store (doc 30 FV-3).
    pub flat_lambda_resolutions: u64,
    /// Partially-applied-builtin resolutions served by the flat closure store.
    pub flat_primop_resolutions: u64,
    /// Legacy payload-handle `Arc` clones; zero after FV-6.
    pub payload_arc_clones: u64,
    /// Thunk force-state sidecar `Arc` clones retained across evaluator re-entry.
    pub thunk_state_arc_clones: u64,
    /// Lexical frame-array capture copies (`EvalEnv::capture`).
    pub env_captures: u64,
    /// Frame handles copied across all lexical captures (8 bytes each).
    pub env_capture_frame_handles: u64,
    /// Flat capture-plan environments materialized (FV-5).
    pub flat_env_captures: u64,
    /// Values copied across all flat capture-plan environments (FV-5).
    pub flat_env_capture_values: u64,
    /// `with`-scope stack capture copies.
    pub with_env_captures: u64,
    /// Scope entries copied across all `with`-stack captures.
    pub with_env_capture_scopes: u64,
    /// Scoped-import global stack capture copies.
    pub scoped_global_env_captures: u64,
    /// Scope values copied across all scoped-global captures.
    pub scoped_global_env_capture_scopes: u64,
    /// Lexical frames allocated (`EvalFrame::new`).
    pub env_frame_allocs: u64,
    /// Slot-storage bytes allocated across all frame allocations.
    pub env_frame_slot_bytes: u64,
    /// Payload bytes of freshly allocated string values.
    pub string_payload_bytes: u64,
    /// The store-path-shaped subset of [`Self::string_payload_bytes`].
    pub string_store_path_payload_bytes: u64,
    /// Payload bytes of freshly allocated path values.
    pub path_payload_bytes: u64,
    /// Spine elements of freshly allocated list values (16 bytes each).
    pub list_payload_elements: u64,
    /// Typed records resident in the record side table at snapshot time.
    ///
    /// A gauge, not a rate: after doc 30 FV-3 every production allocation
    /// path is flat, so this reads zero outside the Tier-B B2 relocation
    /// proving ground (whose GC-stress heaps keep the record placement).
    pub record_table_records: u64,
    /// Flat heap objects resident in the flat stores at snapshot time.
    ///
    /// A gauge: strings, paths, lists, attrsets (doc 30 FV-1/FV-2), and
    /// worker closures (doc 30 FV-3).
    pub flat_objects: u64,
}

impl CampaignCounters {
    /// Returns the field-wise saturating sum of `self` and `other`.
    ///
    /// Used when merging parallel worker statistics into one report.
    pub fn merged(self, other: Self) -> Self {
        Self {
            record_probes_string: self
                .record_probes_string
                .saturating_add(other.record_probes_string),
            record_probes_path: self
                .record_probes_path
                .saturating_add(other.record_probes_path),
            record_probes_list: self
                .record_probes_list
                .saturating_add(other.record_probes_list),
            record_probes_attrs: self
                .record_probes_attrs
                .saturating_add(other.record_probes_attrs),
            record_probes_lambda: self
                .record_probes_lambda
                .saturating_add(other.record_probes_lambda),
            record_probes_primop: self
                .record_probes_primop
                .saturating_add(other.record_probes_primop),
            record_probes_thunk: self
                .record_probes_thunk
                .saturating_add(other.record_probes_thunk),
            record_probes_other: self
                .record_probes_other
                .saturating_add(other.record_probes_other),
            flat_string_resolutions: self
                .flat_string_resolutions
                .saturating_add(other.flat_string_resolutions),
            flat_path_resolutions: self
                .flat_path_resolutions
                .saturating_add(other.flat_path_resolutions),
            flat_list_resolutions: self
                .flat_list_resolutions
                .saturating_add(other.flat_list_resolutions),
            flat_attrs_resolutions: self
                .flat_attrs_resolutions
                .saturating_add(other.flat_attrs_resolutions),
            flat_thunk_resolutions: self
                .flat_thunk_resolutions
                .saturating_add(other.flat_thunk_resolutions),
            flat_lambda_resolutions: self
                .flat_lambda_resolutions
                .saturating_add(other.flat_lambda_resolutions),
            flat_primop_resolutions: self
                .flat_primop_resolutions
                .saturating_add(other.flat_primop_resolutions),
            payload_arc_clones: self
                .payload_arc_clones
                .saturating_add(other.payload_arc_clones),
            thunk_state_arc_clones: self
                .thunk_state_arc_clones
                .saturating_add(other.thunk_state_arc_clones),
            env_captures: self.env_captures.saturating_add(other.env_captures),
            env_capture_frame_handles: self
                .env_capture_frame_handles
                .saturating_add(other.env_capture_frame_handles),
            flat_env_captures: self
                .flat_env_captures
                .saturating_add(other.flat_env_captures),
            flat_env_capture_values: self
                .flat_env_capture_values
                .saturating_add(other.flat_env_capture_values),
            with_env_captures: self
                .with_env_captures
                .saturating_add(other.with_env_captures),
            with_env_capture_scopes: self
                .with_env_capture_scopes
                .saturating_add(other.with_env_capture_scopes),
            scoped_global_env_captures: self
                .scoped_global_env_captures
                .saturating_add(other.scoped_global_env_captures),
            scoped_global_env_capture_scopes: self
                .scoped_global_env_capture_scopes
                .saturating_add(other.scoped_global_env_capture_scopes),
            env_frame_allocs: self.env_frame_allocs.saturating_add(other.env_frame_allocs),
            env_frame_slot_bytes: self
                .env_frame_slot_bytes
                .saturating_add(other.env_frame_slot_bytes),
            string_payload_bytes: self
                .string_payload_bytes
                .saturating_add(other.string_payload_bytes),
            string_store_path_payload_bytes: self
                .string_store_path_payload_bytes
                .saturating_add(other.string_store_path_payload_bytes),
            path_payload_bytes: self
                .path_payload_bytes
                .saturating_add(other.path_payload_bytes),
            list_payload_elements: self
                .list_payload_elements
                .saturating_add(other.list_payload_elements),
            record_table_records: self
                .record_table_records
                .saturating_add(other.record_table_records),
            flat_objects: self.flat_objects.saturating_add(other.flat_objects),
        }
    }

    /// Returns the total record-table probes across every value kind.
    pub const fn record_probes_total(&self) -> u64 {
        self.record_probes_string
            + self.record_probes_path
            + self.record_probes_list
            + self.record_probes_attrs
            + self.record_probes_lambda
            + self.record_probes_primop
            + self.record_probes_thunk
            + self.record_probes_other
    }
}
