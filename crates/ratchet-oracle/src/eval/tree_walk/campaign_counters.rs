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
//! - record-probe / flat-resolution / `Arc`-clone counts from the serial
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
    /// `Arc` payload-handle clones handed out by thunk/lambda/primop resolution.
    pub payload_arc_clones: u64,
    /// Lexical frame-array capture copies (`EvalEnv::capture`).
    pub env_captures: u64,
    /// Frame handles copied across all lexical captures (8 bytes each).
    pub env_capture_frame_handles: u64,
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
            payload_arc_clones: self
                .payload_arc_clones
                .saturating_add(other.payload_arc_clones),
            env_captures: self.env_captures.saturating_add(other.env_captures),
            env_capture_frame_handles: self
                .env_capture_frame_handles
                .saturating_add(other.env_capture_frame_handles),
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
