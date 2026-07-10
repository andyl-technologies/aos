//! Dereference-chain counters for the evaluator heap (RFC-0007 doc 30 FV-0).
//!
//! Every serial heap-value resolution currently funnels through the record
//! side table ([`super::record_table::HeapRecordTable`]): an address-hash
//! probe, a record load, and (before FV-6) a refcounted payload-handle clone.
//! Doc 30 §1.1 identifies that chain as the evaluator's dominant
//! architectural unit cost; these counters make its volume observable from a
//! stock build (`AOS_NIX_EVAL_STATS=1`) so the flat-value stages can claim
//! their probe reductions against reproducible denominators.
//!
//! The counters use [`Cell`] fields because the resolution paths take `&self`
//! (the same pattern as the heap's access-epoch cell). They count the *serial*
//! backend only: parallel shared-arena resolution has its own probe structure
//! and is quiesced from the flat-value stages until the shared-mode follow-up.

use std::cell::Cell;

use crate::value::ValueTag;

/// Interior-mutable per-heap dereference counters.
///
/// Snapshot with [`EvalHeapDerefCounters::snapshot`]; the snapshot feeds the
/// campaign block of the evaluator's public statistics.
#[derive(Debug, Default)]
pub(crate) struct EvalHeapDerefCounters {
    record_probes_string: Cell<u64>,
    record_probes_path: Cell<u64>,
    record_probes_list: Cell<u64>,
    record_probes_attrs: Cell<u64>,
    record_probes_lambda: Cell<u64>,
    record_probes_primop: Cell<u64>,
    record_probes_thunk: Cell<u64>,
    record_probes_other: Cell<u64>,
    flat_string_resolutions: Cell<u64>,
    flat_path_resolutions: Cell<u64>,
    flat_list_resolutions: Cell<u64>,
    flat_attrs_resolutions: Cell<u64>,
    flat_thunk_resolutions: Cell<u64>,
    flat_lambda_resolutions: Cell<u64>,
    flat_primop_resolutions: Cell<u64>,
    payload_arc_clones: Cell<u64>,
    thunk_state_arc_clones: Cell<u64>,
}

impl EvalHeapDerefCounters {
    /// Records one record-table address probe issued under `tag`.
    #[inline]
    pub(super) fn note_record_probe(&self, tag: ValueTag) {
        let counter = match tag {
            ValueTag::String => &self.record_probes_string,
            ValueTag::Path => &self.record_probes_path,
            ValueTag::List => &self.record_probes_list,
            ValueTag::Attrs => &self.record_probes_attrs,
            ValueTag::Lambda => &self.record_probes_lambda,
            ValueTag::Primop => &self.record_probes_primop,
            ValueTag::Thunk => &self.record_probes_thunk,
            _ => &self.record_probes_other,
        };
        counter.set(counter.get().saturating_add(1));
    }

    /// Records one flat-object resolution that bypassed the record table.
    #[inline]
    pub(super) fn note_flat_resolution(&self, tag: ValueTag) {
        let counter = match tag {
            ValueTag::String => &self.flat_string_resolutions,
            ValueTag::Path => &self.flat_path_resolutions,
            ValueTag::List => &self.flat_list_resolutions,
            ValueTag::Attrs => &self.flat_attrs_resolutions,
            ValueTag::Thunk => &self.flat_thunk_resolutions,
            ValueTag::Lambda => &self.flat_lambda_resolutions,
            ValueTag::Primop => &self.flat_primop_resolutions,
            _ => return,
        };
        counter.set(counter.get().saturating_add(1));
    }

    /// Records thunk force-state sidecar `Arc` clones in an owned snapshot.
    #[inline]
    pub(super) fn note_thunk_state_arc_clones(&self, clones: u64) {
        self.thunk_state_arc_clones
            .set(self.thunk_state_arc_clones.get().saturating_add(clones));
    }

    /// Returns a plain-value copy of all counters.
    pub(crate) fn snapshot(&self) -> EvalHeapDerefCountersSnapshot {
        EvalHeapDerefCountersSnapshot {
            record_probes_string: self.record_probes_string.get(),
            record_probes_path: self.record_probes_path.get(),
            record_probes_list: self.record_probes_list.get(),
            record_probes_attrs: self.record_probes_attrs.get(),
            record_probes_lambda: self.record_probes_lambda.get(),
            record_probes_primop: self.record_probes_primop.get(),
            record_probes_thunk: self.record_probes_thunk.get(),
            record_probes_other: self.record_probes_other.get(),
            flat_string_resolutions: self.flat_string_resolutions.get(),
            flat_path_resolutions: self.flat_path_resolutions.get(),
            flat_list_resolutions: self.flat_list_resolutions.get(),
            flat_attrs_resolutions: self.flat_attrs_resolutions.get(),
            flat_thunk_resolutions: self.flat_thunk_resolutions.get(),
            flat_lambda_resolutions: self.flat_lambda_resolutions.get(),
            flat_primop_resolutions: self.flat_primop_resolutions.get(),
            payload_arc_clones: self.payload_arc_clones.get(),
            thunk_state_arc_clones: self.thunk_state_arc_clones.get(),
        }
    }
}

/// A point-in-time copy of one heap's dereference counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EvalHeapDerefCountersSnapshot {
    /// Record-table probes issued for string handles.
    pub(crate) record_probes_string: u64,
    /// Record-table probes issued for path handles.
    pub(crate) record_probes_path: u64,
    /// Record-table probes issued for list handles.
    pub(crate) record_probes_list: u64,
    /// Record-table probes issued for attrset handles.
    pub(crate) record_probes_attrs: u64,
    /// Record-table probes issued for lambda handles.
    pub(crate) record_probes_lambda: u64,
    /// Record-table probes issued for partially applied builtin handles.
    pub(crate) record_probes_primop: u64,
    /// Record-table probes issued for thunk handles.
    pub(crate) record_probes_thunk: u64,
    /// Record-table probes issued under any other tag.
    pub(crate) record_probes_other: u64,
    /// String resolutions served by the flat store without a record probe.
    pub(crate) flat_string_resolutions: u64,
    /// Path resolutions served by the flat store without a record probe.
    pub(crate) flat_path_resolutions: u64,
    /// List resolutions served by the flat store without a record probe.
    pub(crate) flat_list_resolutions: u64,
    /// Attrset resolutions served by the flat store without a record probe.
    pub(crate) flat_attrs_resolutions: u64,
    /// Thunk resolutions served by the flat store without a record probe.
    pub(crate) flat_thunk_resolutions: u64,
    /// Lambda resolutions served by the flat store without a record probe.
    pub(crate) flat_lambda_resolutions: u64,
    /// Partially-applied-builtin resolutions served by the flat store.
    pub(crate) flat_primop_resolutions: u64,
    /// Legacy payload-handle `Arc` clones; zero after FV-6.
    pub(crate) payload_arc_clones: u64,
    /// Thunk force-state sidecar `Arc` clones retained across evaluator re-entry.
    pub(crate) thunk_state_arc_clones: u64,
}
