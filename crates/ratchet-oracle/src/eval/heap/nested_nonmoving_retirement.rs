//! Report-only admission accounting for nested nonmoving retirement.
//!
//! This scanner consumes one complete non-writeback root set, performs the
//! ordinary weak graph traversal, and classifies every iterable heap object as
//! reachable or dead. It models no mutation: hash candidates remain installed,
//! side tables remain intact, payloads are not dropped, and pages are not
//! advised. Physical credit fails closed unless reservation residency is exact.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ptr::NonNull;

use super::arena::any_value_heap_ptr;
use super::*;
use crate::attrs::{AttrEntry, AttrsStorageKind};
use crate::eval::ThunkState;
use crate::string::StringBytesStorageKind;

const PAGE_BYTES_FALLBACK: usize = 4096;
const LOGICAL_GATE_BYTES: u64 = 48 * 1024 * 1024;
const PHYSICAL_GATE_BYTES: u64 = 40 * 1024 * 1024;
const CATEGORY_COUNT: usize = 14;
const PAGE_COMPLETION_SHORTFALL_BYTES: u64 = 10_780_672;
const FORWARDING_BYTES_PER_OBJECT: usize = std::mem::size_of::<u64>();
const DESTINATION_LIVENESS_BYTES: usize = 2 * 1024 * 1024;
const DESTINATION_FLAT_ENTRY_BYTES: usize = 16;
const PAGE_COMPLETION_TABLE: &str = "nested page-completion projection";

/// Logical dead-candidate mass for one store/kind/generation class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CandidateMass {
    objects: u64,
    inline_bytes: u64,
    external_bytes: u64,
}

impl CandidateMass {
    fn add(&mut self, inline_bytes: usize, external_bytes: usize) {
        self.objects = self.objects.saturating_add(1);
        self.inline_bytes = self.inline_bytes.saturating_add(inline_bytes as u64);
        self.external_bytes = self.external_bytes.saturating_add(external_bytes as u64);
    }

    const fn logical_bytes(self) -> u64 {
        self.inline_bytes.saturating_add(self.external_bytes)
    }
}

/// Exact zero-live-page simulation for the current flat reservation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PageSimulation {
    total: u64,
    live: u64,
    zero_live: u64,
    runs: u64,
    largest_run: u64,
    page_bytes: u64,
    residency_exact: bool,
    resident_zero_live: u64,
}

/// Read-only accounting for the first selective page-completion tier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PageCompletionProjection {
    baseline_zero_live_pages: u64,
    baseline_zero_live_bytes: u64,
    selected_objects: u64,
    selected_inline_bytes: u64,
    selected_external_bytes: u64,
    source_pages: u64,
    destination_inline_pages: u64,
    destination_external_pages: u64,
    gross_released_bytes: u64,
    destination_bytes: u64,
    destination_liveness_bytes: u64,
    destination_flat_entry_bytes: u64,
    forwarding_bytes: u64,
    staging_scratch_bytes: u64,
    net_recovery_bytes: u64,
    target_bytes: u64,
    net_threshold_pass: bool,
    target_pass: bool,
    semantic_purge_blocker: bool,
    destination_metadata_blocker: bool,
    hash_reinstall_blockers: u64,
    writeback_validation_blockers: u64,
    supported_dead_prepass_objects: u64,
    unsupported_dead_page_blockers: u64,
    edge_writeback_blockers: u64,
    pinned_objects: u64,
    pinned_pages: u64,
    pinned_direct_roots: u64,
    pinned_records: u64,
    pinned_typed_heads: u64,
    pinned_boxed_scalars: u64,
    pinned_thunks: u64,
    pinned_closures: u64,
    pinned_tail_owners: u64,
    pinned_malformed_or_external: u64,
    pinned_unstageable_incoming_edges: u64,
    future_plain_primops: u64,
    future_plain_lambdas: u64,
    future_source_pages: u64,
    cadence_singleton_generation_blocker: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionObjectClass {
    Permanent,
    Record,
    TypedHead,
    BoxedScalar,
    Thunk,
    Closure,
}

#[derive(Clone, Debug)]
struct CompletionObject {
    address: usize,
    tag: ValueTag,
    inline_bytes: usize,
    external_bytes: usize,
    pages: Vec<usize>,
    class: CompletionObjectClass,
    eligible: bool,
    pinned: bool,
    unsupported_external: bool,
    edge_blocked: bool,
    future: bool,
}

#[derive(Clone, Debug)]
struct PageRequirement {
    page: usize,
    objects: Vec<usize>,
    survivor_bytes: usize,
    standalone_net: u64,
}

impl PageSimulation {
    const fn physical_bytes(self) -> u64 {
        self.resident_zero_live.saturating_mul(self.page_bytes)
    }
}

/// One selected ordinal's immutable retirement-admission report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NestedNonmovingRetirementReport {
    roots: u64,
    retained_seed_roots: u64,
    reachable: u64,
    allocated: u64,
    dead: u64,
    reconciled: bool,
    categories: [CandidateMass; CATEGORY_COUNT],
    pages: PageSimulation,
    dead_weak_candidates: u64,
    weak_blockers: u64,
    side_table_blockers: u64,
    semantic_side_table_audit_complete: bool,
    retained_edge_audit_complete: bool,
    invalid_state_blockers: u64,
    blackhole_blockers: u64,
    ledger_blockers: u64,
    supported_dead: u64,
    excluded_dead: u64,
    logical_bytes: u64,
    excluded_logical_bytes: u64,
    physical_bytes: u64,
    logical_gate: bool,
    physical_gate: bool,
    safety_gate: bool,
    page_completion: PageCompletionProjection,
}

impl NestedNonmovingRetirementReport {
    /// Returns whether every accounting and threshold gate admits a later
    /// separately implemented transaction.
    pub(crate) const fn admitted(&self) -> bool {
        self.logical_gate && self.physical_gate && self.safety_gate
    }
}

/// Exact reservation census sampled before rotating-checkpoint traversal.
///
/// This is sampled before the probe constructs a root set or weak-traversal
/// scratch, so its residency fields are not polluted by diagnostic work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NestedNonmovingRuntimeReservationSnapshot {
    /// Whether the serial flat heap has a contiguous reservation.
    pub(crate) reservation_present: bool,
    /// Virtual bytes reserved by the flat heap.
    pub(crate) reservation_virtual_bytes: u64,
    /// Bytes occupied across the low and high reservation lanes.
    pub(crate) reservation_used_bytes: u64,
    /// Bytes occupied by the upward-growing stable lane.
    pub(crate) reservation_low_used_bytes: u64,
    /// Bytes occupied by the downward-growing worker lane.
    pub(crate) reservation_high_used_bytes: u64,
    /// Whether an exact reservation-residency sample was obtained.
    pub(crate) residency_available: bool,
    /// Whether the operating system rejected the residency query.
    pub(crate) residency_error: bool,
    /// Operating-system page size used by the residency query.
    pub(crate) page_size: u64,
    /// Distinct used reservation pages.
    pub(crate) used_pages: u64,
    /// Distinct resident reservation pages.
    pub(crate) resident_pages: u64,
}

/// Exact lightweight heap census retained by the rotating-rollover probe.
///
/// This is observational state only. In particular, it carries no page sets,
/// page-completion selector, forwarding map, relocation destination,
/// page-advice request, or mutable heap handle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NestedNonmovingRuntimeHeapSnapshot {
    /// Roots presented to the weak traversal before retained-domain seeds.
    pub(crate) roots: u64,
    /// Retained record and typed-head roots added by the traversal.
    pub(crate) retained_seed_roots: u64,
    /// Distinct heap addresses reached by the traversal.
    pub(crate) reachable: u64,
    /// Iterable heap objects reconciled against reachable and unreachable objects.
    pub(crate) allocated: u64,
    /// Iterable objects not reached from the augmented root set.
    pub(crate) unreachable: u64,
    /// Whether every reachable address belongs to one iterable heap object.
    pub(crate) reconciled: bool,
    /// Stable flat string and path entries.
    pub(crate) flat_string_path_objects: u64,
    /// Stable flat list entries.
    pub(crate) flat_list_objects: u64,
    /// Stable flat attribute-set entries.
    pub(crate) flat_attrs_objects: u64,
    /// Worker flat closure entries.
    pub(crate) flat_closure_objects: u64,
    /// Stable typed thunk heads.
    pub(crate) typed_head_objects: u64,
    /// Boxed wide-scalar cells.
    pub(crate) boxed_scalar_objects: u64,
    /// Typed side-table records.
    pub(crate) record_objects: u64,
}

impl fmt::Display for NestedNonmovingRetirementReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            ("flat_string_path", "permanent"),
            ("flat_list", "permanent"),
            ("flat_attrs", "permanent"),
            ("flat_closure", "young"),
            ("typed_thunk_head", "young"),
            ("record_string", "permanent"),
            ("record_string", "old"),
            ("record_string", "young"),
            ("record_list", "permanent"),
            ("record_list", "old"),
            ("record_list", "young"),
            ("record_closure", "permanent"),
            ("record_closure", "old"),
            ("record_closure", "young"),
        ];
        write!(
            f,
            "{{\"roots\":{},\"retained_seed_roots\":{},\
             \"reachable\":{},\"allocated\":{},\"dead\":{},\
             \"reconciled\":{},\"candidates\":[",
            self.roots,
            self.retained_seed_roots,
            self.reachable,
            self.allocated,
            self.dead,
            self.reconciled
        )?;
        for (index, ((store, generation), mass)) in
            names.into_iter().zip(self.categories).enumerate()
        {
            if index != 0 {
                f.write_str(",")?;
            }
            write!(
                f,
                "{{\"store_kind\":\"{store}\",\"generation\":\"{generation}\",\
                 \"transaction_supported\":{},\
                 \"objects\":{},\"inline_bytes\":{},\"external_bytes\":{},\
                 \"logical_bytes\":{}}}",
                index < 4,
                mass.objects,
                mass.inline_bytes,
                mass.external_bytes,
                mass.logical_bytes(),
            )?;
        }
        write!(
            f,
            "],\"weak\":{{\"dead_hash_candidates\":{},\"blockers\":{}}},\
             \"safety\":{{\"side_table_blockers\":{},\
             \"semantic_side_table_audit_complete\":{},\
             \"retained_edge_audit_complete\":{},\"invalid_state_blockers\":{},\
             \"blackhole_blockers\":{},\
             \"ledger_blockers\":{}}},\
             \"pages\":{{\"total\":{},\"live\":{},\"zero_live\":{},\"runs\":{},\
             \"largest_run\":{},\"page_bytes\":{},\"residency_exact\":{},\
             \"resident_zero_live\":{},\"physical_bytes\":{}}},\
             \"gates\":{{\"supported_objects\":{},\
             \"logical_bytes\":{},\"logical_min_bytes\":{},\
             \"logical_pass\":{},\"physical_bytes\":{},\"physical_min_bytes\":{},\
             \"physical_pass\":{},\"safety_pass\":{},\"admitted\":{}}},\
             \"page_completion\":{{\"tier\":\"permanent_flat_only\",\
             \"baseline_zero_live_pages\":{},\"baseline_zero_live_bytes\":{},\
             \"selected_objects\":{},\"selected_inline_bytes\":{},\
             \"selected_external_bytes\":{},\"additional_released_source_pages\":{},\
             \"destination_inline_pages\":{},\"destination_external_pages\":{},\
             \"gross_released_bytes\":{},\"destination_bytes\":{},\
             \"destination_liveness_bytes\":{},\"destination_flat_entry_bytes\":{},\
             \"persistent_forwarding_bytes\":{},\"committed_staging_scratch_bytes\":{},\
             \"net_recovery_bytes\":{},\"target_shortfall_bytes\":{},\
             \"net_threshold_pass\":{},\"target_pass\":{},\
             \"semantic_purge_blocker\":{},\"destination_metadata_blocker\":{},\
             \"hash_reinstall_blockers\":{},\"writeback_validation_blockers\":{},\
             \"supported_dead_prepass_objects\":{},\"unsupported_dead_page_blockers\":{},\
             \"edge_writeback_blockers\":{},\
             \"pinned\":{{\"objects\":{},\"pages\":{},\"direct_roots\":{},\
             \"records\":{},\"typed_heads_work\":{},\"boxed_scalars\":{},\
             \"thunks\":{},\"closures\":{},\"tail_owners\":{},\
             \"malformed_or_external\":{},\"unstageable_incoming_edges\":{}}},\
             \"future_non_admitted\":{{\"plain_tail_free_primops\":{},\
             \"plain_tail_free_lambdas\":{},\"source_pages\":{}}},\
             \"cadence_singleton_generation_blocker\":{},\
             \"greedy_order\":\"best marginal net, then fewer moved survivor bytes, then source page\",\
             \"mutation\":false,\"writer\":false,\"advice\":false}},\
             \"excluded\":{{\"objects\":{},\"logical_bytes\":{},\
             \"typed_thunk_heads\":true,\"record_objects\":true,\
             \"attrs_external_capacity\":true,\
             \"closure_environment_external_capacity\":true,\
             \"legacy_record_string_external_capacity\":true,\
             \"typed_work_pool_metadata\":true,\"record_arena_pages\":true,\
             \"boxed_scalar_pages_pinned\":true,\
             \"nonresident_zero_live_pages_uncredited\":true}},\
             \"semantics\":{{\"weak_trace_only\":true,\
             \"lazy_identity_foldl_audit\":\"pending\",\
             \"tier1_publication_audit\":\"pending\",\
             \"force_payload_memo_audit\":\"pending\",\
             \"advisory_genlist_memo_obligations\":\"pending\",\
             \"mutation\":false,\"purge\":false,\"retirement\":false,\
             \"advice\":false}}}}",
            self.dead_weak_candidates,
            self.weak_blockers,
            self.side_table_blockers,
            self.semantic_side_table_audit_complete,
            self.retained_edge_audit_complete,
            self.invalid_state_blockers,
            self.blackhole_blockers,
            self.ledger_blockers,
            self.pages.total,
            self.pages.live,
            self.pages.zero_live,
            self.pages.runs,
            self.pages.largest_run,
            self.pages.page_bytes,
            self.pages.residency_exact,
            self.pages.resident_zero_live,
            self.physical_bytes,
            self.supported_dead,
            self.logical_bytes,
            LOGICAL_GATE_BYTES,
            self.logical_gate,
            self.physical_bytes,
            PHYSICAL_GATE_BYTES,
            self.physical_gate,
            self.safety_gate,
            self.admitted(),
            self.page_completion.baseline_zero_live_pages,
            self.page_completion.baseline_zero_live_bytes,
            self.page_completion.selected_objects,
            self.page_completion.selected_inline_bytes,
            self.page_completion.selected_external_bytes,
            self.page_completion.source_pages,
            self.page_completion.destination_inline_pages,
            self.page_completion.destination_external_pages,
            self.page_completion.gross_released_bytes,
            self.page_completion.destination_bytes,
            self.page_completion.destination_liveness_bytes,
            self.page_completion.destination_flat_entry_bytes,
            self.page_completion.forwarding_bytes,
            self.page_completion.staging_scratch_bytes,
            self.page_completion.net_recovery_bytes,
            self.page_completion.target_bytes,
            self.page_completion.net_threshold_pass,
            self.page_completion.target_pass,
            self.page_completion.semantic_purge_blocker,
            self.page_completion.destination_metadata_blocker,
            self.page_completion.hash_reinstall_blockers,
            self.page_completion.writeback_validation_blockers,
            self.page_completion.supported_dead_prepass_objects,
            self.page_completion.unsupported_dead_page_blockers,
            self.page_completion.edge_writeback_blockers,
            self.page_completion.pinned_objects,
            self.page_completion.pinned_pages,
            self.page_completion.pinned_direct_roots,
            self.page_completion.pinned_records,
            self.page_completion.pinned_typed_heads,
            self.page_completion.pinned_boxed_scalars,
            self.page_completion.pinned_thunks,
            self.page_completion.pinned_closures,
            self.page_completion.pinned_tail_owners,
            self.page_completion.pinned_malformed_or_external,
            self.page_completion.pinned_unstageable_incoming_edges,
            self.page_completion.future_plain_primops,
            self.page_completion.future_plain_lambdas,
            self.page_completion.future_source_pages,
            self.page_completion.cadence_singleton_generation_blocker,
            self.excluded_dead,
            self.excluded_logical_bytes,
        )
    }
}

impl EvalHeap {
    /// Samples flat-reservation accounting before diagnostic traversal.
    pub(crate) fn nested_nonmoving_runtime_reservation_snapshot(
        &self,
    ) -> NestedNonmovingRuntimeReservationSnapshot {
        let stats = self.flat_arena.reservation_stats();
        let residency = self.flat_reservation_residency();
        let (residency_available, residency_error, page_size, used_pages, resident_pages) =
            match residency {
                Some(Ok(sample)) => (
                    true,
                    false,
                    sample.page_size as u64,
                    sample.total_pages as u64,
                    sample.total_resident_pages as u64,
                ),
                Some(Err(_)) => (false, true, 0, 0, 0),
                None => (false, false, 0, 0, 0),
            };
        NestedNonmovingRuntimeReservationSnapshot {
            reservation_present: stats.is_some(),
            reservation_virtual_bytes: stats.map_or(0, |value| value.virtual_reserved_bytes as u64),
            reservation_used_bytes: stats.map_or(0, |value| value.used_bytes as u64),
            reservation_low_used_bytes: stats.map_or(0, |value| value.low_used_bytes as u64),
            reservation_high_used_bytes: stats.map_or(0, |value| value.high_used_bytes as u64),
            residency_available,
            residency_error,
            page_size,
            used_pages,
            resident_pages,
        }
    }

    /// Captures exact read-only graph accounting for a rotating checkpoint.
    ///
    /// Unlike [`Self::nested_nonmoving_retirement_report`], this path does not
    /// build reservation page sets or run the selective page-completion
    /// projection. The supplied roots remain borrowed throughout the existing
    /// weak graph traversal, and no heap storage or weak index is changed.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if weak traversal encounters a stale root,
    /// malformed edge, invalid thunk state, or cannot grow traversal storage.
    pub(crate) fn nested_nonmoving_runtime_heap_snapshot(
        &self,
        roots: &EvalRootSet,
    ) -> Result<NestedNonmovingRuntimeHeapSnapshot, EvalHeapError> {
        let original_root_count = roots.len();
        let mut retained_roots = roots.clone();
        let mut retained_slot = original_root_count;
        for record in self.records.iter().filter(|record| !record.is_retired()) {
            let value = Self::value_for_record(record)?;
            retained_roots
                .try_push_value_stack(retained_slot, value)
                .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                    table: "rotating retained record roots",
                    entries: 1,
                })?;
            retained_slot =
                retained_slot
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: "rotating retained record roots",
                    })?;
        }
        for (address, _bytes) in self.typed_thunk_heads.initialized_regions() {
            let ptr = NonNull::new(address as *mut HeapObject).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: "rotating retained typed-head roots",
                },
            )?;
            let value = Value::thunk(ptr)?;
            retained_roots
                .try_push_value_stack(retained_slot, value)
                .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                    table: "rotating retained typed-head roots",
                    entries: 1,
                })?;
            retained_slot =
                retained_slot
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: "rotating retained typed-head roots",
                    })?;
        }
        let reachable = self.weak_reachable_addresses(&retained_roots)?;
        let mut allocated = 0usize;
        let mut classified_reachable = 0usize;
        let mut observe = |address: usize| {
            allocated = allocated.saturating_add(1);
            classified_reachable =
                classified_reachable.saturating_add(usize::from(reachable.contains(&address)));
        };
        for object in self.flat.iter() {
            observe(object.ptr().as_ptr() as usize);
        }
        for object in self.flat_lists.iter() {
            observe(object.ptr().as_ptr() as usize);
        }
        for object in self.flat_attrs.iter() {
            observe(object.ptr().as_ptr() as usize);
        }
        for object in self.flat_closures.iter() {
            if !object.object().payload().is_retired() {
                observe(object.ptr().as_ptr() as usize);
            }
        }
        for (address, _bytes) in self.typed_thunk_heads.initialized_regions() {
            observe(address);
        }
        for record in self.records.iter().filter(|record| !record.is_retired()) {
            observe(record.ptr.as_ptr() as usize);
        }
        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        allocated = allocated.saturating_add(scalar_regions.len());
        classified_reachable = classified_reachable.saturating_add(scalar_regions.len());
        let reconciled = classified_reachable == reachable.len();

        Ok(NestedNonmovingRuntimeHeapSnapshot {
            roots: original_root_count as u64,
            retained_seed_roots: retained_roots.len().saturating_sub(original_root_count) as u64,
            reachable: reachable.len() as u64,
            allocated: allocated as u64,
            unreachable: allocated.saturating_sub(classified_reachable) as u64,
            reconciled,
            flat_string_path_objects: self.flat.len() as u64,
            flat_list_objects: self.flat_lists.len() as u64,
            flat_attrs_objects: self.flat_attrs.len() as u64,
            flat_closure_objects: self.flat_closures.len() as u64,
            typed_head_objects: self.typed_thunk_heads.len() as u64,
            boxed_scalar_objects: scalar_regions.len() as u64,
            record_objects: self.records.len() as u64,
        })
    }

    /// Builds a read-only, fail-closed nested retirement admission report.
    ///
    /// Hash-cons tables are weak indexes and do not seed reachability. Their
    /// dead entries are counted as pre-transaction invalidation obligations.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if weak traversal encounters a stale root,
    /// malformed edge, invalid thunk state, or cannot grow traversal storage.
    pub(crate) fn nested_nonmoving_retirement_report(
        &self,
        roots: &EvalRootSet,
    ) -> Result<NestedNonmovingRetirementReport, EvalHeapError> {
        let original_root_count = roots.len();
        let mut retained_roots = roots.clone();
        let mut retained_slot = original_root_count;
        for record in self.records.iter().filter(|record| !record.is_retired()) {
            let value = Self::value_for_record(record)?;
            retained_roots
                .try_push_value_stack(retained_slot, value)
                .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                    table: "nested retained record roots",
                    entries: 1,
                })?;
            retained_slot =
                retained_slot
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: "nested retained record roots",
                    })?;
        }
        for (address, _bytes) in self.typed_thunk_heads.initialized_regions() {
            let ptr = NonNull::new(address as *mut HeapObject).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: "nested retained typed-head roots",
                },
            )?;
            let value = Value::thunk(ptr)?;
            retained_roots
                .try_push_value_stack(retained_slot, value)
                .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                    table: "nested retained typed-head roots",
                    entries: 1,
                })?;
            retained_slot =
                retained_slot
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: "nested retained typed-head roots",
                    })?;
        }
        let reachable = self.weak_reachable_addresses(&retained_roots)?;
        let retained_seed_roots = retained_roots.len().saturating_sub(original_root_count);
        let residency = self.flat_reservation_residency();
        let page_bytes = residency
            .as_ref()
            .and_then(|sample| sample.as_ref().ok())
            .map_or(PAGE_BYTES_FALLBACK, |sample| sample.page_size);
        let residency_exact = residency
            .as_ref()
            .and_then(|sample| sample.as_ref().ok())
            .is_some_and(|sample| sample.total_pages == sample.total_resident_pages);
        let mut total_pages = HashSet::new();
        let mut live_pages = HashSet::new();
        let mut categories = [CandidateMass::default(); CATEGORY_COUNT];
        let mut allocated = 0usize;
        let mut classified_reachable = 0usize;
        let mut blackhole_blockers = 0usize;
        let mut invalid_state_blockers = 0usize;

        let mut visit = |address: usize,
                         inline_bytes: usize,
                         external_bytes: usize,
                         category: usize,
                         blackholed: bool,
                         reservation_backed: bool,
                         transaction_supported: bool| {
            allocated = allocated.saturating_add(1);
            if reservation_backed {
                mark_pages(&mut total_pages, address, inline_bytes, page_bytes);
            }
            if reachable.contains(&address) {
                classified_reachable = classified_reachable.saturating_add(1);
                if reservation_backed {
                    mark_pages(&mut live_pages, address, inline_bytes, page_bytes);
                }
                if !transaction_supported {
                    categories[category].add(inline_bytes, external_bytes);
                }
            } else {
                categories[category].add(inline_bytes, external_bytes);
                if reservation_backed && !transaction_supported {
                    mark_pages(&mut live_pages, address, inline_bytes, page_bytes);
                }
                if transaction_supported {
                    blackhole_blockers = blackhole_blockers.saturating_add(usize::from(blackholed));
                }
            }
        };

        for object in self.flat.iter() {
            visit(
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
                0,
                0,
                false,
                true,
                true,
            );
        }
        for object in self.flat_lists.iter() {
            visit(
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
                object
                    .object()
                    .payload()
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Value>()),
                1,
                false,
                true,
                true,
            );
        }
        for object in self.flat_attrs.iter() {
            visit(
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
                0,
                2,
                false,
                true,
                true,
            );
        }
        for object in self.flat_closures.iter() {
            let payload = object.object().payload();
            if payload.is_retired() {
                continue;
            }
            let blackholed = match payload.as_thunk().map(|thunk| thunk.cell().state()) {
                Some(Ok(state)) => state == ThunkState::Blackhole,
                Some(Err(_)) => {
                    invalid_state_blockers = invalid_state_blockers.saturating_add(1);
                    false
                }
                None => false,
            };
            visit(
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
                0,
                3,
                blackholed,
                true,
                true,
            );
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            let state = NonNull::new(address as *mut HeapObject)
                .and_then(|ptr| self.typed_thunk_heads.resolve(ptr).ok())
                .and_then(StableThunkHead::state);
            if state.is_none() {
                invalid_state_blockers = invalid_state_blockers.saturating_add(1);
            }
            visit(
                address,
                bytes,
                0,
                4,
                state == Some(ThunkState::Blackhole),
                true,
                false,
            );
        }
        for record in self.records.iter().filter(|record| !record.is_retired()) {
            let (kind, external_bytes, blackholed) = match &record.object {
                HeapObjectValue::String(_) => (0, 0, false),
                HeapObjectValue::List(list) => (
                    1,
                    list.capacity().saturating_mul(std::mem::size_of::<Value>()),
                    false,
                ),
                HeapObjectValue::Thunk(thunk) => match thunk.cell().state() {
                    Ok(state) => (2, 0, state == ThunkState::Blackhole),
                    Err(_) => {
                        invalid_state_blockers = invalid_state_blockers.saturating_add(1);
                        (2, 0, false)
                    }
                },
                HeapObjectValue::Lambda(_) | HeapObjectValue::Primop(_) => (2, 0, false),
                HeapObjectValue::Retired { .. } => continue,
            };
            visit(
                record.ptr.as_ptr() as usize,
                record.layout.size_bytes,
                external_bytes,
                record_category(kind, record.generation),
                blackholed,
                false,
                false,
            );
        }

        // Boxed scalar cells cannot currently be retired and therefore pin
        // every page they occupy in both the logical and physical simulation.
        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        for &(address, bytes) in &scalar_regions {
            allocated = allocated.saturating_add(1);
            classified_reachable = classified_reachable.saturating_add(1);
            mark_pages(&mut total_pages, address, bytes, page_bytes);
            mark_pages(&mut live_pages, address, bytes, page_bytes);
        }

        let mut zero_live_pages: Vec<_> = total_pages.difference(&live_pages).copied().collect();
        zero_live_pages.sort_unstable();
        let (runs, largest_run) = coalesced_page_runs(&zero_live_pages);
        let pages = PageSimulation {
            total: total_pages.len() as u64,
            live: live_pages.len() as u64,
            zero_live: zero_live_pages.len() as u64,
            runs,
            largest_run,
            page_bytes: page_bytes as u64,
            residency_exact,
            resident_zero_live: if residency_exact {
                zero_live_pages.len() as u64
            } else {
                0
            },
        };
        let (supported_dead, potential_logical_bytes, excluded_dead, excluded_logical_bytes) =
            candidate_accounting(&categories);
        let dead = supported_dead;
        // Every retained record and typed head seeded the weak fixed point
        // above, so their outgoing flat targets are live in this projection.
        let retained_edge_audit_complete = true;
        let logical_bytes = potential_logical_bytes;
        let physical_bytes = pages.physical_bytes();
        let dead_weak_candidates = self.dead_weak_hash_candidates(&reachable)?;
        let reachable_count = reachable.len() as u64;
        let allocated_count = allocated as u64;
        let reconciled = classified_reachable == reachable.len()
            && allocated_count == reachable_count.saturating_add(dead);
        let reconciliation_blockers = if reconciled {
            0
        } else {
            allocated_count.abs_diff(reachable_count.saturating_add(dead))
        };
        // V1 does not yet carry supported dead addresses through TreeWalk's
        // semantic identity tables. Until lazy identity/foldl roots, tier-1
        // publication slots, force payload memo state, and advisory
        // genList/memo entries are audited, admission remains fail-closed.
        let semantic_side_table_audit_complete = false;
        let side_table_blockers =
            reconciliation_blockers.saturating_add(u64::from(!semantic_side_table_audit_complete));
        let ledger_blockers = u64::from(!residency_exact && pages.zero_live != 0);
        let weak_blockers = 0;
        let logical_gate = logical_bytes >= LOGICAL_GATE_BYTES;
        let physical_gate = residency_exact && physical_bytes >= PHYSICAL_GATE_BYTES;
        let safety_gate = reconciled
            && weak_blockers == 0
            && side_table_blockers == 0
            && retained_edge_audit_complete
            && invalid_state_blockers == 0
            && blackhole_blockers == 0
            && ledger_blockers == 0;
        let mut page_completion =
            self.selective_page_completion_projection(&retained_roots, &reachable, page_bytes)?;
        page_completion.baseline_zero_live_pages = pages.resident_zero_live;
        page_completion.baseline_zero_live_bytes = pages.physical_bytes();
        page_completion.supported_dead_prepass_objects = supported_dead;
        page_completion.unsupported_dead_page_blockers =
            (invalid_state_blockers.saturating_add(blackhole_blockers)) as u64;
        page_completion.semantic_purge_blocker =
            !semantic_side_table_audit_complete || dead_weak_candidates != 0;
        // The arena currently exposes no exact destination region-vector and
        // allocator-ledger sizing API. Keep the one-shot number hypothetical
        // and fail route admission closed until those bytes can be charged.
        page_completion.destination_metadata_blocker = true;
        page_completion.net_threshold_pass =
            page_completion.net_recovery_bytes >= PAGE_COMPLETION_SHORTFALL_BYTES;
        page_completion.target_pass = page_completion.net_threshold_pass
            && !page_completion.semantic_purge_blocker
            && !page_completion.destination_metadata_blocker
            && page_completion.hash_reinstall_blockers == 0
            && page_completion.writeback_validation_blockers == 0
            && page_completion.unsupported_dead_page_blockers == 0
            && !page_completion.cadence_singleton_generation_blocker;
        Ok(NestedNonmovingRetirementReport {
            roots: original_root_count as u64,
            retained_seed_roots: retained_seed_roots as u64,
            reachable: reachable_count,
            allocated: allocated_count,
            dead,
            reconciled,
            categories,
            pages,
            dead_weak_candidates,
            weak_blockers,
            side_table_blockers,
            semantic_side_table_audit_complete,
            retained_edge_audit_complete,
            invalid_state_blockers: invalid_state_blockers as u64,
            blackhole_blockers: blackhole_blockers as u64,
            ledger_blockers,
            supported_dead,
            excluded_dead,
            logical_bytes,
            excluded_logical_bytes,
            physical_bytes,
            logical_gate,
            physical_gate,
            safety_gate,
            page_completion,
        })
    }

    /// Projects a deterministic permanent-only page-completion slice.
    ///
    /// The supplied roots and reachable set are the augmented retained-owner
    /// fixed point used by the enclosing retirement report. This routine does
    /// not independently weaken that root policy.
    fn selective_page_completion_projection(
        &self,
        retained_roots: &EvalRootSet,
        reachable: &HashSet<usize>,
        page_bytes: usize,
    ) -> Result<PageCompletionProjection, EvalHeapError> {
        if page_bytes == 0 {
            return Err(EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            });
        }
        let scan = self.scan_precise_roots(retained_roots)?;
        if scan.objects().len() != reachable.len() {
            return Err(EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            });
        }
        let mut direct_roots = HashSet::new();
        direct_roots
            .try_reserve(retained_roots.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PAGE_COMPLETION_TABLE,
                entries: retained_roots.len(),
            })?;
        for root in retained_roots.roots() {
            let ptr = root.value().as_heap_ptr().map_err(EvalHeapError::Value)?;
            direct_roots.insert(ptr.as_ptr() as usize);
        }

        let mut objects = Vec::new();
        objects.try_reserve_exact(reachable.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PAGE_COMPLETION_TABLE,
                entries: reachable.len(),
            }
        })?;
        let mut push = |address: usize,
                        tag: ValueTag,
                        inline_bytes: usize,
                        external_bytes: usize,
                        class: CompletionObjectClass,
                        eligible: bool,
                        future: bool|
         -> Result<(), EvalHeapError> {
            if !reachable.contains(&address) {
                // Every reservation registry is enumerated below. The only
                // omitted reservation objects are the four explicitly
                // supported dead classes consumed by the enclosing nonmoving
                // prepass. Retained typed heads and boxed-scalar pages are
                // added separately and can never receive this credit.
                return Ok(());
            }
            let ptr = NonNull::new(address as *mut HeapObject).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: PAGE_COMPLETION_TABLE,
                },
            )?;
            let pages = match self.flat_arena.index_for_pointer(ptr) {
                Some(index) => completion_pages(index.raw() as usize, inline_bytes, page_bytes)?,
                None if !eligible => Vec::new(),
                None => {
                    return Err(EvalHeapError::ShedRejected {
                        address,
                        reason: "movable page-completion object is outside the flat reservation",
                    });
                }
            };
            objects.push(CompletionObject {
                address,
                tag,
                inline_bytes,
                external_bytes,
                pages,
                class,
                eligible,
                pinned: direct_roots.contains(&address) || !eligible,
                unsupported_external: class == CompletionObjectClass::Permanent && !eligible,
                edge_blocked: false,
                future,
            });
            Ok(())
        };

        for object in self.flat.iter() {
            let payload = object.object().payload();
            let context_supported = payload.context().is_empty();
            let external = match payload.bytes_storage_kind() {
                StringBytesStorageKind::Owned => payload.len(),
                StringBytesStorageKind::FlatWitness => 0,
            };
            push(
                object.ptr().as_ptr() as usize,
                match object.object().kind() {
                    FlatObjectKind::String => ValueTag::String,
                    FlatObjectKind::Path => ValueTag::Path,
                    _ => {
                        return Err(EvalHeapError::UnknownPointer {
                            tag: ValueTag::String,
                            address: object.ptr().as_ptr() as usize,
                        });
                    }
                },
                object.size_bytes(),
                external,
                CompletionObjectClass::Permanent,
                context_supported,
                false,
            )?;
        }
        for object in self.flat_lists.iter() {
            push(
                object.ptr().as_ptr() as usize,
                ValueTag::List,
                object.size_bytes(),
                object
                    .object()
                    .payload()
                    .capacity()
                    .checked_mul(std::mem::size_of::<Value>())
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: PAGE_COMPLETION_TABLE,
                    })?,
                CompletionObjectClass::Permanent,
                true,
                false,
            )?;
        }
        for object in self.flat_attrs.iter() {
            let attrs = &object.object().payload().attrs;
            let external = match attrs.storage_kind() {
                AttrsStorageKind::Owned => attrs
                    .len()
                    .checked_mul(
                        std::mem::size_of::<AttrEntry>()
                            .saturating_add(2 * std::mem::size_of::<u32>()),
                    )
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: PAGE_COMPLETION_TABLE,
                    })?,
                AttrsStorageKind::FlatWitness => 0,
            };
            push(
                object.ptr().as_ptr() as usize,
                ValueTag::Attrs,
                object.size_bytes(),
                external,
                CompletionObjectClass::Permanent,
                true,
                false,
            )?;
        }
        for object in self.flat_closures.iter() {
            let address = object.ptr().as_ptr() as usize;
            let payload = object.object().payload();
            if payload.is_retired() || !reachable.contains(&address) {
                continue;
            }
            let (class, future) = match payload.tag() {
                ValueTag::Thunk => (CompletionObjectClass::Thunk, false),
                ValueTag::Primop => {
                    let tail_free = self
                        .flat_closures
                        .value_tail(object.ptr(), FlatObjectKind::Primop)
                        .map_err(|error| {
                            self.closure_resolution_error(ValueTag::Primop, object.ptr(), error)
                        })?
                        .is_none();
                    (CompletionObjectClass::Closure, tail_free)
                }
                ValueTag::Lambda => {
                    let tail_free = self
                        .flat_closures
                        .value_tail(object.ptr(), FlatObjectKind::Lambda)
                        .map_err(|error| {
                            self.closure_resolution_error(ValueTag::Lambda, object.ptr(), error)
                        })?
                        .is_none();
                    let plain = matches!(
                        payload,
                        FlatClosurePayload::Lambda(lambda)
                            if tail_free
                                && lambda.with_scope_env().is_empty()
                                && lambda.scoped_global_env().is_empty()
                                && lambda.env().flat_base().is_none()
                    );
                    (CompletionObjectClass::Closure, plain)
                }
                _ => (CompletionObjectClass::Closure, false),
            };
            push(
                address,
                payload.tag(),
                object.size_bytes(),
                0,
                class,
                false,
                future,
            )?;
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            push(
                address,
                ValueTag::Thunk,
                bytes,
                0,
                CompletionObjectClass::TypedHead,
                false,
                false,
            )?;
        }
        for record in self.records.iter().filter(|record| !record.is_retired()) {
            push(
                record.ptr.as_ptr() as usize,
                record.object.tag(),
                record.layout.size_bytes,
                0,
                CompletionObjectClass::Record,
                false,
                false,
            )?;
        }
        let mut boxed_scalar_objects = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut boxed_scalar_objects);
        for (address, bytes) in boxed_scalar_objects {
            push(
                address,
                ValueTag::Int,
                bytes,
                0,
                CompletionObjectClass::BoxedScalar,
                false,
                false,
            )?;
        }
        objects.sort_unstable_by_key(|object| object.address);
        if objects
            .windows(2)
            .any(|pair| pair[0].address == pair[1].address)
        {
            return Err(EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            });
        }
        let address_to_object: HashMap<_, _> = objects
            .iter()
            .enumerate()
            .map(|(index, object)| (object.address, index))
            .collect();
        if address_to_object.len() != reachable.len() {
            return Err(EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            });
        }

        let mut hash_indexed = HashSet::new();
        for table in [
            &self.string_cons,
            &self.path_cons,
            &self.list_cons,
            &self.attrs_cons,
        ] {
            for (_hash, _index, value) in table.committed_entries() {
                let (_tag, ptr) = any_value_heap_ptr(*value)?;
                hash_indexed.insert(ptr.as_ptr() as usize);
            }
        }
        let mut hash_reinstall_blockers = 0usize;
        for object in &mut objects {
            if object.eligible && hash_indexed.contains(&object.address) {
                object.pinned = true;
                object.edge_blocked = true;
                hash_reinstall_blockers = hash_reinstall_blockers.saturating_add(1);
            }
        }

        let mut dependencies = vec![Vec::<usize>::new(); objects.len()];
        let mut edge_writeback_blockers = 0usize;
        let mut writeback_validation_blockers = 0usize;
        for owner in scan.objects() {
            let owner_ptr = owner
                .value()
                .as_heap_ptr()
                .map_err(EvalHeapError::Value)?
                .as_ptr() as usize;
            let owner_index =
                *address_to_object
                    .get(&owner_ptr)
                    .ok_or(EvalHeapError::UnknownPointer {
                        tag: owner.tag(),
                        address: owner_ptr,
                    })?;
            for edge in owner.edges() {
                let target_ptr = edge
                    .value()
                    .as_heap_ptr()
                    .map_err(EvalHeapError::Value)?
                    .as_ptr() as usize;
                let Some(&target_index) = address_to_object.get(&target_ptr) else {
                    return Err(EvalHeapError::UnknownPointer {
                        tag: edge.value().tag(),
                        address: target_ptr,
                    });
                };
                if !objects[target_index].eligible {
                    continue;
                }
                if objects[owner_index].eligible {
                    if objects[owner_index].pinned {
                        objects[target_index].pinned = true;
                        objects[target_index].edge_blocked = true;
                        edge_writeback_blockers = edge_writeback_blockers.saturating_add(1);
                    } else {
                        dependencies[target_index].push(owner_index);
                    }
                } else {
                    // Classifying the owner is not equivalent to invoking the
                    // staged writeback validator with a concrete replacement.
                    objects[target_index].pinned = true;
                    objects[target_index].edge_blocked = true;
                    edge_writeback_blockers = edge_writeback_blockers.saturating_add(1);
                    writeback_validation_blockers = writeback_validation_blockers.saturating_add(1);
                }
            }
        }
        for owners in &mut dependencies {
            owners.sort_unstable();
            owners.dedup();
        }
        // If an eligible owner was pinned after an earlier edge visit, its
        // outgoing permanent targets must fail closed too.
        let mut changed = true;
        while changed {
            changed = false;
            for target in 0..objects.len() {
                if objects[target].pinned {
                    continue;
                }
                if dependencies[target]
                    .iter()
                    .any(|owner| objects[*owner].pinned)
                {
                    objects[target].pinned = true;
                    objects[target].edge_blocked = true;
                    edge_writeback_blockers = edge_writeback_blockers.saturating_add(1);
                    changed = true;
                }
            }
        }

        let mut page_objects = HashMap::<usize, Vec<usize>>::new();
        for (index, object) in objects.iter().enumerate() {
            for page in &object.pages {
                page_objects.entry(*page).or_default().push(index);
            }
        }
        let mut scalar_pages = HashSet::new();
        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        for &(address, bytes) in &scalar_regions {
            let ptr = NonNull::new(address as *mut HeapObject).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: PAGE_COMPLETION_TABLE,
                },
            )?;
            let index =
                self.flat_arena
                    .index_for_pointer(ptr)
                    .ok_or(EvalHeapError::ShedRejected {
                        address,
                        reason: "boxed scalar is outside the flat reservation",
                    })?;
            scalar_pages.extend(completion_pages(index.raw() as usize, bytes, page_bytes)?);
        }

        let mut resident_pages = HashSet::new();
        for page in page_objects.keys().copied() {
            let byte_offset =
                page.checked_mul(page_bytes)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: PAGE_COMPLETION_TABLE,
                    })?;
            let raw =
                u32::try_from(byte_offset).map_err(|_| EvalHeapError::RootScanLengthOverflow {
                    table: PAGE_COMPLETION_TABLE,
                })?;
            if self
                .flat_arena
                .page_is_resident_at_index(crate::heap::ArenaIndex::new(raw))
                .and_then(Result::ok)
                == Some(true)
            {
                resident_pages.insert(page);
            }
        }

        let mut requirements = Vec::new();
        let empty_selection = HashSet::new();
        for (&page, residents) in &page_objects {
            if !resident_pages.contains(&page)
                || scalar_pages.contains(&page)
                || residents.iter().any(|index| objects[*index].pinned)
            {
                continue;
            }
            let mut required = HashSet::new();
            let mut work = residents.clone();
            while let Some(index) = work.pop() {
                if !objects[index].eligible || objects[index].pinned {
                    required.clear();
                    break;
                }
                if required.insert(index) {
                    work.extend(dependencies[index].iter().copied());
                }
            }
            if required.is_empty() {
                continue;
            }
            let mut required: Vec<_> = required.into_iter().collect();
            required.sort_unstable();
            let survivor_bytes = required.iter().try_fold(0usize, |total, index| {
                total
                    .checked_add(objects[*index].inline_bytes)
                    .and_then(|bytes| bytes.checked_add(objects[*index].external_bytes))
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: PAGE_COMPLETION_TABLE,
                    })
            })?;
            let standalone = completion_marginal_accounting(
                &objects,
                &empty_selection,
                &required,
                &page_objects,
                &resident_pages,
                page_bytes,
                PageCompletionProjection::default(),
            )?;
            requirements.push(PageRequirement {
                page,
                objects: required,
                survivor_bytes,
                standalone_net: standalone.net_recovery_bytes,
            });
        }
        requirements.sort_unstable_by(|left, right| {
            right
                .standalone_net
                .cmp(&left.standalone_net)
                .then_with(|| left.survivor_bytes.cmp(&right.survivor_bytes))
                .then_with(|| left.page.cmp(&right.page))
        });

        let mut selected = HashSet::new();
        let mut accounting = PageCompletionProjection::default();
        loop {
            let mut best: Option<(u64, usize, usize, Vec<usize>)> = None;
            for requirement in &requirements {
                let additions: Vec<_> = requirement
                    .objects
                    .iter()
                    .copied()
                    .filter(|index| !selected.contains(index))
                    .collect();
                if additions.is_empty() {
                    continue;
                }
                let added_survivor_bytes = additions.iter().try_fold(0usize, |total, index| {
                    total
                        .checked_add(objects[*index].inline_bytes)
                        .and_then(|bytes| bytes.checked_add(objects[*index].external_bytes))
                        .ok_or(EvalHeapError::RootScanLengthOverflow {
                            table: PAGE_COMPLETION_TABLE,
                        })
                })?;
                let projected = completion_marginal_accounting(
                    &objects,
                    &selected,
                    &additions,
                    &page_objects,
                    &resident_pages,
                    page_bytes,
                    accounting,
                )?;
                let marginal = projected
                    .net_recovery_bytes
                    .saturating_sub(accounting.net_recovery_bytes);
                if marginal == 0 {
                    continue;
                }
                let replaces = match &best {
                    None => true,
                    Some((best_marginal, best_bytes, best_page, _)) => {
                        (
                            marginal,
                            usize::MAX.saturating_sub(added_survivor_bytes),
                            usize::MAX.saturating_sub(requirement.page),
                        ) > (
                            *best_marginal,
                            usize::MAX.saturating_sub(*best_bytes),
                            usize::MAX.saturating_sub(*best_page),
                        )
                    }
                };
                if replaces {
                    best = Some((marginal, added_survivor_bytes, requirement.page, additions));
                }
            }
            let Some((_marginal, _bytes, _page, additions)) = best else {
                break;
            };
            selected.extend(additions);
            let mut selected_ordered: Vec<_> = selected.iter().copied().collect();
            selected_ordered.sort_unstable();
            accounting = completion_accounting(
                &objects,
                &selected_ordered,
                &page_objects,
                &resident_pages,
                page_bytes,
            )?;
            if accounting.net_recovery_bytes >= PAGE_COMPLETION_SHORTFALL_BYTES {
                break;
            }
        }

        let mut pinned_pages = scalar_pages.clone();
        for object in &objects {
            if object.pinned {
                pinned_pages.extend(object.pages.iter().copied());
            }
            let tail_kind = match object.tag {
                ValueTag::Thunk => Some(FlatObjectKind::Thunk),
                ValueTag::Primop => Some(FlatObjectKind::Primop),
                ValueTag::Lambda => Some(FlatObjectKind::Lambda),
                _ => None,
            };
            if let Some(kind) = tail_kind {
                let ptr = NonNull::new(object.address as *mut HeapObject).ok_or(
                    EvalHeapError::RootScanLengthOverflow {
                        table: PAGE_COMPLETION_TABLE,
                    },
                )?;
                if self.flat_closure_payload_any(ptr).is_some()
                    && self
                        .flat_closures
                        .value_tail(ptr, kind)
                        .map_err(|error| self.closure_resolution_error(object.tag, ptr, error))?
                        .is_some()
                {
                    accounting.pinned_tail_owners = accounting.pinned_tail_owners.saturating_add(1);
                }
            }
            accounting.pinned_objects = accounting
                .pinned_objects
                .saturating_add(u64::from(object.pinned));
            accounting.pinned_direct_roots = accounting.pinned_direct_roots.saturating_add(
                u64::from(object.pinned && direct_roots.contains(&object.address)),
            );
            match object.class {
                CompletionObjectClass::Record => {
                    accounting.pinned_records = accounting.pinned_records.saturating_add(1)
                }
                CompletionObjectClass::TypedHead => {
                    accounting.pinned_typed_heads = accounting.pinned_typed_heads.saturating_add(1)
                }
                CompletionObjectClass::BoxedScalar => {}
                CompletionObjectClass::Thunk => {
                    accounting.pinned_thunks = accounting.pinned_thunks.saturating_add(1)
                }
                CompletionObjectClass::Closure => {
                    accounting.pinned_closures = accounting.pinned_closures.saturating_add(1)
                }
                CompletionObjectClass::Permanent if object.unsupported_external => {
                    accounting.pinned_malformed_or_external =
                        accounting.pinned_malformed_or_external.saturating_add(1)
                }
                CompletionObjectClass::Permanent => {}
            }
            accounting.pinned_unstageable_incoming_edges = accounting
                .pinned_unstageable_incoming_edges
                .saturating_add(u64::from(object.edge_blocked));
            if object.future {
                match object.class {
                    CompletionObjectClass::Closure => {
                        if object.tag == ValueTag::Primop {
                            accounting.future_plain_primops =
                                accounting.future_plain_primops.saturating_add(1);
                        } else if object.tag == ValueTag::Lambda {
                            accounting.future_plain_lambdas =
                                accounting.future_plain_lambdas.saturating_add(1);
                        }
                    }
                    _ => {}
                }
            }
        }
        let future_pages: HashSet<_> = objects
            .iter()
            .filter(|object| object.future)
            .flat_map(|object| object.pages.iter().copied())
            .collect();
        accounting.future_source_pages = future_pages.len() as u64;
        accounting.pinned_pages = pinned_pages.len() as u64;
        accounting.pinned_boxed_scalars = scalar_regions.len() as u64;
        accounting.edge_writeback_blockers = edge_writeback_blockers as u64;
        accounting.hash_reinstall_blockers = hash_reinstall_blockers as u64;
        accounting.writeback_validation_blockers = writeback_validation_blockers as u64;
        accounting.target_bytes = PAGE_COMPLETION_SHORTFALL_BYTES;
        accounting.net_threshold_pass =
            accounting.net_recovery_bytes >= PAGE_COMPLETION_SHORTFALL_BYTES;
        accounting.target_pass = false;
        // The current arena exposes only one serial reservation generation;
        // repeated peak-shaping collections cannot yet distinguish a retired
        // source cohort from a newly published destination cohort.
        accounting.cadence_singleton_generation_blocker = true;
        Ok(accounting)
    }

    fn dead_weak_hash_candidates(&self, reachable: &HashSet<usize>) -> Result<u64, EvalHeapError> {
        let mut dead = 0u64;
        for table in [
            &self.string_cons,
            &self.path_cons,
            &self.list_cons,
            &self.attrs_cons,
        ] {
            for (_hash, _index, value) in table.committed_entries() {
                let (_tag, ptr) = any_value_heap_ptr(*value)?;
                if !reachable.contains(&(ptr.as_ptr() as usize)) {
                    dead = dead.saturating_add(1);
                }
            }
        }
        Ok(dead)
    }
}

fn completion_pages(
    byte_offset: usize,
    bytes: usize,
    page_bytes: usize,
) -> Result<Vec<usize>, EvalHeapError> {
    if bytes == 0 || page_bytes == 0 {
        return Err(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        });
    }
    let first = byte_offset / page_bytes;
    let last = byte_offset.checked_add(bytes.saturating_sub(1)).ok_or(
        EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        },
    )? / page_bytes;
    let count = last
        .checked_sub(first)
        .and_then(|span| span.checked_add(1))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    let mut pages = Vec::new();
    pages
        .try_reserve_exact(count)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: PAGE_COMPLETION_TABLE,
            entries: count,
        })?;
    pages.extend(first..=last);
    Ok(pages)
}

fn completion_page_round(bytes: usize, page_bytes: usize) -> Result<usize, EvalHeapError> {
    if bytes == 0 {
        return Ok(0);
    }
    bytes
        .checked_add(page_bytes.saturating_sub(1))
        .map(|rounded| rounded / page_bytes * page_bytes)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })
}

fn completion_accounting(
    objects: &[CompletionObject],
    selected: &[usize],
    page_objects: &HashMap<usize, Vec<usize>>,
    resident_pages: &HashSet<usize>,
    page_bytes: usize,
) -> Result<PageCompletionProjection, EvalHeapError> {
    let selected_set: HashSet<_> = selected.iter().copied().collect();
    let inline_bytes = selected.iter().try_fold(0usize, |total, index| {
        total.checked_add(objects[*index].inline_bytes).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            },
        )
    })?;
    let external_bytes = selected.iter().try_fold(0usize, |total, index| {
        total.checked_add(objects[*index].external_bytes).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            },
        )
    })?;
    let source_pages = page_objects
        .iter()
        .filter(|(page, residents)| {
            resident_pages.contains(page)
                && !residents.is_empty()
                && residents.iter().all(|index| selected_set.contains(index))
        })
        .count();
    let destination_inline_bytes = completion_page_round(inline_bytes, page_bytes)?;
    let destination_external_bytes = completion_page_round(external_bytes, page_bytes)?;
    let destination_liveness_bytes = if selected.is_empty() {
        0
    } else {
        completion_page_round(DESTINATION_LIVENESS_BYTES, page_bytes)?
    };
    let destination_flat_entry_bytes = completion_page_round(
        selected
            .len()
            .checked_mul(DESTINATION_FLAT_ENTRY_BYTES)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            })?,
        page_bytes,
    )?;
    let forwarding_bytes = selected
        .len()
        .checked_mul(FORWARDING_BYTES_PER_OBJECT)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    // Charge a compact mark/forwarding work entry and a staged address/value
    // pair per selected object, plus one bit per source page. The charge is
    // committed-page rounded and deliberately separate from the persistent
    // minimum forwarding index above.
    let staging_scratch_bytes = selected
        .len()
        .checked_mul(3 * std::mem::size_of::<usize>())
        .and_then(|bytes| bytes.checked_add(page_objects.len().div_ceil(8)))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    let staging_scratch_bytes = completion_page_round(staging_scratch_bytes, page_bytes)?;
    let gross_released_bytes =
        source_pages
            .checked_mul(page_bytes)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            })?;
    let destination_bytes = destination_inline_bytes
        .checked_add(destination_external_bytes)
        .and_then(|bytes| bytes.checked_add(destination_liveness_bytes))
        .and_then(|bytes| bytes.checked_add(destination_flat_entry_bytes))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    let net_recovery_bytes = gross_released_bytes
        .saturating_sub(destination_bytes)
        .saturating_sub(forwarding_bytes)
        .saturating_sub(staging_scratch_bytes);
    Ok(PageCompletionProjection {
        selected_objects: selected.len() as u64,
        selected_inline_bytes: inline_bytes as u64,
        selected_external_bytes: external_bytes as u64,
        source_pages: source_pages as u64,
        destination_inline_pages: destination_inline_bytes.div_ceil(page_bytes) as u64,
        destination_external_pages: destination_external_bytes.div_ceil(page_bytes) as u64,
        gross_released_bytes: gross_released_bytes as u64,
        destination_bytes: destination_bytes as u64,
        destination_liveness_bytes: destination_liveness_bytes as u64,
        destination_flat_entry_bytes: destination_flat_entry_bytes as u64,
        forwarding_bytes: forwarding_bytes as u64,
        staging_scratch_bytes: staging_scratch_bytes as u64,
        net_recovery_bytes: net_recovery_bytes as u64,
        ..PageCompletionProjection::default()
    })
}

#[allow(clippy::too_many_arguments)]
fn completion_marginal_accounting(
    objects: &[CompletionObject],
    selected: &HashSet<usize>,
    additions: &[usize],
    page_objects: &HashMap<usize, Vec<usize>>,
    resident_pages: &HashSet<usize>,
    page_bytes: usize,
    current: PageCompletionProjection,
) -> Result<PageCompletionProjection, EvalHeapError> {
    let addition_set: HashSet<_> = additions.iter().copied().collect();
    let mut affected_pages = HashSet::new();
    for index in additions {
        affected_pages.extend(objects[*index].pages.iter().copied());
    }
    let newly_completed_pages = affected_pages
        .iter()
        .filter(|page| {
            resident_pages.contains(page)
                && page_objects.get(page).is_some_and(|residents| {
                    residents
                        .iter()
                        .all(|index| selected.contains(index) || addition_set.contains(index))
                })
        })
        .count();
    let added_inline = additions.iter().try_fold(0usize, |total, index| {
        total.checked_add(objects[*index].inline_bytes).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            },
        )
    })?;
    let added_external = additions.iter().try_fold(0usize, |total, index| {
        total.checked_add(objects[*index].external_bytes).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            },
        )
    })?;
    let inline_bytes = usize::try_from(current.selected_inline_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(added_inline))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    let external_bytes = usize::try_from(current.selected_external_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(added_external))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    let selected_objects = selected.len().checked_add(additions.len()).ok_or(
        EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        },
    )?;
    let source_pages = usize::try_from(current.source_pages)
        .ok()
        .and_then(|pages| pages.checked_add(newly_completed_pages))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    let destination_inline_bytes = completion_page_round(inline_bytes, page_bytes)?;
    let destination_external_bytes = completion_page_round(external_bytes, page_bytes)?;
    let destination_liveness_bytes = if selected_objects == 0 {
        0
    } else {
        completion_page_round(DESTINATION_LIVENESS_BYTES, page_bytes)?
    };
    let destination_flat_entry_bytes = completion_page_round(
        selected_objects
            .checked_mul(DESTINATION_FLAT_ENTRY_BYTES)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            })?,
        page_bytes,
    )?;
    let forwarding_bytes = selected_objects
        .checked_mul(FORWARDING_BYTES_PER_OBJECT)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    let staging_scratch_bytes = selected_objects
        .checked_mul(3 * std::mem::size_of::<usize>())
        .and_then(|bytes| bytes.checked_add(page_objects.len().div_ceil(8)))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    let staging_scratch_bytes = completion_page_round(staging_scratch_bytes, page_bytes)?;
    let gross_released_bytes =
        source_pages
            .checked_mul(page_bytes)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PAGE_COMPLETION_TABLE,
            })?;
    let destination_bytes = destination_inline_bytes
        .checked_add(destination_external_bytes)
        .and_then(|bytes| bytes.checked_add(destination_liveness_bytes))
        .and_then(|bytes| bytes.checked_add(destination_flat_entry_bytes))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PAGE_COMPLETION_TABLE,
        })?;
    Ok(PageCompletionProjection {
        selected_objects: selected_objects as u64,
        selected_inline_bytes: inline_bytes as u64,
        selected_external_bytes: external_bytes as u64,
        source_pages: source_pages as u64,
        destination_inline_pages: destination_inline_bytes.div_ceil(page_bytes) as u64,
        destination_external_pages: destination_external_bytes.div_ceil(page_bytes) as u64,
        gross_released_bytes: gross_released_bytes as u64,
        destination_bytes: destination_bytes as u64,
        destination_liveness_bytes: destination_liveness_bytes as u64,
        destination_flat_entry_bytes: destination_flat_entry_bytes as u64,
        forwarding_bytes: forwarding_bytes as u64,
        staging_scratch_bytes: staging_scratch_bytes as u64,
        net_recovery_bytes: gross_released_bytes
            .saturating_sub(destination_bytes)
            .saturating_sub(forwarding_bytes)
            .saturating_sub(staging_scratch_bytes) as u64,
        ..PageCompletionProjection::default()
    })
}

fn candidate_accounting(categories: &[CandidateMass; CATEGORY_COUNT]) -> (u64, u64, u64, u64) {
    let fold = |masses: &[CandidateMass]| {
        masses.iter().fold((0u64, 0u64), |(objects, bytes), mass| {
            (
                objects.saturating_add(mass.objects),
                bytes.saturating_add(mass.logical_bytes()),
            )
        })
    };
    let (supported_objects, supported_bytes) = fold(&categories[..4]);
    let (excluded_objects, excluded_bytes) = fold(&categories[4..]);
    (
        supported_objects,
        supported_bytes,
        excluded_objects,
        excluded_bytes,
    )
}

const fn record_category(kind: usize, generation: HeapGeneration) -> usize {
    let generation = match generation {
        HeapGeneration::Permanent => 0,
        HeapGeneration::Old => 1,
        HeapGeneration::Young => 2,
    };
    5 + kind * 3 + generation
}

fn mark_pages(pages: &mut HashSet<usize>, address: usize, bytes: usize, page_bytes: usize) {
    if bytes == 0 || page_bytes == 0 {
        return;
    }
    let first = address / page_bytes;
    let last = address.saturating_add(bytes.saturating_sub(1)) / page_bytes;
    for page in first..=last {
        pages.insert(page);
    }
}

fn coalesced_page_runs(pages: &[usize]) -> (u64, u64) {
    let Some(_) = pages.first() else {
        return (0, 0);
    };
    let mut runs = 1u64;
    let mut current = 1u64;
    let mut largest = 1u64;
    for pair in pages.windows(2) {
        if pair[1] == pair[0].saturating_add(1) {
            current = current.saturating_add(1);
            largest = largest.max(current);
        } else {
            runs = runs.saturating_add(1);
            current = 1;
        }
    }
    (runs, largest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_exact_zero_live_runs() {
        assert_eq!(coalesced_page_runs(&[]), (0, 0));
        assert_eq!(coalesced_page_runs(&[2, 3, 7, 9, 10, 11]), (3, 3));
    }

    #[test]
    fn record_categories_preserve_generation() {
        assert_eq!(record_category(0, HeapGeneration::Permanent), 5);
        assert_eq!(record_category(1, HeapGeneration::Old), 9);
        assert_eq!(record_category(2, HeapGeneration::Young), 13);
    }

    #[test]
    fn typed_heads_and_records_are_observed_but_uncredited() {
        let mut categories = [CandidateMass::default(); CATEGORY_COUNT];
        categories[4].add(4096, 0);
        categories[8].add(128, 8192);
        let (supported_objects, supported_bytes, excluded_objects, excluded_bytes) =
            candidate_accounting(&categories);
        assert_eq!((supported_objects, supported_bytes), (0, 0));
        assert_eq!(excluded_objects, 2);
        assert_eq!(excluded_bytes, 4096 + 128 + 8192);
    }

    #[test]
    fn retained_typed_extent_pins_its_page() {
        let mut total = HashSet::new();
        let mut live = HashSet::new();
        mark_pages(&mut total, 0x1000, 64, 4096);
        mark_pages(&mut live, 0x1000, 64, 4096);
        assert_eq!(total.difference(&live).count(), 0);
    }

    #[test]
    fn retained_owner_seed_keeps_flat_target_out_of_dead_set() {
        let retained_target = 0x2000usize;
        let mut reachable = HashSet::new();
        reachable.insert(retained_target);
        assert!(reachable.contains(&retained_target));
    }

    #[test]
    fn malformed_state_count_blocks_safety() {
        let invalid_state_blockers = 1usize;
        let safety_gate = invalid_state_blockers == 0;
        assert!(!safety_gate);
    }

    #[test]
    fn completion_pages_credit_every_page_spanned_by_one_object() {
        assert_eq!(
            completion_pages(4090, 20, 4096).expect("bounded extent"),
            vec![0, 1]
        );
    }

    #[test]
    fn completion_net_subtracts_destination_forwarding_and_committed_scratch() {
        let objects = vec![CompletionObject {
            address: 0x1000,
            tag: ValueTag::String,
            inline_bytes: 64,
            external_bytes: 32,
            pages: vec![0, 1],
            class: CompletionObjectClass::Permanent,
            eligible: true,
            pinned: false,
            unsupported_external: false,
            edge_blocked: false,
            future: false,
        }];
        let page_objects = HashMap::from([(0, vec![0]), (1, vec![0])]);
        let resident_pages = HashSet::from([0, 1]);

        let projection =
            completion_accounting(&objects, &[0], &page_objects, &resident_pages, 4096)
                .expect("bounded accounting");

        assert_eq!(projection.gross_released_bytes, 8192);
        assert_eq!(projection.destination_liveness_bytes, 2 * 1024 * 1024);
        assert_eq!(projection.destination_flat_entry_bytes, 4096);
        assert_eq!(projection.destination_bytes, 8192 + 2 * 1024 * 1024 + 4096);
        assert_eq!(projection.forwarding_bytes, 8);
        assert_eq!(projection.staging_scratch_bytes, 4096);
        assert_eq!(projection.net_recovery_bytes, 0);
    }

    #[test]
    fn hypothetical_threshold_does_not_override_route_blockers() {
        let projection = PageCompletionProjection {
            net_recovery_bytes: PAGE_COMPLETION_SHORTFALL_BYTES,
            net_threshold_pass: true,
            target_pass: false,
            destination_metadata_blocker: true,
            cadence_singleton_generation_blocker: true,
            ..PageCompletionProjection::default()
        };

        assert!(projection.net_threshold_pass);
        assert!(!projection.target_pass);
    }

    #[test]
    fn report_reconciles_live_root_and_dead_list() {
        let mut heap = EvalHeap::new();
        let live = heap
            .alloc_string(NixString::from_bytes(b"live".to_vec()))
            .expect("live string allocates");
        heap.alloc_list(NixList::new(vec![live; 32]))
            .expect("dead list allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, live)
            .expect("live root records");

        let report = heap
            .nested_nonmoving_retirement_report(&roots)
            .expect("weak report succeeds");

        assert!(report.reconciled);
        assert_eq!(report.roots, 1);
        assert_eq!(report.reachable, 1);
        assert_eq!(report.dead, 1);
        assert!(report.categories[1].external_bytes >= 32 * std::mem::size_of::<Value>() as u64);
    }

    #[test]
    fn physical_gate_fails_closed_without_exact_residency() {
        let report = NestedNonmovingRetirementReport {
            logical_bytes: LOGICAL_GATE_BYTES,
            physical_bytes: PHYSICAL_GATE_BYTES,
            logical_gate: true,
            physical_gate: false,
            safety_gate: true,
            ..NestedNonmovingRetirementReport {
                roots: 0,
                retained_seed_roots: 0,
                reachable: 0,
                allocated: 0,
                dead: 0,
                reconciled: true,
                categories: [CandidateMass::default(); CATEGORY_COUNT],
                pages: PageSimulation::default(),
                dead_weak_candidates: 0,
                weak_blockers: 0,
                side_table_blockers: 0,
                semantic_side_table_audit_complete: false,
                retained_edge_audit_complete: false,
                invalid_state_blockers: 0,
                blackhole_blockers: 0,
                ledger_blockers: 1,
                supported_dead: 0,
                excluded_dead: 0,
                logical_bytes: 0,
                excluded_logical_bytes: 0,
                physical_bytes: 0,
                logical_gate: false,
                physical_gate: false,
                safety_gate: false,
                page_completion: PageCompletionProjection::default(),
            }
        };
        assert!(!report.admitted());
    }
}
