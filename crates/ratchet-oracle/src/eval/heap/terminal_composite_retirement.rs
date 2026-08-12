//! Terminal-only selective retirement of unreachable permanent composites.
//!
//! This default-off semantic proof retires flat lists and attrsets that are
//! absent from a complete evaluator root closure. It deliberately runs only
//! after root evaluation has unwound: terminal reclamation cannot reduce the
//! chronological peak, but it proves that permanent composites can stop
//! owning worker closure graphs without changing the returned value.
//!
//! Preparation computes exact weak reachability, inventories every selected
//! payload, rejects shared heaps and active blackholes, and validates both flat
//! store selections before mutation. Commit drops selected payloads, removes
//! their exact addresses from weak interning and side-hash tables without
//! dereferencing them, then invokes the existing non-moving worker sweep so
//! the newly unowned closure graph can be released.

use std::collections::HashSet;
use std::fmt;
use std::ptr::NonNull;

use super::*;
use crate::attrs::AttrEntry;
use crate::eval::thunk::ThunkState;

/// Result of one terminal composite-retirement proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::eval) struct TerminalCompositeRetirementReport {
    roots: u64,
    reachable_objects: u64,
    lists_retired: u64,
    attrs_retired: u64,
    inline_bytes_retired: u64,
    list_spine_capacity_bytes_dropped: u64,
    attrs_array_logical_bytes_dropped: u64,
    weak_list_candidates_purged: u64,
    weak_attrs_candidates_purged: u64,
    cold_side_hashes_purged: u64,
    stale_side_hashes_purged: u64,
    worker_records_retired: u64,
    worker_sweep_failed: bool,
    candidate_pages: u64,
    advised_pages: u64,
    advice_failed: bool,
}

impl fmt::Display for TerminalCompositeRetirementReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\"ok\":true,\"terminal_only\":true,\"peak_credit\":false,\
             \"roots\":{},\"reachable_objects\":{},\
             \"retired\":{{\"lists\":{},\"attrs\":{},\"inline_bytes\":{},\
             \"list_spine_capacity_bytes\":{},\"attrs_array_logical_bytes\":{},\
             \"worker_closures\":{},\"worker_sweep_failed\":{}}},\
             \"purged\":{{\"weak_list_candidates\":{},\
             \"weak_attrs_candidates\":{},\"cold_side_hashes\":{},\
             \"stale_side_hashes\":{}}},\
             \"page_advice\":{{\"candidate_pages\":{},\"advised_pages\":{},\
             \"advice_failed\":{}}},\
             \"semantics\":{{\"complete_true_roots\":true,\
             \"hash_cons_is_weak\":true,\"stale_handles_fail_loudly\":true,\
             \"chronological_peak_unchanged\":true}}}}",
            self.roots,
            self.reachable_objects,
            self.lists_retired,
            self.attrs_retired,
            self.inline_bytes_retired,
            self.list_spine_capacity_bytes_dropped,
            self.attrs_array_logical_bytes_dropped,
            self.worker_records_retired,
            self.worker_sweep_failed,
            self.weak_list_candidates_purged,
            self.weak_attrs_candidates_purged,
            self.cold_side_hashes_purged,
            self.stale_side_hashes_purged,
            self.candidate_pages,
            self.advised_pages,
            self.advice_failed,
        )
    }
}

/// Fully prepared retirement inventory.
struct TerminalCompositeSelection {
    reachable: HashSet<usize>,
    lists: Vec<NonNull<HeapObject>>,
    attrs: Vec<NonNull<HeapObject>>,
    addresses: Vec<usize>,
    report: TerminalCompositeRetirementReport,
}

impl EvalHeap {
    /// Retires unreachable flat lists and attrsets at terminal quiescence.
    ///
    /// Hash-cons tables are weak and do not seed reachability. The selected
    /// identities are removed by exact address after their payloads are
    /// dropped, and the ordinary non-moving worker sweep runs afterward from
    /// the same roots. A worker-sweep failure is recorded in the report rather
    /// than invalidating the already committed composite retirement.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] without mutation for shared heaps, stale
    /// roots or edges, invalid flat-store selections, typed blackholes, or
    /// unreachable blackholed worker thunks. Allocation failure during
    /// preparation also leaves the heap unchanged.
    pub(in crate::eval) fn retire_terminal_unreachable_composites(
        &mut self,
        roots: &EvalRootSet,
    ) -> Result<TerminalCompositeRetirementReport, EvalHeapError> {
        if self.shared.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "terminal composite retirement requires the serial heap",
            });
        }
        let selection = self.prepare_terminal_composite_selection(roots)?;
        self.commit_terminal_composite_selection(roots, selection)
    }

    /// Builds and validates the complete terminal selection before mutation.
    fn prepare_terminal_composite_selection(
        &mut self,
        roots: &EvalRootSet,
    ) -> Result<TerminalCompositeSelection, EvalHeapError> {
        let reachable = self.weak_reachable_addresses(roots)?;
        let mut lists = Vec::new();
        let mut attrs = Vec::new();
        let mut addresses = Vec::new();
        let mut report = TerminalCompositeRetirementReport {
            roots: roots.len() as u64,
            reachable_objects: reachable.len() as u64,
            ..TerminalCompositeRetirementReport::default()
        };

        for entry in self.flat_lists.iter() {
            let address = entry.ptr().as_ptr() as usize;
            if reachable.contains(&address) {
                continue;
            }
            lists
                .try_reserve(1)
                .map_err(|_| EvalHeapError::RecordAllocationFailed { records: 1 })?;
            addresses
                .try_reserve(1)
                .map_err(|_| EvalHeapError::RecordAllocationFailed { records: 1 })?;
            lists.push(entry.ptr());
            addresses.push(address);
            report.lists_retired = report.lists_retired.saturating_add(1);
            report.inline_bytes_retired = report
                .inline_bytes_retired
                .saturating_add(entry.size_bytes() as u64);
            report.list_spine_capacity_bytes_dropped =
                report.list_spine_capacity_bytes_dropped.saturating_add(
                    (entry.object().payload().capacity() as u64)
                        .saturating_mul(std::mem::size_of::<Value>() as u64),
                );
        }
        for entry in self.flat_attrs.iter() {
            let address = entry.ptr().as_ptr() as usize;
            if reachable.contains(&address) {
                continue;
            }
            attrs
                .try_reserve(1)
                .map_err(|_| EvalHeapError::RecordAllocationFailed { records: 1 })?;
            addresses
                .try_reserve(1)
                .map_err(|_| EvalHeapError::RecordAllocationFailed { records: 1 })?;
            attrs.push(entry.ptr());
            addresses.push(address);
            report.attrs_retired = report.attrs_retired.saturating_add(1);
            report.inline_bytes_retired = report
                .inline_bytes_retired
                .saturating_add(entry.size_bytes() as u64);
            report.attrs_array_logical_bytes_dropped =
                report.attrs_array_logical_bytes_dropped.saturating_add(
                    (entry.object().payload().attrs.len() as u64).saturating_mul(
                        (std::mem::size_of::<AttrEntry>() + 2 * std::mem::size_of::<u32>()) as u64,
                    ),
                );
        }
        addresses.sort_unstable();

        // A typed head is not retired by this experiment. Any blackhole still
        // proves terminal quiescence false, so fail closed rather than relying
        // on its detached-work lease being represented elsewhere.
        for (address, _) in self.typed_thunk_heads.initialized_regions() {
            let Some(ptr) = NonNull::new(address as *mut HeapObject) else {
                continue;
            };
            let head = self
                .typed_thunk_heads
                .resolve(ptr)
                .map_err(|_| EvalHeapError::unknown(ValueTag::Thunk, ptr))?;
            if head.state() == Some(ThunkState::Blackhole) {
                return Err(EvalHeapError::ShedRejected {
                    address,
                    reason: "terminal composite retirement found a typed blackhole",
                });
            }
        }
        self.validate_unreachable_worker_blackholes(&reachable)?;

        // Exercise both exact selection validators before either store is
        // mutated. The tokens are intentionally dropped: commit preparation is
        // repeated below after all other fallible validation has completed,
        // where field-disjoint mutable borrows can be held together.
        self.flat_lists
            .prepare_retire_live_subset(lists.iter().copied())
            .map_err(|_| EvalHeapError::ShedRejected {
                address: 0,
                reason: "terminal list retirement selection failed validation",
            })?;
        self.flat_attrs
            .prepare_retire_live_subset(attrs.iter().copied())
            .map_err(|_| EvalHeapError::ShedRejected {
                address: 0,
                reason: "terminal attrs retirement selection failed validation",
            })?;

        Ok(TerminalCompositeSelection {
            reachable,
            lists,
            attrs,
            addresses,
            report,
        })
    }

    /// Rejects quiescence violations that the post-commit worker sweep would find.
    fn validate_unreachable_worker_blackholes(
        &self,
        reachable: &HashSet<usize>,
    ) -> Result<(), EvalHeapError> {
        for entry in self.flat_closures.iter() {
            let address = entry.ptr().as_ptr() as usize;
            if reachable.contains(&address) {
                continue;
            }
            if let Some(thunk) = entry.object().payload().as_thunk()
                && thunk.cell().state().map_err(EvalHeapError::Thunk)? == ThunkState::Blackhole
            {
                return Err(EvalHeapError::ShedRejected {
                    address,
                    reason: "terminal composite retirement found an unreachable blackhole",
                });
            }
        }
        for record in self.records.iter() {
            let address = record.ptr.as_ptr() as usize;
            if record.is_retired() || reachable.contains(&address) {
                continue;
            }
            if let HeapObjectValue::Thunk(thunk) = &record.object
                && thunk.cell().state().map_err(EvalHeapError::Thunk)? == ThunkState::Blackhole
            {
                return Err(EvalHeapError::ShedRejected {
                    address,
                    reason: "terminal composite retirement found an unreachable blackhole",
                });
            }
        }
        Ok(())
    }

    /// Commits an already validated terminal selection.
    fn commit_terminal_composite_selection(
        &mut self,
        roots: &EvalRootSet,
        selection: TerminalCompositeSelection,
    ) -> Result<TerminalCompositeRetirementReport, EvalHeapError> {
        let TerminalCompositeSelection {
            reachable,
            lists,
            attrs,
            addresses,
            mut report,
        } = selection;
        debug_assert!(
            lists
                .iter()
                .chain(&attrs)
                .all(|ptr| !reachable.contains(&(ptr.as_ptr() as usize)))
        );

        let list_retirement = self
            .flat_lists
            .prepare_retire_live_subset(lists.iter().copied())
            .map_err(|_| EvalHeapError::ShedRejected {
                address: 0,
                reason: "validated terminal list selection changed before commit",
            })?;
        let attrs_retirement = self
            .flat_attrs
            .prepare_retire_live_subset(attrs.iter().copied())
            .map_err(|_| EvalHeapError::ShedRejected {
                address: 0,
                reason: "validated terminal attrs selection changed before commit",
            })?;
        debug_assert_eq!(list_retirement.commit(), lists.len());
        debug_assert_eq!(attrs_retirement.commit(), attrs.len());

        let weak = self.purge_weak_hash_cons_candidates(&addresses);
        report.weak_list_candidates_purged = weak.list.retained.candidates_removed as u64;
        report.weak_attrs_candidates_purged = weak.attrs.retained.candidates_removed as u64;
        for address in &addresses {
            if self.flat_cold_hashes.clear(*address) {
                report.cold_side_hashes_purged = report.cold_side_hashes_purged.saturating_add(1);
            }
            if self.flat_stale_hashes.remove(address) {
                report.stale_side_hashes_purged = report.stale_side_hashes_purged.saturating_add(1);
            }
        }

        let worker = self.sweep_unreachable_worker_records(roots);
        match worker {
            Ok(worker) => {
                report.worker_records_retired = worker.swept() as u64;
                report.advice_failed |= worker.advice_failed;
            }
            Err(_) => report.worker_sweep_failed = true,
        }
        match self.flat_arena.advise_zero_liveness_pages() {
            Some(Ok(advice)) => {
                report.candidate_pages = advice.candidate_pages() as u64;
                report.advised_pages = advice.applied_pages() as u64;
            }
            Some(Err(_)) => report.advice_failed = true,
            None => {}
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn retires_only_dead_composites_and_releases_their_worker_edges() {
        let mut heap = EvalHeap::new();
        let dead_worker = heap
            .alloc_thunk(EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(1),
                Span::new(1, 2),
                Value::int(1),
                EvalModuleId::ROOT,
                IrId::new(2),
                Value::int(2),
            ))
            .expect("dead worker allocates");
        let dead_list = heap
            .alloc_list(NixList::new(vec![dead_worker]))
            .expect("dead list allocates");
        let live_list = heap
            .alloc_list(NixList::new(vec![Value::int(7)]))
            .expect("live list allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, live_list)
            .expect("root storage grows");

        let report = heap
            .retire_terminal_unreachable_composites(&roots)
            .expect("terminal retirement succeeds");

        assert_eq!(report.lists_retired, 1);
        assert_eq!(report.worker_records_retired, 1);
        assert!(heap.get_list(live_list).is_ok());
        assert!(heap.get_list(dead_list).is_err(), "stale list fails loudly");
        assert!(
            heap.clone_thunk(dead_worker).is_err(),
            "released worker edge permits closure retirement"
        );
    }

    #[test]
    fn retirement_purges_weak_candidate_identity() {
        let mut heap = EvalHeap::new();
        let dead = heap
            .alloc_list(NixList::new(vec![Value::int(11)]))
            .expect("dead list allocates");

        let report = heap
            .retire_terminal_unreachable_composites(&EvalRootSet::new())
            .expect("terminal retirement succeeds");
        let rebuilt = heap
            .alloc_list(NixList::new(vec![Value::int(11)]))
            .expect("equivalent list rebuilds");

        assert_eq!(report.weak_list_candidates_purged, 1);
        assert!(!rebuilt.raw_eq(dead));
    }

    #[test]
    fn stale_attr_handle_fails_loudly_after_retirement() {
        let mut heap = EvalHeap::new();
        let dead = heap
            .alloc_attrs(0, FlatAttrs::empty())
            .expect("dead attrs allocates");

        let report = heap
            .retire_terminal_unreachable_composites(&EvalRootSet::new())
            .expect("terminal retirement succeeds");

        assert_eq!(report.attrs_retired, 1);
        assert!(heap.get_attrs(dead).is_err());
    }

    #[test]
    fn stale_root_validation_error_does_not_mutate_composites() {
        let mut heap = EvalHeap::new();
        let live = heap
            .alloc_list(NixList::new(vec![Value::int(3)]))
            .expect("list allocates");
        let stale = {
            let mut other = EvalHeap::new();
            other
                .alloc_list(NixList::new(vec![Value::int(4)]))
                .expect("foreign list allocates")
        };
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, stale)
            .expect("root storage grows");

        assert!(
            heap.retire_terminal_unreachable_composites(&roots).is_err(),
            "foreign root fails validation"
        );
        assert!(
            heap.get_list(live).is_ok(),
            "validation error leaves candidate live"
        );
    }

    #[test]
    fn typed_blackhole_validation_error_does_not_mutate_composites() {
        let mut heap = EvalHeap::new();
        heap.enable_typed_apply_thunk_heads();
        let typed = heap
            .try_typed_alloc_thunk(EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(1),
                Span::new(1, 2),
                Value::int(1),
                EvalModuleId::ROOT,
                IrId::new(2),
                Value::int(2),
            ))
            .expect("typed allocation succeeds")
            .expect("apply work uses a typed head");
        heap.test_blackhole_typed_thunk(typed)
            .expect("test installs the blackhole sentinel");
        let dead = heap
            .alloc_list(NixList::new(vec![Value::int(5)]))
            .expect("candidate list allocates");

        assert!(
            heap.retire_terminal_unreachable_composites(&EvalRootSet::new())
                .is_err(),
            "typed blackhole rejects terminal retirement"
        );
        assert!(
            heap.get_list(dead).is_ok(),
            "blackhole validation failure precedes mutation"
        );
    }

    #[test]
    fn shared_heap_fails_closed_without_mutation() {
        let arena = Arc::new(SharedHeapArena::new(1, 32));
        let mut heap = EvalHeap::with_shared_shard(
            Arc::clone(&arena),
            Arc::clone(arena.shard(0).expect("shard exists")),
        );
        let value = heap
            .alloc_list(NixList::new(vec![Value::int(13)]))
            .expect("shared list allocates");

        assert!(
            heap.retire_terminal_unreachable_composites(&EvalRootSet::new())
                .is_err()
        );
        assert!(heap.get_list(value).is_ok());
    }

    #[test]
    fn report_is_strict_json_and_denies_peak_credit() {
        let rendered = TerminalCompositeRetirementReport::default().to_string();
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("report is strict JSON");

        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["terminal_only"], true);
        assert_eq!(parsed["peak_credit"], false);
    }
}
