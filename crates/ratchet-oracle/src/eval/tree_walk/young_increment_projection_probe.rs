//! Selected-milestone producer for chronological typed-increment projections.
//!
//! Every successful final-config completion records only an allocation fence.
//! Internal milestones remain fail-closed because their recursive native
//! continuations are not yet completely modeled. Terminal ordinal 357 is
//! sampled only after its semantic leaf has returned to the rooted outer
//! dispatcher loop head. At that boundary the existing rooted collection-poll
//! preflight supplies the stable result/root inventory; no force census is
//! required because every recursive force and continuation has returned.
//! The producer never changes heap placement, weak indexes, roots, or object
//! state.

use super::*;

const ORDINAL_ENV: &str = "AOS_NIX_YOUNG_INCREMENT_PROJECTION_ORDINAL";
const MILESTONES: [u64; 8] = [160, 192, 224, 256, 288, 320, 352, 357];
const RSS_CEILING_BYTES: u64 = 239_054_848;
const EXPECTED_STREAMS: u64 = 9;

/// Bounded process-local state for one independently selected milestone.
#[derive(Debug)]
pub(super) struct YoungIncrementProjectionProbe {
    selected_ordinal: u64,
    completions: u64,
    fence_error: bool,
    internal_selected_observed: bool,
    fences: Vec<crate::eval::heap::DemandRegionAllocationFence>,
    snapshot: Option<YoungIncrementProjectionSnapshot>,
}

#[derive(Clone, Debug)]
struct YoungIncrementProjectionSnapshot {
    ordinal: u64,
    runtime_blockers: usize,
    internal_boundary_refusal: bool,
    terminal_outer_boundary: bool,
    terminal_outer_proven: bool,
    root_error: bool,
    projection_error: bool,
    rss_unavailable: bool,
    rss_error: bool,
    rss_bytes: u64,
    reservation: crate::eval::heap::NestedNonmovingRuntimeReservationSnapshot,
    roots: super::nested_nonmoving_safepoint_probe::NestedNonmovingRootInventory,
    projection: Option<crate::eval::heap::YoungIncrementProjection>,
}

impl YoungIncrementProjectionProbe {
    /// Constructs a probe for one listed milestone and captures its initial fence.
    pub(super) fn from_env(heap: &EvalHeap) -> Option<Self> {
        let selected_ordinal = std::env::var(ORDINAL_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|ordinal| MILESTONES.contains(ordinal))?;
        let initial = heap.demand_region_allocation_fence()?;
        // Initial + one fence per completion + the returned-loop-head tail
        // fence. Preallocation keeps terminal sampling allocation-free before
        // its RSS observation.
        let mut fences = Vec::with_capacity(selected_ordinal as usize + 2);
        fences.push(initial);
        Some(Self {
            selected_ordinal,
            completions: 0,
            fence_error: false,
            internal_selected_observed: false,
            fences,
            snapshot: None,
        })
    }
}

impl TreeWalk {
    /// Captures one completion fence without admitting its internal callback.
    pub(super) fn note_young_increment_final_config_completion(&mut self, _result: Value) {
        let Some(probe) = self.young_increment_projection_probe.as_mut() else {
            return;
        };
        probe.completions = probe.completions.saturating_add(1);
        let ordinal = probe.completions;
        let Some(fence) = self.heap.demand_region_allocation_fence() else {
            probe.fence_error = true;
            return;
        };
        if probe.fences.try_reserve(1).is_err() {
            probe.fence_error = true;
            return;
        }
        probe.fences.push(fence);
        if ordinal == probe.selected_ordinal {
            probe.internal_selected_observed = true;
        }
    }

    /// Projects a selected ordinal only at its exact returned dispatcher loop head.
    pub(super) fn note_young_increment_returned_outer_loop_head(&mut self) {
        let selected_ordinal = self
            .young_increment_projection_probe
            .as_ref()
            .and_then(|probe| {
                (probe.internal_selected_observed
                    && returned_outer_matches(probe.selected_ordinal, probe.completions)
                    && probe.snapshot.is_none())
                .then_some(probe.selected_ordinal)
            });
        let Some(selected_ordinal) = selected_ordinal else {
            return;
        };

        let terminal_fence = self.heap.demand_region_allocation_fence();
        if let Some(probe) = self.young_increment_projection_probe.as_mut() {
            match terminal_fence {
                Some(fence) => probe.fences.push(fence),
                None => probe.fence_error = true,
            }
        }
        let returned =
            self.whole_demand_dispatcher.returned_loop_head_completions >= selected_ordinal;
        let structure_proven = self
            .dispatcher_collection_poll_structure_preflight()
            .is_ok();
        let mut snapshot = YoungIncrementProjectionSnapshot {
            ordinal: selected_ordinal,
            runtime_blockers: self
                .young_increment_terminal_runtime_blocker_count()
                .saturating_add(usize::from(
                    !returned || !structure_proven || terminal_fence.is_none(),
                )),
            internal_boundary_refusal: false,
            terminal_outer_boundary: true,
            terminal_outer_proven: false,
            root_error: false,
            projection_error: false,
            rss_unavailable: false,
            rss_error: false,
            rss_bytes: 0,
            reservation: self.heap.nested_nonmoving_runtime_reservation_snapshot(),
            roots: super::nested_nonmoving_safepoint_probe::NestedNonmovingRootInventory::default(),
            projection: None,
        };
        match ProcessResidentMemorySample::current() {
            Ok(Some(sample)) => snapshot.rss_bytes = sample.resident_bytes() as u64,
            Ok(None) => snapshot.rss_unavailable = true,
            Err(_) => snapshot.rss_error = true,
        }

        if snapshot.runtime_blockers == 0 {
            match self.dispatcher_collection_poll_preflight() {
                Ok(guard) => {
                    let roots = guard.into_roots();
                    let result_slot = self.whole_demand_dispatcher.value_slots.last().copied();
                    snapshot.roots.total_roots = roots.len();
                    snapshot.roots.result_roots = usize::from(result_slot.is_some_and(|slot| {
                        roots
                            .roots()
                            .iter()
                            .any(|root| root.source() == &EvalRootSource::ValueStack { slot })
                    }));
                    snapshot.terminal_outer_proven = true;
                    let fences = self
                        .young_increment_projection_probe
                        .as_ref()
                        .map(|probe| probe.fences.as_slice())
                        .unwrap_or_default();
                    match self.heap.young_increment_projection(&roots, fences) {
                        Ok(projection) => snapshot.projection = Some(projection),
                        Err(_) => snapshot.projection_error = true,
                    }
                }
                Err(_) => snapshot.root_error = true,
            }
        }
        if let Some(probe) = self.young_increment_projection_probe.as_mut() {
            probe.snapshot = Some(snapshot);
        }
    }

    /// Counts terminal blockers without requiring an active force census.
    ///
    /// The returned outer loop head owns its result in the dispatcher value
    /// slot and every synchronous force has returned. Exact root-bijection
    /// preflight therefore replaces the internal mixed-force census proof.
    fn young_increment_terminal_runtime_blocker_count(&self) -> usize {
        let native = self.native_continuation_snapshot();
        usize::from(!native.reconciled())
            .saturating_add(native.active_frames)
            .saturating_add(native.active_roots)
            .saturating_add(native.active_primop_contexts)
            .saturating_add(self.active_force_roots.len())
            .saturating_add(self.active_composite_accumulator_depth)
            .saturating_add(self.order_sensitive_binding_depth)
            .saturating_add(self.active_primop_arg_frames.len())
            .saturating_add(self.active_primop_arg_roots.len())
            .saturating_add(self.active_call_argument_plans.len())
            .saturating_add(self.active_import_cache_leases.len())
            .saturating_add(self.active_import_module_leases.len())
            .saturating_add(self.active_force_leases.len())
            .saturating_add(self.active_lambda_call_leases.len())
            .saturating_add(self.active_typed_thunk_work_leases.len())
            .saturating_add(usize::from(!self.stg_apply_runtime.is_idle()))
            .saturating_add(usize::from(self.stg_session_active))
            .saturating_add(usize::from(self.shared.is_some()))
            .saturating_add(usize::from(self.tier1_engine.is_some()))
            .saturating_add(usize::from(self.force_cache_active))
            .saturating_add(usize::from(
                self.options.memo_active() || self.options.boundary_memo_active(),
            ))
            .saturating_add(usize::from(
                self.persist_cache.is_some()
                    || !self.persist_secondary_caches.is_empty()
                    || self.options.persist_cache_root().is_some(),
            ))
    }

    /// Emits the selected projection and its fail-closed evidence gates.
    pub(super) fn emit_young_increment_projection_report(&self) {
        let Some(probe) = self.young_increment_projection_probe.as_ref() else {
            return;
        };
        let Some(snapshot) = probe.snapshot.as_ref() else {
            eprintln!(
                "aos_nix_young_increment_projection_refusal \
                 selected_ordinal={} completions={} selected_observed=false \
                 internal_selected_observed={} exact_returned_outer_observed=false \
                 fence_error={} collection=false mutation=false advice=false",
                probe.selected_ordinal,
                probe.completions,
                probe.internal_selected_observed,
                probe.fence_error,
            );
            return;
        };
        let resident_source_bytes = snapshot
            .reservation
            .resident_pages
            .saturating_mul(snapshot.reservation.page_size);
        if let Some(projection) = snapshot.projection.as_ref() {
            for variant in projection.variants {
                let projected_steady_rss = snapshot
                    .rss_bytes
                    .saturating_sub(resident_source_bytes)
                    .saturating_add(variant.retained_segment_bytes);
                let zero_unclassified = projection.unclassified == 0;
                let zero_blockers = snapshot.runtime_blockers == 0
                    && !snapshot.root_error
                    && !snapshot.projection_error
                    && !snapshot.rss_unavailable
                    && !snapshot.rss_error
                    && !probe.fence_error
                    && projection.fences_reconciled
                    && snapshot.reservation.residency_available
                    && !snapshot.reservation.residency_error;
                let target_pass =
                    zero_unclassified && zero_blockers && projected_steady_rss < RSS_CEILING_BYTES;
                eprintln!(
                    "aos_nix_young_increment_projection \
                     ordinal={} segment_bytes={} cohort_intervals={} streams={} \
                     roots={} reachable={} classified_objects={} \
                     classified_reachable={} unclassified={} \
                     total_segments={} live_segments={} dead_segments={} \
                     initialized_bytes={} retained_segment_bytes={} \
                     reclaimable_segment_bytes={} rss_bytes={} \
                     resident_source_bytes={} projected_steady_rss={} \
                     target_bytes={} target_pass={} zero_unclassified={} \
                     zero_blockers={} fences_reconciled={} \
                     internal_boundary_refusal={} terminal_outer_boundary={} \
                     terminal_outer_proven={} force_census_required=false \
                     same_layout_upper_bound=true packed_layout_exact=false \
                     registry_index_compaction_credited=false \
                     external_payload_reclamation_credited=false \
                     carried_prior_collection_state=false \
                     admission=false collection=false mutation=false advice=false",
                    snapshot.ordinal,
                    variant.segment_bytes,
                    projection.cohort_intervals,
                    EXPECTED_STREAMS,
                    projection.roots,
                    projection.reachable,
                    projection.classified_objects,
                    projection.classified_reachable,
                    projection.unclassified,
                    variant.total_segments,
                    variant.live_segments,
                    variant.dead_segments,
                    variant.initialized_bytes,
                    variant.retained_segment_bytes,
                    variant.reclaimable_segment_bytes,
                    snapshot.rss_bytes,
                    resident_source_bytes,
                    projected_steady_rss,
                    RSS_CEILING_BYTES,
                    target_pass,
                    zero_unclassified,
                    zero_blockers,
                    projection.fences_reconciled,
                    snapshot.internal_boundary_refusal,
                    snapshot.terminal_outer_boundary,
                    snapshot.terminal_outer_proven,
                );
            }
        }
        eprintln!(
            "aos_nix_young_increment_projection_conservation \
             selected_ordinal={} completions={} selected_observed=true \
             runtime_blockers={} root_error={} projection_error={} \
             internal_boundary_refusal={} terminal_outer_boundary={} \
             terminal_outer_proven={} force_census_required=false \
             rss_unavailable={} rss_error={} fence_error={} fences={} \
             single_traversal_per_process=true pre_scan_rss=true \
             approximation_blocks_admission=true collection=false mutation=false advice=false",
            probe.selected_ordinal,
            probe.completions,
            snapshot.runtime_blockers,
            snapshot.root_error,
            snapshot.projection_error,
            snapshot.internal_boundary_refusal,
            snapshot.terminal_outer_boundary,
            snapshot.terminal_outer_proven,
            snapshot.rss_unavailable,
            snapshot.rss_error,
            probe.fence_error,
            probe.fences.len(),
        );
    }
}

const fn returned_outer_matches(selected_ordinal: u64, completions: u64) -> bool {
    completions == selected_ordinal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn milestones_are_strict_and_include_the_terminal_completion() {
        assert!(MILESTONES.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(MILESTONES.last(), Some(&357));
    }

    #[test]
    fn returned_outer_boundary_must_match_the_selected_completion_exactly() {
        assert!(returned_outer_matches(357, 357));
        assert!(!returned_outer_matches(160, 357));
        assert!(!returned_outer_matches(160, 77));
    }
}
