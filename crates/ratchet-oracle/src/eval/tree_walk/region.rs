//! Region-placement adapters for the tree-walk evaluator.

use super::*;

impl TreeWalk {
    /// Runs discardable crate-internal work inside a worker-region mark.
    ///
    /// The marker is retired through [`EvalHeap::pop_worker_region_if_plan_permits`]
    /// after `run` returns. Plans that do not permit early pop leave the work's
    /// allocations in the heap and return `Ok(None)`. Plans that permit early
    /// pop reclaim the suffix only if the typed heap side-table validation can
    /// prove that the suffix contains only worker-domain records and no retained
    /// edge points into the marked region.
    ///
    /// The closure is deliberately discard-only. This helper does not return
    /// heap handles, but `Value` handles are copyable and the type system cannot
    /// prevent a closure from publishing one through captured state. Internal
    /// callers must use this only for already-proven no-escape scratch work:
    /// handles to worker-domain values allocated above the marker become invalid
    /// after a successful pop, and later bump allocation may reuse the same raw
    /// address for a different typed record. Callers must also not manipulate
    /// worker-region markers directly or leave nested markers active inside the
    /// closure; this helper owns the innermost worker marker during cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the worker marker cannot be created, if the
    /// marker cannot be retired, or if a pop-permitting plan fails the typed
    /// heap reclamation gate.
    ///
    /// # Panics
    ///
    /// Attempts to retire the worker marker before re-panicking if `run` panics.
    /// When `plan` permits early pop, also panics if the heap exhausts all
    /// region-owner ids while rotating an overflowed worker-region epoch.
    // Production allocation-site wiring is a later region-inference slice.
    #[allow(dead_code)]
    pub(crate) fn discard_worker_region_if_plan_permits(
        &mut self,
        plan: RegionPlan,
        run: impl FnOnce(&mut Self),
    ) -> Result<Option<EvalHeapWorkerRegionPopReport>, EvalHeapError> {
        let mark = self.heap.worker_region_mark()?;
        let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(self)));
        if let Err(payload) = run_result {
            let _ = self.heap.cancel_worker_region_mark(mark);
            std::panic::resume_unwind(payload);
        }

        let pop_result = self.heap.pop_worker_region_if_plan_permits(mark, plan);
        if pop_result.is_err() && plan.permits_early_pop() {
            self.heap.cancel_worker_region_mark(mark)?;
        }
        pop_result
    }

    /// Classifies one current-module allocation candidate for region placement.
    ///
    /// This is a policy adapter only. It does not change allocation behavior or
    /// prove that a site has been placed in a worker subregion.
    pub(super) fn region_plan_for_allocation(
        &self,
        id: IrId,
        tier: RegionRuntimeTier,
    ) -> RegionPlan {
        RegionPlan::classify(tier, self.allocation_region_facts(id))
    }

    /// Returns conservative region facts for one current-module IR node.
    ///
    /// Missing nodes or fact records fail closed to
    /// [`AllocationRegionFacts::conservative`]. Hash-consed reusable value
    /// shapes are marked permanent shared so they bypass lexical region
    /// placement. A lexical subregion candidate is emitted only when the
    /// existing IR facts prove strict, no-escape, speculable evaluation for a
    /// private non-thunk allocation site.
    pub(super) fn allocation_region_facts(&self, id: IrId) -> AllocationRegionFacts {
        let ir = self.current_ir();
        let Some(node) = ir.arena.node(id) else {
            return AllocationRegionFacts::conservative();
        };
        let Some(facts) = ir.node_facts(id) else {
            return AllocationRegionFacts::conservative();
        };
        allocation_region_facts_for_node(node, facts)
    }
}

fn allocation_region_facts_for_node(node: &IrNode, facts: ExprFacts) -> AllocationRegionFacts {
    let proven_no_escape = facts.escape == Escape::NoEscape;
    let thunk_like = matches!(node.kind, IrKind::ThunkAlloc);
    let no_latent_force = facts.strictness.is_demanded() && !thunk_like;
    let speculable = node.effect.is_speculable();
    let sharing = allocation_region_sharing_for_node(node.kind);

    AllocationRegionFacts {
        escapes_frame: !proven_no_escape,
        has_latent_force: !no_latent_force,
        effect: if speculable {
            RegionEffect::Speculable
        } else {
            RegionEffect::Effectful
        },
        lifetime: if proven_no_escape && !thunk_like {
            RegionLifetime::Lexical
        } else {
            RegionLifetime::Unbounded
        },
        sharing,
    }
}

fn allocation_region_sharing_for_node(kind: IrKind) -> RegionSharing {
    match kind {
        IrKind::Str
        | IrKind::Path
        | IrKind::SearchPath
        | IrKind::Uri
        | IrKind::List
        | IrKind::AttrSet
        | IrKind::Interp => RegionSharing::SharedPermanent,
        _ => RegionSharing::Private,
    }
}
