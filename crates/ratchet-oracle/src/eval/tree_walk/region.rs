//! Region-placement adapters for the tree-walk evaluator.

#![allow(dead_code)]

use super::*;

impl TreeWalk {
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
    /// [`AllocationRegionFacts::conservative`]. A lexical subregion candidate is
    /// emitted only when the existing IR facts prove strict, no-escape,
    /// speculable evaluation for a non-thunk allocation site.
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
    let no_latent_force = facts.strictness == Strictness::Strict && !thunk_like;
    let speculable = node.effect.is_speculable();

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
        sharing: RegionSharing::Private,
    }
}
