//! Region-placement adapter tests for the tree-walk evaluator.

use super::*;
use crate::compile::Cardinality;
use crate::heap::{RegionPlacement, RegionPlacementReason};

#[test]
fn region_plan_for_allocation_fails_closed_for_conservative_facts() {
    let ir = lower("[ (1 + 2) ]");
    let evaluator = TreeWalk::new(&ir);

    let plan = evaluator.region_plan_for_allocation(ir.root, RegionRuntimeTier::OneShotArena);

    assert_eq!(plan.placement, RegionPlacement::RootArena);
    assert_eq!(plan.reason, RegionPlacementReason::ConservativeFallback);
    assert_eq!(
        evaluator.allocation_region_facts(IrId::new(999_999)),
        AllocationRegionFacts::conservative()
    );
}

#[test]
fn region_plan_for_allocation_uses_strict_no_escape_facts() {
    let mut ir = lower("[ 1 ]");
    *ir.facts.get_mut(ir.root).expect("root fact exists") = ExprFacts {
        strictness: Strictness::Strict,
        cardinality: Cardinality::Many,
        escape: Escape::NoEscape,
    };
    let evaluator = TreeWalk::new(&ir);

    let facts = evaluator.allocation_region_facts(ir.root);
    let plan = evaluator.region_plan_for_allocation(ir.root, RegionRuntimeTier::OneShotArena);

    assert_eq!(facts, AllocationRegionFacts::lexical_no_escape());
    assert_eq!(plan.placement, RegionPlacement::LexicalSubregion);
    assert_eq!(plan.reason, RegionPlacementReason::ProvenLexicalNoEscape);
}

#[test]
fn region_plan_for_allocation_requires_strictness_and_no_escape() {
    for (strictness, escape, label) in [
        (
            Strictness::Unknown,
            Escape::NoEscape,
            "no escape without strictness has latent force",
        ),
        (
            Strictness::Strict,
            Escape::Escapes,
            "strict escaping node leaves the frame",
        ),
    ] {
        let mut ir = lower("[ 1 ]");
        *ir.facts.get_mut(ir.root).expect("root fact exists") = ExprFacts {
            strictness,
            cardinality: Cardinality::Many,
            escape,
        };
        let evaluator = TreeWalk::new(&ir);

        let plan = evaluator.region_plan_for_allocation(ir.root, RegionRuntimeTier::OneShotArena);

        assert_eq!(plan.placement, RegionPlacement::RootArena, "{label}");
        assert_eq!(
            plan.reason,
            RegionPlacementReason::ConservativeFallback,
            "{label}"
        );
    }
}

#[test]
fn region_plan_for_allocation_keeps_thunk_allocations_conservative() {
    let body = IrId::new(0);
    let root = IrId::new(1);
    let mut ir = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(1, 2), IrData::Int(1)),
            pure_node(IrKind::ThunkAlloc, Span::new(0, 3), IrData::Node(body)),
        ],
    );
    *ir.facts.get_mut(root).expect("root fact exists") = ExprFacts {
        strictness: Strictness::Strict,
        cardinality: Cardinality::Once,
        escape: Escape::NoEscape,
    };
    let evaluator = TreeWalk::new(&ir);

    let facts = evaluator.allocation_region_facts(root);
    let plan = evaluator.region_plan_for_allocation(root, RegionRuntimeTier::OneShotArena);

    assert_eq!(facts.escapes_frame, false);
    assert_eq!(facts.has_latent_force, true);
    assert_eq!(facts.lifetime, RegionLifetime::Unbounded);
    assert_eq!(plan.placement, RegionPlacement::RootArena);
    assert_eq!(plan.reason, RegionPlacementReason::ConservativeFallback);
}

#[test]
fn region_plan_for_allocation_requires_speculable_effects() {
    let root = IrId::new(0);
    let mut ir = manual_ir(
        root,
        vec![IrNode::new(
            IrKind::List,
            Span::new(0, 2),
            EffectClass::new(7, false),
            IrData::Children(IrChildSlice::new(0, 0)),
        )],
    );
    *ir.facts.get_mut(root).expect("root fact exists") = ExprFacts {
        strictness: Strictness::Strict,
        cardinality: Cardinality::Once,
        escape: Escape::NoEscape,
    };
    let evaluator = TreeWalk::new(&ir);

    let facts = evaluator.allocation_region_facts(root);
    let plan = evaluator.region_plan_for_allocation(root, RegionRuntimeTier::OneShotArena);

    assert_eq!(facts.effect, RegionEffect::Effectful);
    assert_eq!(facts.has_latent_force, false);
    assert_eq!(facts.escapes_frame, false);
    assert_eq!(plan.placement, RegionPlacement::RootArena);
    assert_eq!(plan.reason, RegionPlacementReason::ConservativeFallback);
}
