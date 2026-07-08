//! Region-placement adapter tests for the tree-walk evaluator.

use super::*;
use crate::compile::Cardinality;
use crate::heap::{AllocationRegionFacts, RegionPlacement, RegionPlacementReason, RegionPlan};

#[test]
fn region_plan_for_allocation_fails_closed_for_conservative_facts() {
    let ir = lower("x: x");
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
    let mut ir = lower("x: x");
    *ir.facts.get_mut(ir.root).expect("root fact exists") = ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
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
fn region_plan_for_allocation_routes_hash_consed_shapes_to_permanent_shared() {
    for (source, label) in [
        ("[ 1 ]", "list"),
        ("{ a = 1; }", "attrset"),
        (r#""value""#, "string"),
        (r#""pre-${"value"}""#, "interpolated string"),
        ("./value.nix", "path"),
        ("<nixpkgs>", "search path"),
        ("https://example.test/value", "uri"),
    ] {
        let mut ir = lower(source);
        *ir.facts.get_mut(ir.root).expect("root fact exists") = ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Many,
            escape: Escape::NoEscape,
        };
        let evaluator = TreeWalk::new(&ir);

        let facts = evaluator.allocation_region_facts(ir.root);
        let plan = evaluator.region_plan_for_allocation(ir.root, RegionRuntimeTier::OneShotArena);

        assert_eq!(facts.sharing, RegionSharing::SharedPermanent, "{label}");
        assert_eq!(plan.placement, RegionPlacement::PermanentShared, "{label}");
        assert_eq!(
            plan.reason,
            RegionPlacementReason::PermanentSharing,
            "{label}"
        );
    }
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
            Strictness::DemandedBeforeEffect,
            Escape::Escapes,
            "strict escaping node leaves the frame",
        ),
    ] {
        let mut ir = lower("x: x");
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
        strictness: Strictness::DemandedBeforeEffect,
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
            IrKind::Lambda,
            Span::new(0, 2),
            EffectClass::new(7, false),
            IrData::None,
        )],
    );
    *ir.facts.get_mut(root).expect("root fact exists") = ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
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

#[test]
fn region_plan_decision_telemetry_counts_policy_outcomes() {
    let mut evaluator = TreeWalk::new(&lower("null"));

    evaluator.record_source_thunk_region_plan_decision(RegionPlan::classify(
        RegionRuntimeTier::OneShotArena,
        AllocationRegionFacts::lexical_no_escape(),
    ));
    evaluator.record_source_thunk_region_plan_decision(RegionPlan::classify(
        RegionRuntimeTier::OneShotArena,
        AllocationRegionFacts::conservative(),
    ));

    let stats = evaluator.stats();
    assert_eq!(stats.source_thunk_region_plan_decisions(), 2);
    assert_eq!(
        stats.source_thunk_region_plan_lexical_subregion_decisions(),
        1
    );
    assert_eq!(stats.source_thunk_region_plan_conservative_fallbacks(), 1);
}

#[test]
fn discard_worker_region_scope_pops_when_plan_permits() {
    let ir = lower("1 + 2");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let plan = RegionPlan::classify(
        RegionRuntimeTier::OneShotArena,
        AllocationRegionFacts::lexical_no_escape(),
    );

    let report = evaluator
        .discard_worker_region_if_plan_permits(plan, |eval| {
            let value = eval
                .alloc_thunk_for_node(ir.root, ir.root, span)
                .expect("discarded worker thunk allocates");
            assert_eq!(value.tag(), ValueTag::Thunk);
        })
        .expect("lexical worker region scope retires")
        .expect("lexical no-escape plan permits pop");

    assert_eq!(report.reclaimed_records(), 1);
    assert_eq!(report.records_after(), 0);
    assert!(report.arena_report().used_bytes_released() > 0);
    assert_eq!(evaluator.heap().len(), 0);
    assert_eq!(evaluator.stats().thunks_allocated(), 1);
    assert_eq!(evaluator.stats().source_thunk_region_plan_decisions(), 0);
}

#[test]
fn discard_worker_region_scope_cancels_when_plan_is_conservative() {
    let ir = lower("1 + 2");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let plan = RegionPlan::classify(
        RegionRuntimeTier::OneShotArena,
        AllocationRegionFacts::conservative(),
    );

    let report = evaluator
        .discard_worker_region_if_plan_permits(plan, |eval| {
            let value = eval
                .alloc_thunk_for_node(ir.root, ir.root, span)
                .expect("retained worker thunk allocates");
            assert_eq!(value.tag(), ValueTag::Thunk);
        })
        .expect("conservative worker region scope retires");

    assert_eq!(report, None);
    assert_eq!(evaluator.heap().len(), 1);
    assert_eq!(evaluator.stats().thunks_allocated(), 1);
}

#[test]
fn discard_worker_region_scope_retires_mark_after_pop_error() {
    let ir = lower("1 + 2");
    let mut evaluator = TreeWalk::new(&ir);
    let plan = RegionPlan::classify(
        RegionRuntimeTier::OneShotArena,
        AllocationRegionFacts::lexical_no_escape(),
    );

    let error = evaluator
        .discard_worker_region_if_plan_permits(plan, |eval| {
            let value = eval
                .heap
                .alloc_string(NixString::from_bytes(b"permanent".to_vec()))
                .expect("permanent string allocates");
            assert_eq!(value.tag(), ValueTag::String);
        })
        .expect_err("permanent suffix rejects lexical worker-region pop");

    assert_eq!(
        error,
        EvalHeapError::WorkerRegionPopNonWorkerRecords { records: 1 }
    );
    assert_eq!(evaluator.heap.active_worker_region_marks_for_test(), 0);
    assert_eq!(evaluator.heap().len(), 1);
}

#[test]
fn discard_worker_region_scope_retires_mark_after_retained_edge_error() {
    let ir = lower("1 + 2");
    let mut evaluator = TreeWalk::new(&ir);
    let retained = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(10)))
        .expect("retained thunk allocates before marker");
    let plan = RegionPlan::classify(
        RegionRuntimeTier::OneShotArena,
        AllocationRegionFacts::lexical_no_escape(),
    );

    let error = evaluator
        .discard_worker_region_if_plan_permits(plan, |eval| {
            let forced = eval
                .heap
                .alloc_lambda(EvalLambda::new(
                    IrId::new(20),
                    IrId::new(21),
                    FrameId::new(0),
                    EvalEnv::default(),
                ))
                .expect("worker lambda allocates above marker");
            let retained_thunk = eval
                .heap
                .clone_thunk(retained)
                .expect("retained thunk exists");
            let crate::eval::ForceClaim::Claimed(guard) = retained_thunk
                .cell()
                .begin_force()
                .expect("retained thunk claim succeeds")
            else {
                panic!("retained thunk should be claimable");
            };
            guard
                .finish(forced)
                .expect("forced value publishes into retained thunk");
        })
        .expect_err("retained edge rejects lexical worker-region pop");

    assert!(matches!(
        error,
        EvalHeapError::WorkerRegionPopRetainedEdge { .. }
    ));
    assert_eq!(evaluator.heap.active_worker_region_marks_for_test(), 0);
    assert_eq!(evaluator.heap().len(), 2);
    assert!(evaluator.heap().get_thunk(retained).is_ok());
}

#[test]
fn discard_worker_region_scope_retires_mark_after_panic() {
    let ir = lower("1 + 2");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let plan = RegionPlan::classify(
        RegionRuntimeTier::OneShotArena,
        AllocationRegionFacts::lexical_no_escape(),
    );

    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = evaluator.discard_worker_region_if_plan_permits(plan, |eval| {
            let value = eval
                .alloc_thunk_for_node(ir.root, ir.root, span)
                .expect("worker thunk allocates before panic");
            assert_eq!(value.tag(), ValueTag::Thunk);
            panic!("scope panic");
        });
    }));

    assert!(panic_result.is_err());
    assert_eq!(evaluator.heap.active_worker_region_marks_for_test(), 0);
    assert_eq!(evaluator.heap().len(), 1);
}

#[test]
fn allocated_thunks_record_conservative_region_plan_telemetry() {
    let outcome = eval_whnf_owned(&lower("[ (1 + 6) ]")).expect("thunked list evaluates");

    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.stats().source_thunk_region_plan_decisions(), 1);
    assert_eq!(
        outcome
            .stats()
            .source_thunk_region_plan_lexical_subregion_decisions(),
        0
    );
    assert_eq!(
        outcome
            .stats()
            .source_thunk_region_plan_conservative_fallbacks(),
        1
    );
}

#[test]
fn synthetic_thunk_helpers_do_not_record_source_thunk_region_telemetry() {
    let ir = lower("1 + 2");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&ir);

    let value = evaluator
        .alloc_thunk_for_node(ir.root, ir.root, span)
        .expect("synthetic thunk allocates");

    assert_eq!(value.tag(), ValueTag::Thunk);
    let stats = evaluator.stats();
    assert_eq!(stats.thunks_allocated(), 1);
    assert_eq!(stats.source_thunk_region_plan_decisions(), 0);
    assert_eq!(
        stats.source_thunk_region_plan_lexical_subregion_decisions(),
        0
    );
    assert_eq!(stats.source_thunk_region_plan_conservative_fallbacks(), 0);
}

#[test]
fn empty_foldl_synthetic_initial_thunk_does_not_record_source_thunk_region_telemetry() {
    let outcome = eval_whnf_owned(&lower("builtins.foldl' (acc: x: acc) (1 + 2) []"))
        .expect("empty foldl' evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.stats().source_thunk_region_plan_decisions(), 0);
    assert_eq!(
        outcome
            .stats()
            .source_thunk_region_plan_lexical_subregion_decisions(),
        0
    );
    assert_eq!(
        outcome
            .stats()
            .source_thunk_region_plan_conservative_fallbacks(),
        0
    );
}
