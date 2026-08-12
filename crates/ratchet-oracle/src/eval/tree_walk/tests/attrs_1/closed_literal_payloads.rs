//! Force-cache payload tests for closed literal list and attrset thunks.

use super::*;

#[test]
fn closed_literal_lazy_list_payload_hits_rehydrate_static_elements() {
    let (ir, a) = position_free_closed_literal_lazy_list_ir();
    let source = "{ a = [ 1 ]; }";
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    assert!(ir.bindings.iter().all(|binding| binding.position.is_none()));

    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "closed-literal-lazy-list-hit.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("a is a node thunk");
            let body = thunk.body().expect("a has a lowered list body");
            let node = ir.arena.node(body).expect("list body exists");
            assert_eq!(node.kind, IrKind::List);
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("closed literal lazy list subject builds")
        };
        assert_eq!(
            subject.memoization_admission,
            ForceCacheMemoizationAdmission::SelectedSubstrate,
            "closed literal lazy lists should admit on first demand"
        );

        let forced = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("closed literal lazy list force succeeds");
        let list = evaluator
            .heap()
            .get_list(forced)
            .expect("forced value is a list");
        let element = list.get(0).expect("element exists");
        if expected_hit {
            assert_eq!(element.as_int(), Ok(1));
        } else {
            assert_eq!(element.tag(), ValueTag::Thunk);
            let element_thunk = evaluator
                .heap()
                .get_thunk(element)
                .expect("cold list keeps the literal element lazy");
            assert_eq!(element_thunk.cell().state(), Ok(ThunkState::Suspended));
        }
        assert_eq!(evaluator.stats().force_cache_memoization_bypasses(), 0);
        assert!(
            evaluator.stats().force_cache_memoization_admits() > 0,
            "closed literal lazy list forces should be admitted"
        );
        assert!(
            evaluator.stats().force_cache_probes() > 0,
            "closed literal lazy list forces should probe the shared cache"
        );
        if expected_hit {
            assert!(evaluator.stats().force_cache_hits() > 0);
            assert_eq!(evaluator.stats().force_cache_misses(), 0);
        } else {
            assert_eq!(evaluator.stats().force_cache_hits(), 0);
            assert!(evaluator.stats().force_cache_misses() > 0);
        }
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }
}

// Builds synthetic position-free IR rather than parser-lowered source IR so
// attr position metadata does not block the replayable payload path under test.
#[test]
fn closed_literal_lazy_attrset_payload_hits_rehydrate_static_bindings() {
    let (ir, a, b) = position_free_closed_literal_lazy_attrset_ir();
    let source = "{ a = { b = 1; }; }";
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    assert!(ir.bindings.iter().all(|binding| binding.position.is_none()));

    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "closed-literal-lazy-attrset-hit.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("a is a node thunk");
            let body = thunk.body().expect("a has a lowered attrset body");
            let node = ir.arena.node(body).expect("attrset body exists");
            assert_eq!(node.kind, IrKind::AttrSet);
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("closed literal lazy attrset subject builds")
        };
        assert_eq!(
            subject.memoization_admission,
            ForceCacheMemoizationAdmission::SelectedSubstrate,
            "closed literal lazy attrsets should admit on first demand"
        );

        let forced = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("closed literal lazy attrset force succeeds");
        let attrs = evaluator
            .heap()
            .get_attrs(forced)
            .expect("forced value is an attrset");
        let binding = attrs.get(b).expect("b exists");
        if expected_hit {
            assert_eq!(binding.as_int(), Ok(1));
        } else {
            assert_eq!(binding.tag(), ValueTag::Thunk);
            let binding_thunk = evaluator
                .heap()
                .get_thunk(binding)
                .expect("cold attrset keeps the literal binding lazy");
            assert_eq!(binding_thunk.cell().state(), Ok(ThunkState::Suspended));
        }
        assert_eq!(evaluator.stats().force_cache_memoization_bypasses(), 0);
        assert!(
            evaluator.stats().force_cache_memoization_admits() > 0,
            "closed literal lazy attrset forces should be admitted"
        );
        assert!(
            evaluator.stats().force_cache_probes() > 0,
            "closed literal lazy attrset forces should probe the shared cache"
        );
        if expected_hit {
            assert!(evaluator.stats().force_cache_hits() > 0);
            assert_eq!(evaluator.stats().force_cache_misses(), 0);
        } else {
            assert_eq!(evaluator.stats().force_cache_hits(), 0);
            assert!(evaluator.stats().force_cache_misses() > 0);
        }
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }
}

#[test]
fn closed_source_order_attrset_literal_thunks_admit_and_rehydrate_source_order() {
    let (ir, a) = position_free_source_order_attrset_ir();
    let source = "{ a = { c = 2; b = 1; }; }";
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "source-order-composite-first-demand.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("a is a node thunk");
            let body = thunk.body().expect("a has a lowered attrset body");
            let node = ir.arena.node(body).expect("attrset body exists");
            assert_eq!(node.kind, IrKind::AttrSet);
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("closed source-order attrset subject builds")
        };
        assert_eq!(
            subject.memoization_admission,
            ForceCacheMemoizationAdmission::SelectedSubstrate,
            "closed source-order attrset literals should admit on first demand"
        );

        let forced = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("source-order attrset literal force succeeds");
        assert_source_order_attrset_ints(&evaluator, forced, &[(b"c", 2), (b"b", 1)]);
        assert_eq!(evaluator.stats().force_cache_memoization_bypasses(), 0);
        assert_eq!(evaluator.stats().force_cache_memoization_admits(), 1);
        assert_eq!(
            evaluator.stats().force_cache_hits() > 0,
            expected_hit,
            "second raw force should hit the closed source-order attrset payload"
        );
    }
}
