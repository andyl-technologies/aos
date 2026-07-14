//! Split-out tests (part_11). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_attrs_accumulator_allocation_node_clears_after_binding_error() {
    let span = Span::new(0, 1);
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let b = symbols.intern(b"b").expect("b interns");
    let body = IrId::new(0);
    let first_value = IrId::new(1);
    let error_value = IrId::new(2);
    let root = IrId::new(3);
    let ir = manual_ir_with_attr_tables(
        root,
        vec![
            pure_node(IrKind::Int, span, IrData::Int(7)),
            pure_node(IrKind::ThunkAlloc, span, IrData::Node(body)),
            pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 }),
            pure_node(
                IrKind::AttrSet,
                span,
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 2),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
        ],
        symbols,
        vec![
            IrBinding {
                key: IrAttrPathSegment::Static(a),
                position: None,
                value: first_value,
            },
            IrBinding {
                key: IrAttrPathSegment::Static(b),
                position: None,
                value: error_value,
            },
        ],
        vec![IrShape::new(vec![a, b].into_boxed_slice())],
    );
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let error = evaluator
        .eval_root()
        .expect_err("invalid attr binding reports evaluation error");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingEnvironment { id: error_value }
    );
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert!(heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values) >= 1);
    assert_eq!(evaluator.active_root_eval_node, None);
    assert_eq!(evaluator.active_gc_stress_accumulator_allocation_node, None);
    assert_eq!(evaluator.active_composite_accumulator_depth, 0);
    assert!(evaluator.transient_value_stack_roots().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_attrs_allocation_dispatch_skips_captured_lexical_env_fields() {
    let ir = lower("rec { a = b; b = x: x; }");
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let default_outcome = eval_whnf_owned(&ir).expect("default recursive attrset evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress recursive attrset evaluates without unsupported captured-env writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let (a_value, b_value) = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("b exists"),
        )
    };
    assert_eq!(a_value.tag(), ValueTag::Thunk);
    assert_eq!(b_value.tag(), ValueTag::Thunk);
    let a_thunk = outcome
        .heap()
        .get_thunk(a_value)
        .expect("a is a heap-owned thunk");
    let b_thunk = outcome
        .heap()
        .get_thunk(b_value)
        .expect("b is a heap-owned thunk");
    assert!(a_thunk.env().is_some_and(|env| !env.frames().is_empty()));
    assert!(b_thunk.env().is_some_and(|env| !env.frames().is_empty()));

    assert_eq!(
        outcome.heap().permanent_allocation_safepoints().count(),
        default_outcome
            .heap()
            .permanent_allocation_safepoints()
            .count()
    );
    let permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("recursive attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_thunk_allocation_dispatch_skips_active_lexical_env_frames() {
    let ir = lower("let r = rec { a = b; b = x: x; }; in { inherit (r) a; }");
    let a = symbol_for(&ir, b"a");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress inherited select evaluates without active-frame writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let selected = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(selected.tag(), ValueTag::Thunk);
    let selected_thunk = outcome
        .heap()
        .get_thunk(selected)
        .expect("inherited select is a heap-owned thunk");
    assert!(selected_thunk.env().is_none());
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_attrs_allocation_dispatch_skips_synthetic_select_thunk_fields() {
    let ir = lower("{ inherit ({ a = 1; }) a; }");
    let a = symbol_for(&ir, b"a");
    let default_outcome = eval_whnf_owned(&ir).expect("default inherited attrset evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress inherited attrset evaluates without synthetic select writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let selected = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(selected.tag(), ValueTag::Thunk);
    let selected_thunk = outcome
        .heap()
        .get_thunk(selected)
        .expect("inherited select is a heap-owned thunk");
    assert!(matches!(
        selected_thunk.kind(),
        EvalThunkKind::Select { .. }
    ));
    assert_eq!(
        outcome.heap().permanent_allocation_safepoints().count(),
        default_outcome
            .heap()
            .permanent_allocation_safepoints()
            .count()
    );
    let permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_thunk_allocation_dispatch_skips_application_argument_locals() {
    let ir = lower("(x: 1) (y: y)");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress root application evaluates without hidden callee-local writebacks");

    assert_eq!(outcome.value().as_int(), Ok(1));
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert_eq!(thunk_values.len(), 1);
    assert_eq!(
        outcome
            .heap()
            .generation(thunk_values[0])
            .expect("argument thunk source generation is known"),
        HeapGeneration::Young
    );
    let final_worker_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("argument thunk allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_thunk_allocation_dispatch_skips_synthetic_apply_accumulators() {
    let ir = lower("builtins.map (x: x) [ 1 2 ]");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress map evaluates without synthetic apply accumulator writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::List);
    let elements = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("mapped list is heap-owned");
        assert_eq!(list.len(), 2);
        [
            list.get(0).expect("first mapped element exists"),
            list.get(1).expect("second mapped element exists"),
        ]
    };
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert_eq!(thunk_values.len(), elements.len());
    for element in elements {
        assert_eq!(element.tag(), ValueTag::Thunk);
        assert!(thunk_values.iter().any(|value| value.raw_eq(element)));
        let thunk = outcome
            .heap()
            .get_thunk(element)
            .expect("mapped element is a heap-owned thunk");
        assert!(matches!(thunk.kind(), EvalThunkKind::Apply { .. }));
    }
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_attrs_allocation_dispatch_skips_direct_eval_node_callers() {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let value = evaluator
        .eval_node(ir.root)
        .expect("direct attrset node evaluation succeeds");

    assert_eq!(value.tag(), ValueTag::Attrs);
    let attr_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(attr_value.tag(), ValueTag::Thunk);
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(thunk_values.len(), 1);
    assert_eq!(
        thunk_values
            .iter()
            .filter(|value| value.raw_eq(attr_value))
            .count(),
        1
    );
    assert!(evaluator.heap().allocation_safepoints().count() >= 1);
    let final_worker_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("direct attrset worker allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        1
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("direct attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

#[test]
fn heap_cheap_memory_advice_option_can_be_configured() {
    let mut options = TreeWalkOptions::new();

    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), None);
    options.set_heap_cheap_memory_advice_min_idle_epochs(7);
    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), Some(7));
    options.clear_heap_cheap_memory_advice();
    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), None);

    let options = TreeWalkOptions::with_heap_cheap_memory_advice_min_idle_epochs(3);
    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), Some(3));
}

#[test]
fn heap_cheap_memory_advice_option_reports_after_tree_walk_eval() {
    let ir = lower("\"advised\"");
    let default_outcome = eval_whnf_owned(&ir).expect("string evaluates without advice");
    assert_eq!(default_outcome.cheap_memory_advice_report(), None);
    assert_eq!(default_outcome.cheap_memory_budget_plan(), None);

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_heap_cheap_memory_advice_min_idle_epochs(0),
    )
    .expect("string evaluates");

    assert_eq!(outcome.stats(), default_outcome.stats());
    assert_eq!(
        outcome
            .heap()
            .get_string(outcome.value())
            .expect("advised result is a heap-owned string")
            .bytes(),
        default_outcome
            .heap()
            .get_string(default_outcome.value())
            .expect("default result is a heap-owned string")
            .bytes()
    );
    let report = outcome
        .cheap_memory_advice_report()
        .expect("cheap heap advice report is recorded");
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Cold);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
    assert!(report.cold_hash_consed().records() >= 1);
    assert!(report.cold_hash_consed().requested_bytes() > 0);
    assert_eq!(outcome.heap().memory_budget_poll_count(), 0);
    assert_eq!(outcome.heap().last_memory_budget_action(), None);
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

#[test]
fn heap_cheap_memory_advice_option_reports_after_attr_path_eval() {
    let ir = lower("{ selected = \"advised\"; }");
    let attr_path = vec![b"selected".to_vec()];
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &attr_path,
        TreeWalkOptions::with_heap_cheap_memory_advice_min_idle_epochs(0),
        None,
    )
    .expect("attr-path evaluation succeeds");

    let report = outcome
        .cheap_memory_advice_report()
        .expect("attr-path outcomes also carry the post-evaluation advice report");
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Cold);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
    assert_eq!(outcome.heap().memory_budget_poll_count(), 0);
    assert_eq!(outcome.heap().last_memory_budget_action(), None);
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

#[test]
fn heap_budget_and_cheap_advice_options_report_cold_aware_plan() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("\"planned\"");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("string evaluates");

    let action = outcome
        .memory_budget_action()
        .expect("heap budget still records the automatic action");
    assert_eq!(action.decision().budget(), budget);
    assert_eq!(
        action.decision().sample().cold_hash_consed_bytes(),
        0,
        "automatic allocation polling stays on unused-tail action telemetry"
    );
    let plan = outcome
        .cheap_memory_budget_plan()
        .expect("combined options record a cold-aware budget plan");
    assert_eq!(plan.decision().budget(), budget);
    assert!(
        plan.decision().sample().cold_hash_consed_bytes() > 0,
        "the opt-in plan carries cold hash-consed spill capacity"
    );
    let plan_report = plan
        .cheap_advice_report()
        .expect("over-budget cold-aware planning records advice telemetry");
    assert_eq!(outcome.cheap_memory_advice_report(), Some(plan_report));
    assert_eq!(outcome.cold_hash_consed_value_materialization(), None);
    assert_eq!(plan_report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(
        plan_report.cold_hash_consed().kind(),
        MemoryAdviceKind::Evict
    );
    assert_eq!(plan_report.cold_hash_consed().min_idle_epochs(), 0);
}

#[test]
fn heap_budget_and_persistent_cache_materialize_cold_values_after_reclaim_plan() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let persist_root = unique_temp_dir("heap-budget-cold-value-materialization");
    let ir = lower("\"spill-prep\"");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);
    options.set_persist_cache_root(&persist_root);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("string evaluates");

    let plan = outcome
        .cheap_memory_budget_plan()
        .expect("combined options record a cold-aware budget plan");
    assert!(
        plan.cheap_advice_report().is_some(),
        "the tiny budget should request reclaim"
    );
    let materialization = outcome
        .cold_hash_consed_value_materialization()
        .expect("persistent cache root enables cold value materialization");
    assert!(materialization.candidates() >= 1);
    assert_eq!(materialization.captured(), materialization.candidates());
    assert_eq!(materialization.uncapturable(), 0);
    assert_eq!(materialization.errors(), 0);
    assert_eq!(materialization.cache_unavailable(), 0);
    assert_eq!(
        materialization.materialized_hashes().len(),
        materialization.materialized()
    );
    assert!(
        !materialization.materialized_hashes().is_empty(),
        "the outcome report should name the ensured indexed value payloads"
    );

    let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
    for value_hash in materialization.materialized_hashes() {
        let payload = persist_cache
            .load_cached_expression_value_indexed(*value_hash)
            .expect("indexed value load succeeds")
            .expect("indexed value exists");
        assert_eq!(payload.value_hash().expect("payload hashes"), *value_hash);
    }

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn attr_path_heap_budget_and_persistent_cache_materialize_cold_values_after_reclaim_plan() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let persist_root = unique_temp_dir("attr-path-heap-budget-cold-value-materialization");
    let ir = lower("{ selected = \"spill-prep-attr\"; }");
    let attr_path = vec![b"selected".to_vec()];
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);
    options.set_persist_cache_root(&persist_root);

    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir, &attr_path, options, None,
    )
    .expect("attr-path selection evaluates");
    assert_eq!(
        outcome
            .heap()
            .get_string(outcome.value())
            .expect("selected value is a heap-owned string")
            .bytes(),
        b"spill-prep-attr"
    );

    let plan = outcome
        .cheap_memory_budget_plan()
        .expect("attr-path outcome records a cold-aware budget plan");
    assert!(
        plan.cheap_advice_report().is_some(),
        "the tiny budget should request reclaim"
    );
    let materialization = outcome
        .cold_hash_consed_value_materialization()
        .expect("attr-path outcome runs cold value materialization");
    assert!(materialization.candidates() >= 1);
    assert_eq!(materialization.captured(), materialization.candidates());
    assert_eq!(materialization.uncapturable(), 0);
    assert_eq!(materialization.errors(), 0);
    assert_eq!(materialization.cache_unavailable(), 0);
    assert_eq!(
        materialization.materialized_hashes().len(),
        materialization.materialized()
    );
    assert!(
        !materialization.materialized_hashes().is_empty(),
        "the attr-path report should name the ensured indexed value payloads"
    );

    let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
    for value_hash in materialization.materialized_hashes() {
        let payload = persist_cache
            .load_cached_expression_value_indexed(*value_hash)
            .expect("indexed value load succeeds")
            .expect("indexed value exists");
        assert_eq!(payload.value_hash().expect("payload hashes"), *value_hash);
    }

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn heap_budget_and_cheap_advice_options_fall_back_to_cold_advice_under_soft_limit() {
    let budget = HeapMemoryBudget::new(usize::MAX).expect("budget is non-zero");
    let ir = lower("\"under-budget\"");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("string evaluates");

    let plan = outcome
        .cheap_memory_budget_plan()
        .expect("combined options record a cold-aware budget plan");
    assert!(matches!(
        plan.decision().response(),
        HeapMemoryBudgetResponse::ContinueTierA { .. }
    ));
    assert_eq!(plan.cheap_advice_report(), None);
    let report = outcome
        .cheap_memory_advice_report()
        .expect("under-budget combined options still record plain advice telemetry");
    assert_eq!(outcome.cold_hash_consed_value_materialization(), None);
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Cold);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
}

#[test]
fn force_cache_materialization_costs_can_be_configured() {
    let costs = MaterializationCosts::new(20, 3, 4, 5);
    let mut options = TreeWalkOptions::new();

    assert_eq!(
        options.force_cache_materialization_costs(),
        MaterializationCosts::new(4, 1, 1, 1)
    );
    options.set_force_cache_materialization_costs(costs);
    assert_eq!(options.force_cache_materialization_costs(), costs);

    let options = TreeWalkOptions::with_force_cache_materialization_costs(costs);
    assert_eq!(options.force_cache_materialization_costs(), costs);
}

#[test]
fn unary_type_predicate_primops_classify_whnf_values() {
    assert_eq!(eval("builtins.isAttrs { a = 1; }").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isAttrs [ 1 ]").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isList [ 1 ]").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFunction (x: x)").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.isFunction builtins.length").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction (builtins.map (x: x))").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isString \"x\"").as_bool(), Ok(true));
    let ir = lower("builtins.isString \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("isString argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"x".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");
    assert_eq!(
        evaluator
            .eval_strict_unary_primop_value(
                ir.root,
                root.span,
                StrictUnaryPrimOp::IsString,
                argument,
                argument_span,
                value,
            )
            .expect("isString evaluates context-bearing strings")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isInt 1").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isInt 1.0").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isFloat 1.0").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFloat 1").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isBool false").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isNull null").as_bool(), Ok(true));
    assert_eq!(eval("isNull null").as_bool(), Ok(true));
    assert_eq!(
        eval("let isNull = x: false; in isNull null").as_bool(),
        Ok(false)
    );
    assert_eq!(eval("builtins.isPath /tmp").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isPath \"not-path\"").as_bool(), Ok(false));
}

#[test]
fn type_of_primop_returns_nix_type_names() {
    assert_eq!(eval_string_bytes("builtins.typeOf 1"), b"int");
    assert_eq!(eval_string_bytes("builtins.typeOf 1.0"), b"float");
    assert_eq!(eval_string_bytes("builtins.typeOf false"), b"bool");
    assert_eq!(eval_string_bytes("builtins.typeOf null"), b"null");
    assert_eq!(eval_string_bytes("builtins.typeOf \"x\""), b"string");
    assert_eq!(eval_string_bytes("builtins.typeOf /tmp"), b"path");
    assert_eq!(eval_string_bytes("builtins.typeOf [ 1 ]"), b"list");
    assert_eq!(eval_string_bytes("builtins.typeOf { a = 1; }"), b"set");
    assert_eq!(eval_string_bytes("builtins.typeOf (x: x)"), b"lambda");
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.length"),
        b"lambda"
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf (builtins.map (x: x))"),
        b"lambda"
    );
}

#[test]
fn builtin_lookup_uses_shared_declaration_registry() {
    let builtin_names = BUILTINS.iter().map(Builtin::name).collect::<BTreeSet<_>>();

    assert_eq!(builtin_names.len(), BUILTINS.len());
    for builtin in BUILTINS.iter().copied() {
        assert_eq!(lookup_builtin(builtin.name()), Some(builtin));
    }
}

#[test]
fn direct_builtin_arity_uses_direct_metadata_not_first_class_metadata() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"__testBuiltin").expect("symbol interns");
    let call = BuiltinCall::new(IrId::new(0), Span::new(0, 13), symbol);
    let builtin = Builtin::test_with_call_arities(
        Some(BuiltinDirect::LazyUnary {
            effect: BuiltinEffect::Pure,
        }),
        Some(3),
    );

    check_builtin_direct_arity(call, builtin, 1).expect("direct arity uses direct metadata");

    let error = check_builtin_direct_arity(call, builtin, 3)
        .expect_err("direct arity ignores first-class arity");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidPrimOpArity {
            id: call.id,
            symbol: call.symbol,
            expected: 1,
            actual: 3,
        }
    );
}

#[test]
fn builtin_surface_matches_pinned_flakes_golden_fixture() {
    let fixture = pinned_builtin_name_bytes();
    assert_eq!(fixture.len(), BUILTINS.len());
    assert!(fixture.windows(2).all(|pair| pair[0] < pair[1]));

    let registry_names = BUILTINS
        .iter()
        .map(|builtin| builtin.name().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(registry_names, fixture);

    let mut options =
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec()).expect("system valid");
    options.set_current_time(1_700_000_000).expect("time valid");

    assert_eq!(
        eval_list_string_bytes_with_options("builtins.attrNames builtins", options.clone()),
        fixture,
    );
    assert_eq!(
        eval_list_string_bytes_with_options(
            "builtins.attrNames builtins.builtins",
            options.clone()
        ),
        fixture,
    );

    let outcome =
        eval_whnf_owned_with_options(&lower("builtins"), options).expect("builtins evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("builtins metadata exists");
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

/// End-to-end wiring for the captured-environment apply-count probe (RFC-0007
/// §P1 env-flatten lever): with stats collection enabled, evaluating an
/// expression that applies a lambda several times records at least that many
/// installs against the probe.
///
/// The probe is a process-wide cumulative counter, so this asserts a lower
/// bound on the install delta rather than an absolute total — concurrent tests
/// can only inflate it.
#[test]
fn env_apply_probe_records_installs_under_stats_dump() {
    use crate::eval::env::env_apply_histogram;

    let before = env_apply_histogram().map_or(0, |histogram| histogram.installs);

    let mut options = TreeWalkOptions::new();
    options.set_eval_stats_dump(true);
    // `f` captures the enclosing `let` frame and is applied three times, so a
    // correctly wired probe records at least three installs of that captured
    // environment.
    let bytes =
        eval_string_bytes_with_options(r#"let f = x: x; in "${f "a"}${f "b"}${f "c"}""#, options);
    assert_eq!(bytes, b"abc");

    let after = env_apply_histogram().expect("probe recorded installs under stats dump");
    assert!(
        after.installs >= before + 3,
        "expected at least 3 new installs, before={before} after={}",
        after.installs,
    );
}
