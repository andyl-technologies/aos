//! Split-out tests (part_11). See parent module.

use super::*;
#[cfg(feature = "candidate_c_value")]
use std::panic::{AssertUnwindSafe, catch_unwind};

#[cfg(feature = "candidate_c_value")]
use crate::eval::heap::{EvalHeapSnapshotError, EvalRootSource};

#[test]
fn typed_apply_heads_force_reforce_and_release_work() {
    let ir = lower(
        "let ys = builtins.map (x: x + 1) [ 1 ]; \
         y = builtins.elemAt ys 0; in y + y",
    );
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator.eval_root().expect("typed-head source evaluates");

    assert_eq!(value.as_int(), Ok(4));
    let (heads, live, peak_live, _, _) = evaluator.heap.typed_thunk_head_counts();
    assert!(heads > 0, "ordinary Apply thunks use typed heads");
    assert_eq!(live, 0, "successful forces release suspended work");
    assert!(peak_live > 0, "work pool observes live suspended work");
    assert!(
        evaluator.active_typed_thunk_work_leases.is_empty(),
        "successful force releases its detached-work lease"
    );
}

#[test]
fn typed_node_work_pool_matches_baseline_and_releases_shape_payload() {
    let source = "let x = 20 + 1; y = x + x; in y + y";
    let baseline_ir = lower(source);
    let baseline = TreeWalk::new(&baseline_ir)
        .eval_root()
        .expect("baseline Node thunks evaluate");

    let typed_ir = lower(source);
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&typed_ir, options);
    let typed = evaluator
        .eval_root()
        .expect("shape-sized Node thunks evaluate");

    assert!(typed.raw_eq(baseline));
    assert_eq!(typed.as_int(), Ok(84));
    let (node_live, node_slots, _, _) = evaluator.heap.typed_thunk_work_shape_counts();
    assert_eq!(
        node_live, 0,
        "successful Node forces release their payloads"
    );
    assert!(
        node_slots > 0,
        "ordinary Node work used the shape-sized pool"
    );
}

#[test]
fn typed_heads_preserve_dynamic_scope_capture_via_general_pool() {
    let source = "with { n = 40; }; let x = n + 2; in x + x";
    let baseline_ir = lower(source);
    let baseline = TreeWalk::new(&baseline_ir)
        .eval_root()
        .expect("baseline dynamic capture evaluates");

    let typed_ir = lower(source);
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&typed_ir, options);
    let typed = evaluator
        .eval_root()
        .expect("shape-sized dynamic capture evaluates");

    assert!(typed.raw_eq(baseline));
    assert_eq!(typed.as_int(), Ok(84));
    assert!(
        evaluator.heap.typed_thunk_work_shape_counts().3 > 0,
        "dynamic-scope Node work stays in the full general pool"
    );
}

#[test]
fn typed_apply_heads_admit_the_layout_identical_genlist_marker() {
    let ir = lower(
        "let xs = [ 10 20 30 ]; \
         ys = builtins.genList (i: builtins.elemAt xs (i + 1)) 2; \
         in builtins.elemAt ys 0",
    );
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator
        .eval_root()
        .expect("typed genList marker evaluates");

    assert_eq!(value.as_int(), Ok(20));
    let (heads, live, peak_live, _, _) = evaluator.heap.typed_thunk_head_counts();
    assert!(
        heads >= 4,
        "generated markers and serial node work use stable heads"
    );
    assert!(
        live >= 1,
        "the unselected generated element stays suspended"
    );
    assert!(peak_live >= 2);
}

#[test]
fn typed_apply_heads_retain_work_after_force_error() {
    let ir = lower(
        "let ys = builtins.map (x: builtins.abort \"typed-head retry\") [ 1 ]; \
         in builtins.elemAt ys 0",
    );
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);

    evaluator
        .eval_root()
        .expect_err("failed force preserves suspended work for retry");

    let (heads, live, peak_live, _, _) = evaluator.heap.typed_thunk_head_counts();
    assert!(heads > 0, "ordinary Apply thunks use typed heads");
    assert!(live > 0, "failed publication does not recycle work");
    assert!(peak_live >= live);
    assert!(
        evaluator.active_typed_thunk_work_leases.is_empty(),
        "failed force restores and releases its detached-work lease"
    );
}

#[cfg(feature = "candidate_c_value")]
#[test]
#[allow(unsafe_code)]
fn claimed_typed_head_scans_detached_work_edges_from_evaluator_lease() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let retained = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"retained typed edge".to_vec()))
        .expect("retained string allocates");
    let typed = evaluator
        .alloc_apply_thunk(id, span, id, span, retained, id, retained)
        .expect("typed Apply head allocates");
    let holder = evaluator
        .heap
        .alloc_list(NixList::new(vec![typed]))
        .expect("ordinary rooted object can retain the typed head");
    let ptr = evaluator
        .heap
        .thunk_ptr(typed)
        .expect("typed thunk pointer resolves");
    let parts = evaluator
        .heap
        .typed_thunk_force_parts(ptr)
        .expect("typed force parts resolve")
        .expect("value uses a typed head");

    // SAFETY: `parts` originates from `evaluator.heap`, which remains alive
    // until the claim is dropped below.
    let crate::eval::heap::TypedThunkForceClaim::Claimed(guard) =
        (unsafe { parts.begin_force() }).expect("fresh typed head claims")
    else {
        panic!("fresh typed head cannot already be forced");
    };
    let handle = guard.handle();
    let work = evaluator
        .heap
        .take_typed_thunk_work(ptr, handle)
        .expect("claimed work detaches");
    evaluator
        .push_active_typed_thunk_work_lease(id, span, typed, ptr, handle, work)
        .map_err(|(error, _)| error)
        .expect("evaluator owns detached work");

    assert_eq!(
        evaluator.heap.typed_thunk_state_if_any(typed),
        Some(ThunkState::Blackhole)
    );
    let roots = evaluator
        .safepoint_root_set()
        .expect("blackholed head's detached work roots build");
    let detached: Vec<_> = roots
        .roots()
        .iter()
        .filter(|root| matches!(root.source(), EvalRootSource::DetachedTypedThunkWork { .. }))
        .collect();
    assert_eq!(detached.len(), 2, "Apply retains function and argument");
    assert!(detached.iter().all(|root| root.value().raw_eq(retained)));
    assert!(roots.roots().iter().any(|root| {
        matches!(
            root.source(),
            EvalRootSource::DetachedTypedThunkHead { depth: 0 }
        ) && root.value().raw_eq(typed)
    }));

    // Reach the same blackholed head through an ordinary object as well as its
    // special lease root. Previsiting the latter must make the former safe
    // without weakening unmatched-blackhole rejection.
    evaluator.active_force_roots.push(holder);
    let scan = evaluator
        .safepoint_heap_scan()
        .expect("detached roots make the claimed blackhole scan complete");
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(typed)),
        "the leased head itself is counted live"
    );
    evaluator
        .heap
        .weak_liveness_census(&roots)
        .expect("weak scanner accepts the matching detached-work lease");
    evaluator.active_force_roots.pop();

    let work = evaluator
        .pop_active_typed_thunk_work_lease(id, span, typed, ptr, handle)
        .expect("matching detached-work lease pops");
    evaluator
        .heap
        .restore_typed_thunk_work(ptr, handle, work)
        .expect("detached work restores");
    drop(guard);
    assert_eq!(
        evaluator.heap.typed_thunk_state_if_any(typed),
        Some(ThunkState::Suspended)
    );
    assert!(evaluator.active_typed_thunk_work_leases.is_empty());
}

#[cfg(feature = "candidate_c_value")]
#[test]
#[allow(unsafe_code)]
fn unmatched_typed_blackhole_still_rejects_precise_and_weak_scans() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let typed = evaluator
        .alloc_apply_thunk(id, span, id, span, Value::int(1), id, Value::int(2))
        .expect("typed Apply head allocates");
    let ptr = evaluator
        .heap
        .thunk_ptr(typed)
        .expect("typed thunk pointer resolves");
    let parts = evaluator
        .heap
        .typed_thunk_force_parts(ptr)
        .expect("typed force parts resolve")
        .expect("value uses a typed head");
    // SAFETY: `parts` originates from the live evaluator heap and the claim is
    // dropped before the evaluator.
    let crate::eval::heap::TypedThunkForceClaim::Claimed(guard) =
        (unsafe { parts.begin_force() }).expect("fresh typed head claims")
    else {
        panic!("fresh typed head cannot already be forced");
    };
    let handle = guard.handle();
    let work = evaluator
        .heap
        .take_typed_thunk_work(ptr, handle)
        .expect("claimed work detaches");
    let roots = evaluator
        .safepoint_root_set_with_value_stack([typed])
        .expect("ordinary root set builds");

    assert!(matches!(
        evaluator.heap.scan_precise_roots(&roots),
        Err(EvalHeapError::ShedRejected { .. })
    ));
    assert!(matches!(
        evaluator.heap.weak_liveness_census(&roots),
        Err(EvalHeapError::ShedRejected { .. })
    ));

    evaluator
        .heap
        .restore_typed_thunk_work(ptr, handle, work)
        .expect("unmatched test work restores");
    drop(guard);
}

#[cfg(feature = "candidate_c_value")]
#[test]
fn typed_apply_head_panic_restores_work_and_clears_evaluator_lease() {
    let ir = lower(
        "let ys = builtins.map (x: x + 1) [ 1 ]; \
         in builtins.elemAt ys 0",
    );
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.panic_typed_thunk_body_once = true;

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = evaluator.eval_root();
    }));

    assert!(panic.is_err(), "test hook injects a typed-body panic");
    assert!(
        evaluator.active_typed_thunk_work_leases.is_empty(),
        "panic cleanup removes evaluator-owned detached work"
    );
    let (heads, live, _, _, _) = evaluator.heap.typed_thunk_head_counts();
    assert!(heads > 0, "the injected force used a typed head");
    assert!(live > 0, "panic cleanup restores suspended work");
    let value = evaluator
        .eval_root()
        .expect("restored typed work can be evaluated again");
    assert_eq!(value.as_int(), Ok(2));
}

#[test]
fn typed_apply_heads_fall_back_when_stats_are_enabled() {
    let ir = lower(
        "let ys = builtins.map (x: x + 1) [ 1 ]; \
         in builtins.elemAt ys 0",
    );
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    options.set_eval_stats_dump(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);

    let value = evaluator
        .eval_root()
        .expect("incompatible options retain ordinary closures");

    assert_eq!(value.as_int(), Ok(2));
    assert_eq!(evaluator.heap.typed_thunk_head_counts().0, 0);
}

#[test]
#[cfg(feature = "candidate_c_value")]
fn typed_apply_heads_explicitly_refuse_regions_and_snapshots() {
    let ir = lower(
        "let ys = builtins.map (x: x + 1) [ 1 ]; \
         in builtins.elemAt ys 0",
    );
    let mut options = TreeWalkOptions::new();
    options.set_typed_apply_thunk_heads_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);

    assert!(matches!(
        evaluator.heap.worker_region_mark(),
        Err(EvalHeapError::TypedThunkHeadsRegionUnsupported)
    ));
    evaluator
        .eval_root()
        .expect("typed-head source evaluates before snapshot refusal");
    assert!(matches!(
        evaluator.heap.capture_heap_image(),
        Err(EvalHeapSnapshotError::UnsnapshottableTypedThunkHeads { count })
            if count > 0
    ));
}

#[test]
fn detailed_heap_dereference_counters_are_opt_in() {
    let ir = lower(r#"let xs = [ "a" "b" ]; in builtins.elemAt xs 1"#);
    let mut evaluator = TreeWalk::new(&ir);
    evaluator.eval_root().expect("source evaluates");

    let campaign = evaluator.stats().campaign().clone();
    assert_eq!(campaign.record_probes_total(), 0);
    assert_eq!(campaign.flat_string_resolutions, 0);
    assert_eq!(campaign.flat_list_resolutions, 0);
    assert_eq!(campaign.flat_thunk_resolutions, 0);
}

#[test]
fn detailed_heap_dereference_counters_record_under_stats_dump() {
    let ir = lower(r#"let xs = [ "a" "b" ]; in builtins.elemAt xs 1"#);
    let mut options = TreeWalkOptions::new();
    options.set_eval_stats_dump(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.eval_root().expect("source evaluates");

    let campaign = evaluator.stats().campaign().clone();
    assert!(
        campaign.flat_string_resolutions
            + campaign.flat_list_resolutions
            + campaign.flat_thunk_resolutions
            > 0,
        "stats-dump evaluation records flat heap resolutions",
    );
}

#[test]
fn genlist_selected_child_census_classifies_scalar_node_and_apply_values() {
    let scalar_ir = lower("null");
    let mut scalar_eval = TreeWalk::new(&scalar_ir);
    let scalar = scalar_eval.genlist_selected_child_descriptor(Value::int(7));
    assert_eq!(scalar.runtime_kind, "int");
    assert_eq!(scalar.thunk_kind, "not-thunk");
    assert_eq!(scalar.thunk_state, "not-thunk");
    assert_eq!(scalar.body, "not-node");
    assert!(scalar.apply.is_none());

    let node_ir = lower("[ (1 + 2) ]");
    let mut node_eval = TreeWalk::new(&node_ir);
    let node_list = node_eval
        .eval_node(node_ir.root)
        .expect("lazy arithmetic list evaluates");
    let node_value = node_eval
        .heap()
        .get_list(node_list)
        .expect("root is a list")
        .get(0)
        .expect("list has one element");
    let node = node_eval.genlist_selected_child_descriptor(node_value);
    assert_eq!(node.runtime_kind, "thunk");
    assert_eq!(node.thunk_kind, "node");
    assert_eq!(node.thunk_state, "suspended");
    assert_eq!(node.body, "BinOp:Add");
    assert!(node.apply.is_none());

    let apply_ir = lower("builtins.map (x: x + 1) [ 1 ]");
    let mut apply_eval = TreeWalk::new(&apply_ir);
    let apply_list = apply_eval
        .eval_node(apply_ir.root)
        .expect("lazy mapped list evaluates");
    let apply_value = apply_eval
        .heap()
        .get_list(apply_list)
        .expect("map returns a list")
        .get(0)
        .expect("mapped list has one element");
    let apply = apply_eval.genlist_selected_child_descriptor(apply_value);
    assert_eq!(apply.runtime_kind, "thunk");
    assert_eq!(apply.thunk_kind, "apply");
    assert_eq!(apply.thunk_state, "suspended");
    assert_eq!(apply.body, "not-node");
    let signature = apply.apply.expect("Apply child carries an Apply signature");
    assert_eq!(signature.callee, "lambda");
    assert_eq!(signature.pattern, "simple-formal");
    assert_eq!(signature.body, "BinOp:Add");
    let selected = apply
        .selected_apply
        .expect("Apply child carries reducer-oriented detail");
    assert_eq!(selected.callee_kind, "lambda");
    assert_eq!(selected.lambda_module, "root");
    assert_eq!(selected.lexical_frames, 0);
    assert_eq!(selected.with_scopes, 0);
    assert_eq!(selected.scoped_globals, 0);
    assert_eq!(selected.body.root_kind, "BinOp:Add");
    assert_eq!(selected.body.grammar, "supported");
    assert_ne!(selected.body.features & (1 << 0), 0, "literal observed");
    assert_ne!(
        selected.body.features & (1 << 1),
        0,
        "lexical read observed"
    );
    assert_ne!(selected.body.features & (1 << 8), 0, "operator observed");
}

#[test]
fn genlist_selected_child_census_summarizes_reducer_grammar_and_captures() {
    let ir = lower(
        "let captured = 7; in builtins.map \
         (x: let bundle = { item = [ x captured ]; }; \
         in builtins.elemAt bundle.item 0) [ 1 ]",
    );
    let mut evaluator = TreeWalk::new(&ir);
    let list = evaluator
        .eval_node(ir.root)
        .expect("lazy mapped list evaluates");
    let value = evaluator
        .heap()
        .get_list(list)
        .expect("map returns a list")
        .get(0)
        .expect("mapped list has one element");
    let descriptor = evaluator.genlist_selected_child_descriptor(value);
    let selected = descriptor
        .selected_apply
        .expect("mapped Apply child carries reducer-oriented detail");

    assert_eq!(selected.callee_kind, "lambda");
    assert_eq!(selected.lambda_module, "root");
    assert_eq!(selected.lexical_frames, 1);
    assert_eq!(selected.body.root_kind, "Let");
    assert_eq!(selected.body.grammar, "supported");
    for (bit, family) in [
        (1 << 0, "literal"),
        (1 << 1, "lexical"),
        (1 << 2, "select"),
        (1 << 3, "primop"),
        (1 << 5, "let"),
        (1 << 6, "attrs"),
        (1 << 7, "list"),
        (1 << 9, "thunk"),
    ] {
        assert_ne!(selected.body.features & bit, 0, "{family} family observed");
    }
}

#[test]
fn genlist_selected_child_census_is_a_default_no_op() {
    use crate::eval::tree_walk::force_shape_census::recorded_genlist_selected_children;

    let ir = lower("null");
    let mut options = TreeWalkOptions::new();
    options.set_genlist_selected_child_census_enabled(true);
    assert!(
        !options.genlist_selected_child_census_enabled(),
        "the child-census knob alone cannot enable non-stats instrumentation"
    );
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let descriptor = evaluator.genlist_selected_child_descriptor(Value::int(91));
    let before = recorded_genlist_selected_children(descriptor);

    evaluator.record_genlist_selected_child_if_enabled(Value::int(91));

    assert_eq!(recorded_genlist_selected_children(descriptor), before);
}

#[test]
fn stg_session_is_default_off_and_explicitly_enabled() {
    let mut options = TreeWalkOptions::new();
    assert!(!options.stg_session_enabled());
    options.set_stg_session_enabled(true);
    assert!(options.stg_session_enabled());
}

#[test]
fn genlist_selected_child_census_records_the_pre_force_child() {
    use crate::eval::tree_walk::force_shape_census::recorded_genlist_suspended_child_samples;

    let ir = lower(
        "let xs = builtins.map (x: x + 1) [ 10 20 ]; generated = builtins.genList (i: builtins.elemAt xs (i + 1)) 1; in builtins.elemAt generated 0",
    );
    let mut options = TreeWalkOptions::new();
    options.set_eval_stats_dump(true);
    options.set_genlist_selected_child_census_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let observed = recorded_genlist_suspended_child_samples;
    let before = observed();
    let value = evaluator.eval_root().expect("evaluation succeeds");
    assert_eq!(value.as_int(), Ok(21));
    assert!(observed() > before, "selected child records before forcing");
}

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

    let normalize_process_wide_env_counters = |stats: &EvalStats| {
        let mut stats = *stats;
        stats.campaign.env_captures = 0;
        stats.campaign.env_capture_frame_handles = 0;
        stats.campaign.flat_env_captures = 0;
        stats.campaign.flat_env_capture_values = 0;
        stats.campaign.with_env_captures = 0;
        stats.campaign.with_env_capture_scopes = 0;
        stats.campaign.scoped_global_env_captures = 0;
        stats.campaign.scoped_global_env_capture_scopes = 0;
        stats.campaign.env_frame_allocs = 0;
        stats.campaign.env_frame_slot_bytes = 0;
        stats.campaign.env_frames_recyclable = 0;
        stats
    };
    assert_eq!(
        normalize_process_wide_env_counters(outcome.stats()),
        normalize_process_wide_env_counters(default_outcome.stats()),
    );
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

/// The MEMO-2 package-boundary probe records a formal-set-pattern application
/// and inspects its argument members only when stats collection is active.
///
/// Cumulative process statics mean the assertion is a lower bound on the delta
/// rather than an absolute total — concurrent tests can only inflate it.
#[test]
fn pkg_boundary_probe_records_formal_set_application_under_stats_dump() {
    use crate::eval::tree_walk::pkg_boundary_probe::pkg_boundary_report;

    let before = pkg_boundary_report();
    let before_apps = before.map_or(0, |report| report.applications);
    let before_members = before.map_or(0, |report| report.arg_members);

    let mut options = TreeWalkOptions::new();
    options.set_eval_stats_dump(true);
    // `f` is a formal-set-pattern (`callPackage`-shaped) lambda applied to a
    // two-member attrset, so a correctly wired probe records one boundary
    // application and inspects both argument members.
    let bytes = eval_string_bytes_with_options(
        r#"let f = { a, b }: "${a}${b}"; in f { a = "x"; b = "y"; }"#,
        options,
    );
    assert_eq!(bytes, b"xy");

    let after = pkg_boundary_report().expect("probe recorded a boundary under stats dump");
    assert!(
        after.applications >= before_apps + 1,
        "expected at least one new boundary application, before={before_apps} after={}",
        after.applications,
    );
    assert!(
        after.arg_members >= before_members + 2,
        "expected at least two new argument members inspected, before={before_members} after={}",
        after.arg_members,
    );
}

/// MEMO-2 M2-record increment 2: applying a keyed package file's root formal-set
/// lambda is recognized as a package boundary when the boundary memo is enabled.
///
/// Cumulative process statics mean the assertion is a lower bound on the delta.
#[test]
fn boundary_admission_recognizes_a_keyed_package_application() {
    use crate::eval::tree_walk::BoundaryMemoOptions;
    use crate::eval::tree_walk::boundary_admission::recognized_applications;

    let root = std::fs::canonicalize(unique_temp_dir("boundary-admission"))
        .expect("temp directory canonicalizes");
    // A package file: a top-level formal-set lambda (the `callPackage` shape).
    std::fs::write(root.join("foo.nix"), b"{ mkDerivation }: mkDerivation")
        .expect("package file writes");

    let before = recognized_applications();

    let mut options = TreeWalkOptions::new();
    options.set_boundary_memo(BoundaryMemoOptions {
        enabled: true,
        pkgs_root: Some(root.clone()),
        framework_roots: Vec::new(),
    });
    // Import the package file and apply its root formal-set lambda.
    let expr = format!(
        "import {}/foo.nix {{ mkDerivation = \"ok\"; }}",
        root.display()
    );
    let bytes = eval_string_bytes_with_options(&expr, options);
    assert_eq!(bytes, b"ok");

    assert!(
        recognized_applications() >= before + 1,
        "the keyed package application is recognized, before={before} after={}",
        recognized_applications(),
    );
}

/// The force-shape census classifies forced *thunk* bodies into their IR shape
/// classes only when stats collection is active.
///
/// A lazily-bound `let` binding whose body is a `//` update-merge is forced as
/// one `BinOp:Update` thunk (its inline attrset operands fold into that force's
/// self-time rather than being separately forced — the census measures the
/// forced-thunk population, not every evaluated node). The strict `+` arg is a
/// `BinOp:Add` force. Cumulative process statics mean each assertion is a lower
/// bound on the delta — concurrent tests can only inflate it.
#[test]
fn force_shape_census_classifies_forced_body_shapes_under_stats_dump() {
    use crate::eval::tree_walk::force_shape_census::{
        recorded_allocations, recorded_forces, recorded_work_releases,
    };

    let before_update_allocations = recorded_allocations("BinOp:Update");
    let before_add_allocations = recorded_allocations("BinOp:Add");
    let before_update = recorded_forces("BinOp:Update");
    let before_add = recorded_forces("BinOp:Add");
    let before_work_releases = recorded_work_releases();

    let mut options = TreeWalkOptions::new();
    options.set_eval_stats_dump(true);
    // `m` is a lazily-bound `BinOp:Update` thunk; `m.x + m.y` forces a
    // `BinOp:Add` whose `Select` operands evaluate inline within it.
    let bytes = eval_string_bytes_with_options(
        r#"let m = { x = 1; } // { y = 2; }; in toString (m.x + m.y)"#,
        options,
    );
    assert_eq!(bytes, b"3");

    assert!(
        recorded_allocations("BinOp:Update") > before_update_allocations,
        "expected a new BinOp:Update thunk allocation to be classified",
    );
    assert!(
        recorded_allocations("BinOp:Add") > before_add_allocations,
        "expected a new BinOp:Add thunk allocation to be classified",
    );
    assert!(
        recorded_forces("BinOp:Update") > before_update,
        "expected a new BinOp:Update thunk force to be classified",
    );
    assert!(
        recorded_forces("BinOp:Add") > before_add,
        "expected a new BinOp:Add thunk force to be classified",
    );
    assert!(
        recorded_work_releases() > before_work_releases,
        "expected a forced thunk to release its hypothetical suspended work",
    );
}
