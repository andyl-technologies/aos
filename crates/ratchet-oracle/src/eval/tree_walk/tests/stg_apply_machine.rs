use super::*;

fn generic_apply(ir: &Ir, argument: Value) -> (TreeWalk, Value, IrId, Span) {
    let id = ir.root;
    let span = ir.arena.node(id).expect("root node exists").span;
    let mut options = TreeWalkOptions::new();
    options.set_stg_session_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let function = evaluator.eval_root().expect("lambda evaluates");
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, argument)
        .expect("ordinary Apply thunk allocates");
    (evaluator, apply, id, span)
}

fn static_attrs_argument(evaluator: &mut TreeWalk, name: &[u8], value: Value) -> Value {
    let symbol = evaluator
        .symbols
        .intern(name)
        .expect("attribute symbol interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(symbol, value)], &evaluator.symbols)
        .expect("flat attrs build");
    evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("flat attrs allocate")
}

fn empty_attrs_argument(evaluator: &mut TreeWalk) -> Value {
    let attrs = FlatAttrs::new(Vec::new(), &evaluator.symbols).expect("empty flat attrs build");
    evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("empty flat attrs allocate")
}

fn stg_evaluator(ir: &Ir) -> TreeWalk {
    let mut options = TreeWalkOptions::new();
    options.set_stg_session_enabled(true);
    TreeWalk::with_options(ir, options)
}

fn lambda_with_body(evaluator: &mut TreeWalk, ir: &Ir, body: IrId) -> Value {
    let root = ir.arena.node(ir.root).expect("lambda root exists");
    let IrData::Lambda {
        pattern,
        frame: Some(frame),
        ..
    } = root.data
    else {
        panic!("unary lambda root expected");
    };
    evaluator
        .heap
        .alloc_lambda(EvalLambda::new(pattern, body, frame, EvalEnv::default()))
        .expect("test lambda allocates")
}

#[test]
fn generic_stg_forces_an_ordinary_non_marker_apply() {
    let ir = lower("x: x - 1");
    let (mut evaluator, apply, id, span) = generic_apply(&ir, Value::int(4));

    let result = evaluator
        .force_value(id, span, apply)
        .expect("generic Apply evaluates");

    assert_eq!(result.as_int(), Ok(3));
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 1);
    assert_eq!(evaluator.stg_session_marker_claims, 0);
    assert_eq!(evaluator.stg_apply_runtime.counters.completions, 1);
    assert!(evaluator.stg_apply_runtime.is_idle());
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn generic_stg_admits_the_numeric_local_add_one_cohort() {
    let ir = lower("i: i + 1");
    let (mut evaluator, apply, id, span) = generic_apply(&ir, Value::int(41));

    let result = evaluator
        .force_value(id, span, apply)
        .expect("proven numeric Add evaluates");

    assert_eq!(result.as_int(), Ok(42));
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 1);
    assert!(evaluator.stg_apply_runtime.is_idle());
}

#[test]
fn generic_stg_elem_at_uses_the_exact_primop_helper() {
    let ir = lower("xs: builtins.elemAt xs 1");
    let (mut evaluator, apply, id, span) = generic_apply(&ir, Value::null());
    let list = evaluator
        .alloc_tree_walk_list(id, span, NixList::new(vec![Value::int(10), Value::int(20)]))
        .expect("list allocates");
    {
        let thunk = evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves");
        let EvalThunkKind::Apply { argument_value, .. } = thunk.kind() else {
            panic!("ordinary Apply payload remains available");
        };
        // The test fixture initially installs null only to allocate the list
        // through the same evaluator. Rebuild the Apply with the real argument.
        assert!(argument_value.raw_eq(Value::null()));
    }
    let function = evaluator.eval_root().expect("lambda reevaluates");
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, list)
        .expect("list Apply thunk allocates");

    let result = evaluator
        .force_value(id, span, apply)
        .expect("elemAt Apply evaluates");

    assert_eq!(result.as_int(), Ok(20));
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 1);
    assert!(evaluator.stg_apply_runtime.is_idle());
}

#[test]
fn generic_stg_runs_captured_elem_at_local_add_one_body() {
    let ir = lower("xs: i: builtins.elemAt xs (i + 1)");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut options = TreeWalkOptions::new();
    options.set_stg_session_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let outer = evaluator.eval_root().expect("outer lambda evaluates");
    let list = evaluator
        .alloc_tree_walk_list(id, span, NixList::new(vec![Value::int(10), Value::int(20)]))
        .expect("captured list allocates");
    let inner = evaluator
        .apply_lambda_value(id, span, id, outer, span, id, list)
        .expect("outer application creates the captured inner lambda");
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, inner, id, Value::int(0))
        .expect("ordinary inner Apply thunk allocates");

    let result = evaluator
        .force_value(id, span, apply)
        .expect("captured elemAt/add-one body evaluates");

    assert_eq!(result.as_int(), Ok(20));
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 1);
    assert_eq!(evaluator.stg_session_marker_claims, 0);
    assert!(evaluator.stg_apply_runtime.is_idle());
}

#[test]
fn generic_stg_select_matches_the_exact_static_select_helper() {
    let ir = lower("x: x.a");
    let (mut evaluator, first_apply, id, span) = generic_apply(&ir, Value::null());
    let attrs = static_attrs_argument(&mut evaluator, b"a", Value::int(42));
    let function = evaluator.eval_root().expect("lambda reevaluates");
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, attrs)
        .expect("select Apply thunk allocates");
    let function = evaluator.eval_root().expect("lambda reevaluates again");
    let second_apply = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, attrs)
        .expect("second select Apply thunk allocates");

    let result = evaluator
        .force_value(id, span, apply)
        .expect("static select evaluates");
    assert_eq!(evaluator.stats.inline_cache_misses(), 1);
    assert_eq!(evaluator.stats.inline_cache_hits(), 0);
    let second_result = evaluator
        .force_value(id, span, second_apply)
        .expect("cached static select evaluates");

    assert_eq!(result.as_int(), Ok(42));
    assert_eq!(second_result.as_int(), Ok(42));
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 2);
    assert_eq!(evaluator.stg_apply_runtime.counters.cache_hits, 1);
    assert_eq!(evaluator.stats.inline_cache_misses(), 1);
    assert_eq!(evaluator.stats.inline_cache_hits(), 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.blocks_with_select, 1);
    assert_eq!(
        evaluator
            .stg_apply_runtime
            .counters
            .disqualifier_bitmap_histogram[0],
        1
    );
    assert!(evaluator.stg_apply_runtime.is_idle());
    let _ = first_apply;
}

#[test]
fn generic_stg_select_forces_intermediate_attrsets_in_path_order() {
    let ir = lower("x: x.a.b");
    let (mut evaluator, first_apply, id, span) = generic_apply(&ir, Value::null());
    let inner = static_attrs_argument(&mut evaluator, b"b", Value::int(17));
    let root = ir.arena.node(ir.root).expect("lambda root exists");
    let IrData::Lambda { body, .. } = root.data else {
        panic!("lambda root expected");
    };
    let select = ir.arena.node(body).expect("select body exists");
    let IrData::Select { receiver, .. } = select.data else {
        panic!("select body expected");
    };
    let frame = EvalFrame::new(1).expect("receiver frame allocates");
    frame.set(0, inner).expect("receiver frame initializes");
    let env = EvalEnv::capture(&[frame]).expect("receiver environment captures");
    let suspended_inner = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, receiver, env))
        .expect("intermediate attrset thunk allocates");
    let outer = static_attrs_argument(&mut evaluator, b"a", suspended_inner);
    let function = evaluator.eval_root().expect("lambda reevaluates");
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, outer)
        .expect("nested-select Apply thunk allocates");

    let result = evaluator
        .force_value(id, span, apply)
        .expect("nested static select evaluates");

    assert_eq!(result.as_int(), Ok(17));
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 1);
    assert!(evaluator.stg_apply_runtime.is_idle());
    let _ = first_apply;
}

#[test]
fn generic_stg_select_preserves_nonattrs_type_error_and_unwinds() {
    let ir = lower("x: x.a");
    let (mut evaluator, apply, id, span) = generic_apply(&ir, Value::null());

    let stg_error = evaluator
        .force_value(id, span, apply)
        .expect_err("non-attr receiver preserves the select type error");
    let mut baseline_options = TreeWalkOptions::new();
    baseline_options.set_stg_session_enabled(false);
    let mut baseline = TreeWalk::with_options(&ir, baseline_options);
    let function = baseline.eval_root().expect("baseline lambda evaluates");
    let baseline_apply = baseline
        .alloc_apply_thunk(id, span, id, span, function, id, Value::null())
        .expect("baseline Apply thunk allocates");
    let baseline_error = baseline
        .force_value(id, span, baseline_apply)
        .expect_err("baseline preserves the select type error");

    assert_eq!(stg_error.kind(), baseline_error.kind());
    assert_eq!(stg_error.span(), baseline_error.span());
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.errors, 1);
    assert_eq!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    assert!(evaluator.stg_apply_runtime.is_idle());
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn generic_stg_select_preserves_missing_attribute_error_and_unwinds() {
    let ir = lower("x: x.a");
    let (mut evaluator, first_apply, id, span) = generic_apply(&ir, Value::null());
    let empty = empty_attrs_argument(&mut evaluator);
    let function = evaluator.eval_root().expect("lambda reevaluates");
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, empty)
        .expect("missing-select Apply thunk allocates");

    let error = evaluator
        .force_value(id, span, apply)
        .expect_err("missing attribute remains an error");

    let root = ir.arena.node(id).expect("lambda root exists");
    let IrData::Lambda { body, .. } = root.data else {
        panic!("lambda root expected");
    };
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { id: error_id, .. } if error_id == body
    ));
    assert_eq!(
        error.span(),
        ir.arena.node(body).expect("select body exists").span
    );
    assert_eq!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    assert_eq!(evaluator.stg_apply_runtime.counters.errors, 1);
    assert!(evaluator.stg_apply_runtime.is_idle());
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
    let _ = first_apply;
}

#[test]
fn generic_stg_select_forces_the_selected_suspended_value() {
    let ir = lower("x: x.a");
    let (mut evaluator, first_apply, id, span) = generic_apply(&ir, Value::null());
    let selected = evaluator
        .alloc_tree_walk_thunk(id, span, EvalThunk::new(IrId::new(u32::MAX)))
        .expect("selected suspended thunk allocates");
    let attrs = static_attrs_argument(&mut evaluator, b"a", selected);
    let function = evaluator.eval_root().expect("lambda reevaluates");
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, attrs)
        .expect("selected-thunk Apply allocates");

    evaluator
        .force_value(id, span, apply)
        .expect_err("forcing the selected suspended value preserves its error");

    assert_eq!(evaluator.stg_apply_runtime.counters.errors, 1);
    assert_eq!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    assert!(evaluator.stg_apply_runtime.is_idle());
    let _ = first_apply;
}

#[test]
fn unsupported_opcode_overlap_is_preflighted_once_and_negative_cached() {
    const LAMBDA_DISQUALIFIER: usize = 1 << 0;

    let ir = lower("x: (y: y) x");
    let (mut evaluator, first, id, span) = generic_apply(&ir, Value::int(1));
    let function = evaluator.eval_root().expect("lambda reevaluates");
    let second = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, Value::int(2))
        .expect("second Apply thunk allocates");

    let first_result = evaluator
        .force_value(id, span, first)
        .expect("first force declines to the oracle");
    let second_result = evaluator
        .force_value(id, span, second)
        .expect("second force uses the cached decline");

    assert_eq!(first_result.as_int(), Ok(1));
    assert_eq!(second_result.as_int(), Ok(2));
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 0);
    assert_eq!(evaluator.stg_apply_runtime.counters.blocks_lowered, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.cache_hits, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.negative_cache_hits, 1);
    assert_eq!(
        evaluator
            .stg_apply_runtime
            .counters
            .disqualifier_bitmap_histogram[LAMBDA_DISQUALIFIER],
        1
    );
}

#[test]
fn generic_stg_apply_keeps_an_unused_argument_lazy() {
    let ir = lower("f: f (1 / 0)");
    let id = ir.root;
    let span = ir.arena.node(id).expect("lambda root exists").span;
    let constant_body = ir
        .arena
        .nodes()
        .iter()
        .position(|node| matches!((node.kind, node.data), (IrKind::Int, IrData::Int(1))))
        .map(|index| IrId::new(index as u32))
        .expect("constant body exists");
    let mut evaluator = stg_evaluator(&ir);
    let outer = evaluator.eval_root().expect("outer lambda evaluates");
    let constant = lambda_with_body(&mut evaluator, &ir, constant_body);
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, outer, id, constant)
        .expect("outer Apply thunk allocates");

    let result = evaluator
        .force_value(id, span, apply)
        .expect("unused division argument stays lazy");

    assert_eq!(result.as_int(), Ok(1));
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.apply_continuations, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.thunk_continuations, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.errors, 0);
    assert!(evaluator.stg_apply_runtime.is_idle());
}

#[test]
fn generic_stg_apply_preserves_nested_lazy_application_and_publication() {
    let ir = lower("f: f (f 1)");
    let id = ir.root;
    let span = ir.arena.node(id).expect("lambda root exists").span;
    let root = ir.arena.node(id).expect("lambda root exists");
    let IrData::Lambda { body, .. } = root.data else {
        panic!("lambda root expected");
    };
    let outer_apply = ir.arena.node(body).expect("outer Apply exists");
    let IrData::Pair {
        first: identity_body,
        ..
    } = outer_apply.data
    else {
        panic!("outer Apply payload expected");
    };
    let mut evaluator = stg_evaluator(&ir);
    let outer = evaluator.eval_root().expect("outer lambda evaluates");
    let identity = lambda_with_body(&mut evaluator, &ir, identity_body);
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, outer, id, identity)
        .expect("outer Apply thunk allocates");

    let first = evaluator
        .force_value(id, span, apply)
        .expect("nested lazy applications evaluate");
    let second = evaluator
        .force_value(id, span, apply)
        .expect("published outer update is reused");

    assert_eq!(first.as_int(), Ok(1));
    assert_eq!(second.as_int(), Ok(1));
    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.completions, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.apply_continuations, 1);
    assert_eq!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Forced)
    );
    assert!(evaluator.stg_apply_runtime.is_idle());
}

#[test]
fn generic_stg_apply_error_matches_oracle_span_and_cleans_up() {
    let ir = lower("f: f (1 / 0)");
    let (mut evaluator, apply, id, span) = generic_apply(&ir, Value::int(7));
    let error = evaluator
        .force_value(id, span, apply)
        .expect_err("non-callable function remains a type error");

    let mut baseline = TreeWalk::new(&ir);
    let function = baseline.eval_root().expect("baseline lambda evaluates");
    let baseline_apply = baseline
        .alloc_apply_thunk(id, span, id, span, function, id, Value::int(7))
        .expect("baseline Apply thunk allocates");
    let baseline_error = baseline
        .force_value(id, span, baseline_apply)
        .expect_err("baseline non-callable remains a type error");

    assert_eq!(error.kind(), baseline_error.kind());
    assert_eq!(error.span(), baseline_error.span());
    assert_eq!(evaluator.stg_apply_runtime.counters.errors, 1);
    assert_eq!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    assert!(evaluator.stg_apply_runtime.is_idle());
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn generic_stg_nested_apply_panic_cleans_up_owned_leases() {
    let ir = lower("f: f 1");
    let id = ir.root;
    let span = ir.arena.node(id).expect("lambda root exists").span;
    let root = ir.arena.node(id).expect("lambda root exists");
    let IrData::Lambda { body, .. } = root.data else {
        panic!("lambda root expected");
    };
    let apply_node = ir.arena.node(body).expect("Apply body exists");
    let IrData::Pair {
        first: identity_body,
        ..
    } = apply_node.data
    else {
        panic!("Apply payload expected");
    };
    let mut evaluator = stg_evaluator(&ir);
    let outer = evaluator.eval_root().expect("outer lambda evaluates");
    let identity = lambda_with_body(&mut evaluator, &ir, identity_body);
    let apply = evaluator
        .alloc_apply_thunk(id, span, id, span, outer, id, identity)
        .expect("outer Apply thunk allocates");
    evaluator.stg_apply_runtime.panic_before_nested_apply = true;

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = evaluator.force_value(id, span, apply);
    }));

    assert!(panic.is_err());
    assert_eq!(evaluator.stg_apply_runtime.counters.panics, 1);
    assert_eq!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    assert!(evaluator.stg_apply_runtime.is_idle());
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn overloaded_add_exits_to_the_exact_oracle_after_claim() {
    let ir = lower("x: x + 1");
    let (mut evaluator, apply, id, span) = generic_apply(&ir, Value::bool(true));

    evaluator
        .force_value(id, span, apply)
        .expect_err("ordinary evaluator preserves the type error");

    assert_eq!(evaluator.stg_apply_runtime.counters.claims, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.oracle_leaves, 1);
    assert_eq!(evaluator.stg_apply_runtime.counters.errors, 1);
    assert!(evaluator.stg_apply_runtime.is_idle());
}

#[test]
fn generic_stg_error_aborts_force_and_call_stacks() {
    let ir = lower("x: x / 0");
    let (mut evaluator, apply, id, span) = generic_apply(&ir, Value::int(4));

    evaluator
        .force_value(id, span, apply)
        .expect_err("division by zero is preserved");

    assert_eq!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    assert_eq!(evaluator.stg_apply_runtime.counters.errors, 1);
    assert!(evaluator.stg_apply_runtime.is_idle());
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn generic_stg_panic_aborts_force_and_call_stacks() {
    let ir = lower("x: x.a");
    let (mut evaluator, apply, id, span) = generic_apply(&ir, Value::null());
    evaluator.stg_apply_runtime.panic_after_claim = true;

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = evaluator.force_value(id, span, apply);
    }));

    assert!(panic.is_err());
    assert_eq!(
        evaluator
            .heap
            .get_thunk(apply)
            .expect("Apply thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    assert_eq!(evaluator.stg_apply_runtime.counters.panics, 1);
    assert!(evaluator.stg_apply_runtime.is_idle());
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}
