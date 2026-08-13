//! Evaluator-owned simple lambda-call lease lifecycle tests.

use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn fixture(source: &str) -> (TreeWalk, IrId, Span, Value) {
    let ir = lower(source);
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let function = evaluator.eval_node(id).expect("lambda evaluates");
    assert_eq!(function.tag(), ValueTag::Lambda);
    (evaluator, id, span, function)
}

fn begin(
    evaluator: &mut TreeWalk,
    id: IrId,
    span: Span,
    function: Value,
    argument: Value,
) -> LambdaCallWork {
    match evaluator
        .begin_lambda_call_lease(id, span, id, function, span, id, span, argument)
        .expect("lambda-call lease begins")
    {
        BeginLambdaCallLease::Ready(work) => work,
        BeginLambdaCallLease::Declined => panic!("simple-formal lambda is admitted"),
    }
}

fn assert_declines_without_call_mutation(
    evaluator: &mut TreeWalk,
    id: IrId,
    span: Span,
    function: Value,
) {
    let function_calls_before = evaluator.stats_snapshot().function_calls();
    assert!(matches!(
        evaluator
            .begin_lambda_call_lease(id, span, id, function, span, id, span, Value::null())
            .expect("unsupported mode declines"),
        BeginLambdaCallLease::Declined
    ));
    assert_eq!(
        evaluator.stats_snapshot().function_calls(),
        function_calls_before
    );
    assert_eq!(evaluator.call_depth, 0);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn lambda_call_lease_success_runs_body_and_restores_context() {
    let (mut evaluator, id, span, function) = fixture("x: x");
    let work = begin(&mut evaluator, id, span, function, Value::int(42));

    assert_eq!(evaluator.current_module, work.module);
    assert_eq!(evaluator.call_depth, 1);
    assert_eq!(evaluator.suspended_env_roots.len(), 1);
    assert_eq!(evaluator.active_lambda_call_leases.len(), 1);

    let value = evaluator
        .run_lambda_call_lease_with(work, |eval, work| eval.eval_node(work.body))
        .expect("body evaluates");
    assert!(value.raw_eq(Value::int(42)));
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert_eq!(evaluator.call_depth, 0);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
    assert_eq!(evaluator.stats_snapshot().function_calls(), 1);
}

#[test]
fn lambda_call_lease_body_error_restores_context() {
    let (mut evaluator, id, span, function) = fixture("x: 1 / 0");
    let work = begin(&mut evaluator, id, span, function, Value::null());

    let error = evaluator
        .run_lambda_call_lease_with(work, |eval, work| eval.eval_node(work.body))
        .expect_err("division-by-zero body fails");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert_eq!(evaluator.call_depth, 0);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
    assert_eq!(evaluator.stats_snapshot().function_calls(), 1);
}

#[test]
fn lambda_call_lease_injected_panic_restores_before_unwind() {
    let (mut evaluator, id, span, function) = fixture("x: x");
    let work = begin(&mut evaluator, id, span, function, Value::int(1));

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ =
            evaluator.run_lambda_call_lease_with(work, |_, _| panic!("injected lambda body panic"));
    }));
    assert!(panic.is_err());
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert_eq!(evaluator.call_depth, 0);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn lambda_call_lease_rejects_stale_same_depth_token() {
    let (mut evaluator, id, span, function) = fixture("x: x");
    let stale = begin(&mut evaluator, id, span, function, Value::int(1));
    evaluator
        .finish_lambda_call_lease(stale.token, Ok(Value::int(1)))
        .expect("first call finishes");
    let active = begin(&mut evaluator, id, span, function, Value::int(2));

    assert_eq!(stale.token.depth(), active.token.depth());
    assert_ne!(stale.token.generation(), active.token.generation());
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = evaluator.finish_lambda_call_lease(stale.token, Ok(Value::int(1)));
    }));
    assert!(panic.is_err());
    assert_eq!(evaluator.active_lambda_call_leases.len(), 1);
    assert_eq!(evaluator.call_depth, 1);

    evaluator
        .finish_lambda_call_lease(active.token, Ok(Value::int(2)))
        .expect("active call still finishes");
}

#[test]
fn lambda_call_generation_exhaustion_precedes_observable_mutation() {
    let (mut evaluator, id, span, function) = fixture("x: x");
    evaluator.next_lambda_call_lease_generation = u64::MAX;
    let function_calls_before = evaluator.stats_snapshot().function_calls();

    let error = evaluator
        .begin_lambda_call_lease(id, span, id, function, span, id, span, Value::int(1))
        .expect_err("generation exhaustion rejects the call");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::LambdaCallLeaseGenerationExhausted { .. }
    ));
    assert_eq!(
        evaluator.stats_snapshot().function_calls(),
        function_calls_before
    );
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert_eq!(evaluator.call_depth, 0);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn nested_cross_module_lambda_call_leases_restore_each_caller() {
    let (mut evaluator, id, span, root_function) = fixture("x: x");
    let imported_ir = lower("y: y");
    let imported = evaluator
        .begin_import_module(
            id,
            span,
            b"/lambda-call-lease-import.nix",
            b"/",
            b"y: y",
            imported_ir,
            ImportGlobalScope::Fresh,
        )
        .expect("imported module begins");
    let imported_function = evaluator
        .run_import_module_with(imported, |eval, work| eval.eval_node(work.root))
        .expect("imported lambda evaluates");

    let outer = begin(&mut evaluator, id, span, imported_function, Value::int(1));
    assert_ne!(outer.module, EvalModuleId::ROOT);
    let imported_module = outer.module;
    assert_eq!(evaluator.current_module, imported_module);
    let inner = begin(&mut evaluator, id, span, root_function, Value::int(2));
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert_eq!(evaluator.call_depth, 2);

    evaluator
        .finish_lambda_call_lease(inner.token, Ok(Value::int(2)))
        .expect("inner call finishes");
    assert_eq!(evaluator.current_module, imported_module);
    assert_eq!(evaluator.call_depth, 1);
    evaluator
        .finish_lambda_call_lease(outer.token, Ok(Value::int(1)))
        .expect("outer call finishes");
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert_eq!(evaluator.call_depth, 0);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn ignored_bad_lambda_argument_remains_lazy() {
    let (mut evaluator, id, span, function) = fixture("x: 42");
    let invalid = IrId::new(u32::MAX);
    let argument = evaluator
        .alloc_tree_walk_thunk(id, span, EvalThunk::new(invalid))
        .expect("bad lazy argument allocates");
    let work = begin(&mut evaluator, id, span, function, argument);

    let value = evaluator
        .run_lambda_call_lease_with(work, |eval, work| eval.eval_node(work.body))
        .expect("ignored argument is not forced");
    assert!(value.raw_eq(Value::int(42)));
    assert_eq!(
        evaluator
            .heap
            .get_thunk(argument)
            .expect("argument thunk resolves")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );
    let error = evaluator
        .force_value(id, span, argument)
        .expect_err("forcing the ignored argument proves it is bad");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidNodeId { .. }
    ));
}

#[test]
fn lambda_call_lease_preserves_displaced_lexical_and_dynamic_context() {
    let (mut evaluator, id, span, function) = fixture("x: x");
    let displaced_frame = EvalFrame::new(1).expect("displaced frame allocates");
    displaced_frame
        .set(0, Value::int(7))
        .expect("displaced frame initializes");
    evaluator.push_env_frame(displaced_frame);
    evaluator
        .with_scopes
        .push(EvalWithScope::new(EvalModuleId::ROOT, id, Value::int(8)));
    evaluator.scoped_globals.push(Value::int(9));

    let work = begin(&mut evaluator, id, span, function, Value::int(42));
    let value = evaluator
        .run_lambda_call_lease_with(work, |eval, work| eval.eval_node(work.body))
        .expect("body evaluates");

    assert!(value.raw_eq(Value::int(42)));
    assert_eq!(evaluator.active_env_frame_count(), 1);
    assert!(
        evaluator.env[0]
            .get(0)
            .expect("slot exists")
            .raw_eq(Value::int(7))
    );
    assert_eq!(evaluator.with_scopes.len(), 1);
    assert!(evaluator.with_scopes[0].value().raw_eq(Value::int(8)));
    assert_eq!(evaluator.scoped_globals.len(), 1);
    assert!(evaluator.scoped_globals[0].raw_eq(Value::int(9)));
}

#[test]
fn lambda_call_depth_error_keeps_depth_balanced_and_counts_the_attempt() {
    let (mut evaluator, id, span, function) = fixture("x: x");
    evaluator.options.max_call_depth = 0;
    evaluator.call_depth = 1;

    let error = evaluator
        .begin_lambda_call_lease(id, span, id, function, span, id, span, Value::int(1))
        .expect_err("call depth diagnostic is preserved");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MaxCallDepthExceeded {
            depth: 1,
            max: 0,
            ..
        }
    ));
    assert_eq!(evaluator.stats_snapshot().function_calls(), 1);
    assert_eq!(evaluator.call_depth, 1);
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_lambda_call_leases.is_empty());
}

#[test]
fn unsupported_apply_modes_decline_before_call_mutation() {
    let formal_ir = lower("{ x }: x");
    let formal_id = formal_ir.root;
    let formal_span = formal_ir
        .arena
        .node(formal_id)
        .expect("formal-set root exists")
        .span;
    let mut formal_eval = TreeWalk::new(&formal_ir);
    let formal_function = formal_eval
        .eval_node(formal_id)
        .expect("formal-set lambda evaluates");
    assert_declines_without_call_mutation(
        &mut formal_eval,
        formal_id,
        formal_span,
        formal_function,
    );

    let (mut memo_eval, id, span, function) = fixture("x: x");
    memo_eval.force_cache_active = true;
    assert_declines_without_call_mutation(&mut memo_eval, id, span, function);
    memo_eval.force_cache_active = false;
    memo_eval.options.memo.enabled = true;
    assert_declines_without_call_mutation(&mut memo_eval, id, span, function);
    memo_eval.options.memo.enabled = false;
    memo_eval.options.boundary_memo.enabled = true;
    memo_eval.options.boundary_memo.pkgs_root = Some(PathBuf::from("/pkgs"));
    assert_declines_without_call_mutation(&mut memo_eval, id, span, function);
    memo_eval.options.boundary_memo.enabled = false;
    memo_eval.options.set_jit_tier1_publish_enabled(true);
    assert_declines_without_call_mutation(&mut memo_eval, id, span, function);

    let (mut non_lambda_eval, id, span, _) = fixture("x: x");
    assert_declines_without_call_mutation(&mut non_lambda_eval, id, span, Value::null());

    for (source, expected_tag) in [
        ("builtins.add", ValueTag::Primop),
        ("{ __functor = self: x: x; }", ValueTag::Attrs),
    ] {
        let ir = lower(source);
        let id = ir.root;
        let span = ir.arena.node(id).expect("root exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let function = evaluator
            .eval_node(id)
            .expect("function-like value evaluates");
        assert_eq!(function.tag(), expected_tag);
        assert_declines_without_call_mutation(&mut evaluator, id, span, function);
    }
}
