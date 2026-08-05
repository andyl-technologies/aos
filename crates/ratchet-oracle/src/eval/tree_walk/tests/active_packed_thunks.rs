//! End-to-end tests for serial active packed Apply-shaped thunks.

use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn packed_options(capacity: usize) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::new();
    options.set_active_packed_thunk_capacities(ActivePackedThunkCapacities {
        heads: capacity.saturating_mul(2),
        apply: capacity,
        gen_list_elem_at_add_one: capacity,
    });
    options
}

#[test]
fn active_packed_apply_and_genlist_match_baseline_end_to_end() {
    let source = "let xs = [ 10 20 30 ]; \
                  ys = builtins.genList (i: builtins.elemAt xs (i + 1)) 2; \
                  f = x: x + 1; \
                  zs = builtins.map f [ 1 ]; \
                  in f (builtins.elemAt ys 0) + f (builtins.elemAt ys 1) \
                     + builtins.elemAt zs 0";
    let baseline_ir = lower(source);
    let baseline = TreeWalk::new(&baseline_ir)
        .eval_root()
        .expect("baseline evaluates");

    let packed_ir = lower(source);
    let mut packed = TreeWalk::with_options(&packed_ir, packed_options(128));
    let result = packed.eval_root().expect("packed evaluation succeeds");

    assert!(result.raw_eq(baseline));
    assert_eq!(result.as_int(), Ok(54));
    let accounting = packed.heap.active_packed_thunk_accounting();
    assert!(accounting.apply_allocated > 0);
    assert!(accounting.gen_list_elem_at_add_one_allocated > 0);
    assert!(accounting.initialized_bytes > 0);
    assert!(accounting.capacity_bytes >= accounting.initialized_bytes);
    assert!(accounting.virtual_reserved_bytes >= accounting.capacity_bytes);
}

#[test]
fn active_packed_capacity_exhaustion_fails_loudly_without_fallback() {
    let ir = lower("x: x + 1");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, packed_options(1));
    let function = evaluator.eval_root().expect("lambda evaluates");

    evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, Value::int(1))
        .expect("first packed Apply allocates");
    let error = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, Value::int(2))
        .expect_err("second eligible Apply must not fall back");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Heap {
            source: EvalHeapError::ActivePackedThunk { .. },
            ..
        }
    ));
    assert_eq!(
        evaluator
            .heap
            .active_packed_thunk_accounting()
            .apply_allocated,
        1
    );
}

#[test]
fn active_packed_error_aborts_claim_for_repeatable_retry() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, packed_options(2));
    let thunk = evaluator
        .alloc_apply_thunk(id, span, id, span, Value::int(1), id, Value::int(2))
        .expect("packed Apply allocates");

    evaluator
        .force_value(id, span, thunk)
        .expect_err("an integer is not callable");
    assert_eq!(
        evaluator.heap.active_packed_thunk_state(thunk),
        Some(ThunkState::Suspended)
    );
    evaluator
        .force_value(id, span, thunk)
        .expect_err("restored work can be retried");
    assert_eq!(
        evaluator.heap.active_packed_thunk_state(thunk),
        Some(ThunkState::Suspended)
    );
}

#[test]
fn active_packed_panic_aborts_claim_and_preserves_work() {
    let ir = lower("x: x + 1");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, packed_options(2));
    let function = evaluator.eval_root().expect("lambda evaluates");
    let thunk = evaluator
        .alloc_apply_thunk(id, span, id, span, function, id, Value::int(41))
        .expect("packed Apply allocates");
    evaluator.panic_active_packed_thunk_body_once = true;

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = evaluator.force_value(id, span, thunk);
    }));
    assert!(panic.is_err());
    assert_eq!(
        evaluator.heap.active_packed_thunk_state(thunk),
        Some(ThunkState::Suspended)
    );

    let result = evaluator
        .force_value(id, span, thunk)
        .expect("restored packed work evaluates");
    assert_eq!(result.as_int(), Ok(42));
    assert_eq!(
        evaluator.heap.active_packed_thunk_state(thunk),
        Some(ThunkState::Forced)
    );
}
