//! Tree-walk tests for segmented-stack recursion protection.

use super::*;

/// Runs an evaluator closure on a deliberately small native stack.
fn on_small_stack<T: Send + 'static>(evaluate: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .name("tree-walk-small-stack".to_owned())
        .stack_size(512 * 1024)
        .spawn(evaluate)
        .expect("small-stack evaluator thread spawns")
        .join()
        .expect("segmented-stack evaluator does not panic")
}

#[test]
fn deep_recursion_completes_beyond_the_native_stack() {
    let value = on_small_stack(|| {
        let ir = lower("let f = n: if n == 0 then 42 else f (n - 1); in f 1500");
        let mut evaluator =
            TreeWalk::with_options(&ir, TreeWalkOptions::with_max_call_depth(2_000));
        evaluator.eval_root().expect("deep recursion completes")
    });

    assert_eq!(value.as_int(), Ok(42));
}

#[test]
fn deep_recursion_reaches_the_configured_nix_depth_error() {
    let (matched_depth_error, final_depth) = on_small_stack(|| {
        let ir = lower("let f = n: f (n + 1); in f 0");
        let mut evaluator = TreeWalk::new(&ir);
        let error = evaluator
            .eval_root()
            .expect_err("unbounded recursion reaches max-call-depth");
        (
            matches!(
                error.kind(),
                TreeWalkErrorKind::MaxCallDepthExceeded {
                    depth,
                    max: DEFAULT_MAX_CALL_DEPTH,
                    ..
                } if depth == DEFAULT_MAX_CALL_DEPTH + 1
            ),
            evaluator.call_depth,
        )
    });

    assert!(matched_depth_error);
    assert_eq!(final_depth, 0, "failed recursion unwinds every call frame");
}
