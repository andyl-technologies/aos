//! Tree-walk evaluator tests: Sync-safe shared value graph (parallel L2-P1).
//!
//! These tests pin the make-it-Sync phase of the parallel-evaluation effort:
//! serial-mode thunk error handling stays revert-and-retry, parallel-cell
//! thunks memoize failures and replay them without re-running the body, and
//! the graph-shared handles can actually cross a thread boundary.

use crate::eval::heap::EvalThunk;
use crate::eval::{ParallelThunkTerminalStatus, ThunkState};

use super::*;

/// Evaluates `source` to an attrset and returns the named lazy attr thunk.
fn attr_thunk_value(source: &str, attr: &[u8], options: TreeWalkOptions) -> (Ir, TreeWalk, Value) {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator
        .eval_root()
        .expect("source evaluates to an attrset");
    let attr = evaluator.symbols.intern(attr).expect("attr symbol interns");
    let value = evaluator
        .heap
        .get_attrs(value)
        .expect("root value is a heap attrset")
        .get(attr)
        .expect("attr exists");

    (ir, evaluator, value)
}

#[test]
fn serial_mode_error_force_reverts_to_suspended_and_reruns_the_body() {
    let (ir, mut evaluator, thunk_value) =
        attr_thunk_value("{ x = 1 / 0; }", b"x", TreeWalkOptions::new());

    let first = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("division by zero is a force error");
    assert!(matches!(
        first.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    assert_eq!(evaluator.stats().thunks_forced(), 1);

    let thunk = evaluator
        .heap
        .clone_thunk(thunk_value)
        .expect("attr value is a heap thunk");
    assert!(thunk.parallel_payload_cell().is_none());
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));

    let second = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("serial mode re-runs the errored body");
    assert_eq!(second, first);
    assert_eq!(
        evaluator.stats().thunks_forced(),
        2,
        "serial revert-and-retry must re-claim and re-run the body"
    );
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn parallel_cell_thunk_replays_thrown_error_without_rerunning_the_body() {
    let (ir, mut evaluator, thunk_value) = attr_thunk_value(
        r#"{ x = builtins.throw "boom"; }"#,
        b"x",
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    );

    let first = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("thrown body is a force error");
    assert_eq!(evaluator.stats().thunks_forced(), 1);

    let thunk = evaluator
        .heap
        .clone_thunk(thunk_value)
        .expect("attr value is a heap thunk");
    let parallel_cell = thunk
        .parallel_payload_cell()
        .expect("parallel payload cell is attached");
    assert_eq!(
        parallel_cell.state().expect("parallel state loads"),
        ParallelThunkTerminalStatus::Failed
    );
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));

    let second = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("failed parallel payload replays the stored error");
    assert_eq!(second, first);
    assert_eq!(
        evaluator.stats().thunks_forced(),
        1,
        "the failed body must not run again"
    );
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn shared_thunk_handles_cross_threads_and_replay_terminal_results() {
    let (ir, mut evaluator, thunk_value) = attr_thunk_value(
        "{ x = 1 + 2; }",
        b"x",
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    );
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    assert_eq!(forced.as_int(), Ok(3));

    let thunk: std::sync::Arc<EvalThunk> = evaluator
        .heap
        .clone_thunk(thunk_value)
        .expect("attr value is a heap thunk");

    let remote = std::thread::spawn(move || {
        let serial = thunk
            .cell()
            .cached_value()
            .expect("serial cached value is readable")
            .expect("serial cached value is present");
        let parallel = thunk
            .parallel_payload_cell()
            .expect("parallel payload cell is attached")
            .terminal_result()
            .expect("parallel terminal result is stored")
            .expect("parallel terminal result is successful");
        (serial, parallel)
    })
    .join()
    .expect("remote reader thread completes");

    assert_eq!(remote.0.as_int(), Ok(3));
    assert_eq!(remote.1.as_int(), Ok(3));
}
