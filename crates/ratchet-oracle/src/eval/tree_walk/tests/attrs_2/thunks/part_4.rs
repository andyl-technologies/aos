//! Split-out tests (part_4). See parent module.

use super::*;

#[test]
fn forcing_errors_reset_thunks_to_suspended() {
    let ir = lower("{ a = 1 / 0; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::new(&ir);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let error = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("division by zero remains a force error");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("thunk remains heap-owned");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert!(
        thunk
            .cell()
            .cached_value()
            .expect("suspended thunk has no invalid state")
            .is_none()
    );
}
