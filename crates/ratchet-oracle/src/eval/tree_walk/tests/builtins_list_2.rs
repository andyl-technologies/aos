//! Tree-walk evaluator tests: builtins list 2.

use super::*;

#[test]
fn concat_lists_primop_flattens_spines_without_forcing_elements() {
    assert_eq!(
        eval_list_ints("builtins.concatLists [ [ 1 ] [] [ 2 3 ] ]"),
        vec![1, 2, 3]
    );
    assert_eq!(eval_list_ints("builtins.concatLists []"), Vec::<i64>::new());
    assert_eq!(
        eval_list_ints("let f = builtins.concatLists; in f [ [ 1 ] [] [ 2 3 ] ]"),
        vec![1, 2, 3]
    );

    let ir = lower("builtins.concatLists [ [ true (1 / 0) ] [] ]");
    let outcome = eval_whnf_owned(&ir).expect("concatLists evaluates");
    let heap = outcome.heap();
    let list = heap
        .get_list(outcome.value())
        .expect("concatLists result is a list");

    assert_eq!(list.len(), 2);
    assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));
    let lazy_division = list.get(1).expect("second");
    assert_eq!(lazy_division.tag(), ValueTag::Thunk);
    let thunk = heap
        .get_thunk(lazy_division)
        .expect("inner list element remains lazy");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );

    let ir = lower("let f = builtins.concatLists; in f [ [ true (1 / 0) ] [] ]");
    let outcome = eval_whnf_owned(&ir).expect("first-class concatLists evaluates");
    let heap = outcome.heap();
    let list = heap
        .get_list(outcome.value())
        .expect("concatLists result is a list");

    assert_eq!(list.len(), 2);
    assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));
    assert_eq!(list.get(1).expect("second").tag(), ValueTag::Thunk);
}

#[test]
fn concat_lists_primop_type_checks_outer_and_inner_lists() {
    let ir = lower("builtins.concatLists 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("concatLists requires an outer list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.concatLists [ [ 1 ] 2 [ 3 ] ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("concatLists requires inner lists");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.concatLists (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];

    let error = eval_whnf_owned(&ir).expect_err("outer list is forced first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: argument }
    );

    let ir = lower("builtins.concatLists [ [ 1 ] (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("inner lists are forced in order");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn head_primop_returns_first_element_without_forcing_list_elements() {
    let ir = lower("builtins.head [ (1 / 0) true ]");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_primop(ir.root, &root)
        .expect("head primop evaluates");
    assert_eq!(value.tag(), ValueTag::Thunk);
    let thunk = evaluator
        .heap
        .get_thunk(value)
        .expect("head result remains a heap-owned thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );

    assert_eq!(eval("builtins.head [ true (1 / 0) ]").as_bool(), Ok(true));
    assert_eq!(
        eval("let f = builtins.head; in f [ true (1 / 0) ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_string_bytes("let builtins = { head = x: \"local\"; }; in builtins.head [ 1 ]"),
        b"local"
    );
}

#[test]
fn head_primop_rejects_empty_lists() {
    let ir = lower("builtins.head []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("head requires a non-empty list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::EmptyListPrimOp {
            id: argument,
            op: "head"
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn head_primop_type_checks_argument() {
    let ir = lower("builtins.head 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("head requires a list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn elem_at_primop_returns_indexed_element_without_forcing_other_elements() {
    assert_eq!(
        eval("builtins.elemAt [ true (1 / 0) false ] 0").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = builtins.elemAt; in f [ 1 2 ] 1").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let xs = [ 1 2 ]; n = 1; in builtins.elemAt xs n").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let builtins = { elemAt = xs: n: 42; }; in builtins.elemAt [ true ] 0").as_int(),
        Ok(42)
    );

    let ir = lower("builtins.elemAt [ true (1 / 0) false ] 1");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_primop(ir.root, &root)
        .expect("elemAt primop evaluates");
    assert_eq!(value.tag(), ValueTag::Thunk);
    let thunk = evaluator
        .heap
        .get_thunk(value)
        .expect("selected element remains a heap-owned thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );
}

#[test]
fn elem_at_primop_type_checks_arguments_in_order() {
    let ir = lower("builtins.elemAt 1 true");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let index = args[1];
    let index_span = ir.arena.node(index).expect("index argument exists").span;

    let error = eval_whnf(&ir).expect_err("elemAt checks the index before the list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: index,
            expected: "int",
            actual: ValueTag::Bool
        }
    );
    assert_eq!(error.span(), index_span);

    let ir = lower("builtins.elemAt (1 / 0) true");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let index = args[1];
    let index_span = ir.arena.node(index).expect("index argument exists").span;

    let error = eval_whnf(&ir).expect_err("elemAt checks index type before forcing list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: index,
            expected: "int",
            actual: ValueTag::Bool
        }
    );
    assert_eq!(error.span(), index_span);

    let ir = lower("builtins.elemAt 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let index = args[1];
    let index_span = ir.arena.node(index).expect("index argument exists").span;

    let error = eval_whnf(&ir).expect_err("elemAt forces the index before checking the list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: index }
    );
    assert_eq!(error.span(), index_span);

    let error = eval_whnf_owned(&lower(
        "let f = builtins.elemAt; in f (builtins.throw \"list\") (builtins.throw \"index\")",
    ))
    .expect_err("first-class elemAt forces the index before the list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"index");

    let ir = lower("builtins.elemAt [] true");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let index = args[1];
    let index_span = ir.arena.node(index).expect("index argument exists").span;

    let error = eval_whnf(&ir).expect_err("elemAt requires an integer index");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: index,
            expected: "int",
            actual: ValueTag::Bool
        }
    );
    assert_eq!(error.span(), index_span);
}

#[test]
fn elem_at_primop_rejects_out_of_range_indexes() {
    for (source, expected_index) in [
        ("builtins.elemAt [ true ] 1", 1),
        ("builtins.elemAt [ true ] (-1)", -1),
    ] {
        let ir = lower(source);
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt requires an in-range index");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::ListIndexOutOfBounds {
                id: index,
                index: expected_index,
                len: 1
            }
        );
        assert_eq!(error.span(), index_span);
    }
}

#[test]
fn elem_primop_scans_list_with_structural_equality() {
    assert_eq!(eval("builtins.elem 2 [ 1 2 (1 / 0) ]").as_bool(), Ok(true));
    assert_eq!(eval("builtins.elem 3 [ 1 2 ]").as_bool(), Ok(false));
    assert_eq!(
        eval("let f = builtins.elem; in f 2 [ 1 2 (1 / 0) ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = builtins.elem; in f 3 [ 1 2 ]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("builtins.elem { a = 1; } [ { a = 1; } { a = 1 / 0; } ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = x: x; in builtins.elem f [ f ]").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.elem (x: x) [ (x: x) ]").as_bool(), Ok(false));
    assert_eq!(
        eval("let v = { a = x: x; }; in builtins.elem v.a [ v.a ]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("let xs = [ xs ]; in builtins.elem xs xs").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let xs = [ xs ]; f = builtins.elem; in f xs xs").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let s = rec { a = s; }; in builtins.elem s [ s ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let xs = [ (1 / 0) ]; in builtins.elem xs [ xs ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in builtins.elem nan [ nan ]")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
            eval(
                "builtins.elem ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) [ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ]"
            )
            .as_bool(),
            Ok(false)
        );
    assert_eq!(eval("builtins.elem (1 / 0) []").as_bool(), Ok(false));
    assert_eq!(
        eval("let builtins = { elem = value: list: false; }; in builtins.elem 1 [ 1 ]").as_bool(),
        Ok(false)
    );
}

#[test]
fn elem_primop_type_checks_list_before_candidate() {
    let ir = lower("builtins.elem (1 / 0) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf(&ir).expect_err("elem checks list type before candidate");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.elem 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf(&ir).expect_err("elem forces the list before the candidate");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
    assert_eq!(error.span(), list_span);

    let error = eval_whnf_owned(&lower("let f = builtins.elem; in f (1 / 0) 1"))
        .expect_err("first-class elem checks list before candidate");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("let f = builtins.elem; in f 1 (1 / 0)"))
        .expect_err("first-class elem forces list before candidate");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("builtins.elem 2 [ 1 (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("elem scans until match or error");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("let x = 1 / 0; in builtins.elem x [ x ]");
    let error = eval_whnf_owned(&ir).expect_err("elem forces shared throwing candidates");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("let s = { x = 1 / 0; }; v = { a = s; }; in builtins.elem v.a [ v.a ]");
    let error = eval_whnf_owned(&ir).expect_err("elem does not hide selected attrset errors");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn all_and_any_primops_short_circuit_over_lazy_elements() {
    assert_eq!(
        eval("builtins.all (x: x < 3) [ 1 2 3 ]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("builtins.all (x: x < 4) [ 1 2 3 ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.any (x: x == 2) [ 1 2 (1 / 0) ]").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.any (x: false) []").as_bool(), Ok(false));
    assert_eq!(eval("builtins.all (x: true) []").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.all (x: false) [ (1 / 0) ]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("builtins.any (x: true) [ (1 / 0) ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.all builtins.isInt [ 1 2 ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.any builtins.isString [ 1 \"x\" ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let a = builtins.all; in a (x: x) [ true ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let a = builtins.any; in a (x: x) [ false true ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let p = x: x; xs = [ true ]; in builtins.all p xs").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let builtins = { all = pred: list: false; }; in builtins.all (x: true) []").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("let builtins = { any = pred: list: true; }; in builtins.any (x: false) []").as_bool(),
        Ok(true)
    );
}
