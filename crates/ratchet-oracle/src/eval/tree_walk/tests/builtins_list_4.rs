//! Tree-walk evaluator tests: builtins list 4.

use super::*;

#[test]
fn map_primop_checks_list_before_function_for_nonempty_lists() {
    assert_eq!(eval("builtins.length (builtins.map 1 [])").as_int(), Ok(0));
    assert_eq!(
        eval("builtins.length (builtins.map (builtins.throw \"function\") [])").as_int(),
        Ok(0)
    );

    let ir = lower("builtins.map (builtins.throw \"function\") 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("map checks list before function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.map (x: x) (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("map forces list argument");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.map 1 [ 2 ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let function = args[0];
    let function_span = ir
        .arena
        .node(function)
        .expect("function argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("map requires a function on nonempty lists");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);
}

#[test]
fn filter_primop_selects_without_forcing_returned_elements() {
    assert_eq!(
        eval("builtins.length (builtins.filter (x: x < 3) [ 1 2 3 ])").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.filter (x: x < 3) [ 1 2 3 ]) 0").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.filter (x: x < 3) [ 1 2 3 ]) 1").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.length (builtins.filter (x: false) [ (1 / 0) ])").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("builtins.length (builtins.filter (x: true) [ (1 / 0) ])").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.length (builtins.filter builtins.isInt [ 1 \"x\" 2 ])").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (let f = builtins.filter; in f builtins.isInt [ 1 \"x\" 2 ]) 1")
            .as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let p = x: x; xs = [ true ]; in builtins.length (builtins.filter p xs)").as_int(),
        Ok(1)
    );
    assert_eq!(
            eval("let builtins = { filter = pred: list: [ 42 ]; }; in builtins.filter (x: false) [] == [ 42 ]")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn filter_primop_checks_list_before_predicate() {
    assert_eq!(
        eval("builtins.length (builtins.filter (1 / 0) [])").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("builtins.length (builtins.filter 1 [])").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("let xs = []; in builtins.length (builtins.filter (builtins.throw \"predicate\") xs)")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("let f = builtins.filter; in builtins.length (f (builtins.throw \"predicate\") [])")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("let f = builtins.filter; in builtins.length (f 1 [])").as_int(),
        Ok(0)
    );

    let error = eval_whnf_owned(&lower(
        "let f = builtins.filter; in f (builtins.throw \"predicate\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class filter checks list before predicate");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"list");

    let ir = lower("builtins.filter (1 / 0) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("filter checks list before predicate");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.filter (x: true) (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("filter forces list argument");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
    assert_eq!(error.span(), list_span);
}

#[test]
fn filter_primop_checks_predicate_and_result_for_nonempty_lists() {
    let ir = lower("builtins.filter 1 [ 1 ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let predicate = args[0];
    let predicate_span = ir
        .arena
        .node(predicate)
        .expect("predicate argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("filter requires predicate on nonempty lists");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: predicate,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), predicate_span);

    let ir = lower("builtins.filter (x: 1) [ \"a\" ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let predicate = args[0];
    let predicate_span = ir
        .arena
        .node(predicate)
        .expect("predicate argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("filter requires bool predicate result");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: predicate,
            expected: "bool",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), predicate_span);
}

#[test]
fn partition_primop_splits_forced_elements_into_right_and_wrong() {
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames (builtins.partition (x: true) [])"),
        vec![b"right".to_vec(), b"wrong".to_vec()]
    );
    assert_eq!(
        eval("builtins.length (builtins.partition (x: x < 3) [ 1 2 3 ]).right").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.partition (x: x < 3) [ 1 2 3 ]).right 0").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.partition (x: x < 3) [ 1 2 3 ]).right 1").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.length (builtins.partition (x: x < 3) [ 1 2 3 ]).wrong").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.partition (x: x < 3) [ 1 2 3 ]).wrong 0").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("builtins.length (builtins.partition (x: true) [ { a = 1 / 0; } ]).right").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.length (builtins.partition builtins.isInt [ 1 \"x\" 2 ]).right").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval(
            "builtins.length (let f = builtins.partition; in f builtins.isInt [ 1 \"x\" 2 ]).wrong"
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let p = x: true; xs = []; in builtins.length (builtins.partition p xs).right")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
            eval("let builtins = { partition = pred: list: { right = [ 42 ]; wrong = []; }; }; in builtins.partition (x: false) [] == { right = [ 42 ]; wrong = []; }")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn partition_primop_checks_predicate_before_list() {
    let ir = lower("builtins.partition (1 / 0) []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let predicate = args[0];
    let predicate_span = ir
        .arena
        .node(predicate)
        .expect("predicate argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("partition forces predicate before list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: predicate }
    );
    assert_eq!(error.span(), predicate_span);

    let ir = lower("builtins.partition 1 []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let predicate = args[0];
    let predicate_span = ir
        .arena
        .node(predicate)
        .expect("predicate argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("partition requires predicate first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: predicate,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), predicate_span);

    let ir = lower(
        "let f = builtins.partition; in f (builtins.throw \"predicate\") (builtins.throw \"list\")",
    );

    let error =
        eval_whnf_owned(&ir).expect_err("first-class partition forces predicate before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"predicate");

    let ir = lower("builtins.partition (x: true) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("partition checks list after predicate");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);
}

#[test]
fn partition_primop_forces_elements_before_predicate_application() {
    let ir = lower("builtins.partition (x: true) [ (1 / 0) ]");

    let error = eval_whnf_owned(&ir).expect_err("partition forces elements");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("builtins.partition (x: 1) [ \"a\" ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let predicate = args[0];
    let predicate_span = ir
        .arena
        .node(predicate)
        .expect("predicate argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("partition requires bool predicate result");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: predicate,
            expected: "bool",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), predicate_span);
}

#[test]
fn foldl_strict_primop_folds_left_and_forces_accumulator() {
    assert_eq!(
        eval("builtins.foldl' (acc: x: acc + x) 0 [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval("builtins.foldl' builtins.add 0 [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval("let f = builtins.foldl'; in f (acc: x: acc + x) 0 [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval("let f = builtins.foldl'; in f builtins.add 0 [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.foldl' (acc: x: acc ++ [ x ]) [] [ 1 2 3 ]) 0").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.foldl' (acc: x: acc ++ [ x ]) [] [ 1 2 3 ]) 2").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("builtins.foldl' (acc: x: acc) 0 [ (1 / 0) ]").as_int(),
        Ok(0)
    );

    let ir = lower("builtins.foldl' (acc: x: x) 0 [ (1 / 0) ]");
    let error = eval_whnf(&ir).expect_err("foldl' forces each accumulator result");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let outcome = eval_whnf_owned(&lower("builtins.foldl' (acc: x: { a = 1 / 0; }) 0 [ 1 ]"))
        .expect("foldl' forces accumulator to WHNF only");
    assert_eq!(outcome.value().tag(), ValueTag::Attrs);

    assert_eq!(
        eval(
            "builtins.foldl' (_: x: x) (throw \"initial is lazy\") \
             [ \"but operator results are forced\" 42 ]"
        )
        .as_int(),
        Ok(42)
    );
    assert_eq!(
        eval(
            "let f = builtins.foldl'; in \
             f (_: x: x) (throw \"initial is lazy\") \
             [ \"but operator results are forced\" 42 ]"
        )
        .as_int(),
        Ok(42)
    );
}

#[test]
fn foldl_strict_primop_checks_operator_then_list_without_forcing_initial() {
    let ir = lower("builtins.foldl' (1 / 0) 0 []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let op = args[0];
    let op_span = ir.arena.node(op).expect("operator argument exists").span;

    let error = eval_whnf(&ir).expect_err("foldl' forces operator first");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: op });
    assert_eq!(error.span(), op_span);

    let ir = lower("builtins.foldl' 1 0 []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let op = args[0];
    let op_span = ir.arena.node(op).expect("operator argument exists").span;

    let error = eval_whnf(&ir).expect_err("foldl' requires an operator function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: op,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), op_span);

    let ir = lower("builtins.foldl' (acc: x: acc) (1 / 0) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[2];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf(&ir).expect_err("foldl' checks list before initial value");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let outcome = eval_whnf_owned(&lower("builtins.foldl' (acc: x: acc) (1 / 0) []"))
        .expect("foldl' returns an empty-list initial accumulator lazily");
    assert_eq!(outcome.value().tag(), ValueTag::Thunk);
    assert_eq!(
        eval("builtins.add (builtins.foldl' (acc: x: acc) (1 + 2) []) 1").as_int(),
        Ok(4)
    );

    let error = eval_whnf_owned(&lower("let f = builtins.foldl'; in f (1 / 0) 0 []"))
        .expect_err("first-class foldl' forces operator first");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower("let f = builtins.foldl'; in f 1 0 []"))
        .expect_err("first-class foldl' requires an operator function");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "let f = builtins.foldl'; in f (acc: x: acc) (1 / 0) 1",
    ))
    .expect_err("first-class foldl' checks list before initial value");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let outcome = eval_whnf_owned(&lower(
        "let f = builtins.foldl'; in f (acc: x: acc) (1 / 0) []",
    ))
    .expect("first-class foldl' returns an empty-list initial accumulator lazily");
    assert_eq!(outcome.value().tag(), ValueTag::Thunk);
    assert_eq!(
        eval("let f = builtins.foldl'; in builtins.add (f (acc: x: acc) (1 + 2) []) 1").as_int(),
        Ok(4)
    );
}

#[test]
fn foldl_empty_lazy_initial_is_forced_by_attr_consumers() {
    assert_eq!(
        eval(
            "let discoverPackages = subdirs:
               let filePackages = { zlib = 1; };
                   subdirPackages =
                     builtins.foldl' (acc: subdir: acc // { ${subdir} = true; }) {} subdirs;
               in filePackages // subdirPackages;
             in (discoverPackages []).zlib"
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.isAttrs (builtins.foldl' (acc: _x: acc) { a = 1; } [])").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("((builtins.foldl' (acc: _x: acc) { a = 1; } []) // { b = 2; }).a").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("({ b = 2; } // builtins.foldl' (acc: _x: acc) { a = 1; } []).a").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("(builtins.foldl' (acc: _x: acc) { a = 1; } []).a").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("(builtins.foldl' (acc: _x: acc) { a = { b = 2; }; } []).a.b").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("(builtins.foldl' (acc: _x: acc) { a = 1; } []) ? a").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.hasAttr \"a\" (builtins.foldl' (acc: _x: acc) { a = 1; } [])").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.getAttr \"a\" (builtins.foldl' (acc: _x: acc) { a = 1; } [])").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval(
            "let get = builtins.getAttr \"a\";
             in get (builtins.foldl' (acc: _x: acc) { a = 1; } [])"
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval(
            "let has = builtins.hasAttr \"a\";
             in has (builtins.foldl' (acc: _x: acc) { a = 1; } [])"
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_list_string_bytes(
            "builtins.attrNames (builtins.foldl' (acc: _x: acc) { b = 2; a = 1; } [])"
        ),
        vec![b"a".to_vec(), b"b".to_vec()]
    );
    assert_eq!(
        eval_list_ints("builtins.attrValues (builtins.foldl' (acc: _x: acc) { b = 2; a = 1; } [])"),
        vec![1, 2]
    );
    assert_eq!(
        eval("(builtins.removeAttrs (builtins.foldl' (acc: _x: acc) { a = 1; b = 2; } []) [ \"b\" ]).a").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval(
            "let remove = builtins.removeAttrs (builtins.foldl' (acc: _x: acc) { a = 1; b = 2; } []);
             in (remove [ \"b\" ]).a"
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("(builtins.intersectAttrs (builtins.foldl' (acc: _x: acc) { a = 1; c = 3; } []) { a = 2; b = 4; }).a").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("(builtins.intersectAttrs { a = 0; } (builtins.foldl' (acc: _x: acc) { a = 2; b = 4; } [])).a").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval(
            "let intersect = builtins.intersectAttrs { a = 0; };
             in (intersect (builtins.foldl' (acc: _x: acc) { a = 2; b = 4; } [])).a"
        )
        .as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("(builtins.mapAttrs (_name: value: value + 1) (builtins.foldl' (acc: _x: acc) { a = 1; } [])).a").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval(
            "let map = builtins.mapAttrs (_name: value: value + 1);
             in (map (builtins.foldl' (acc: _x: acc) { a = 1; } [])).a"
        )
        .as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.unsafeGetAttrPos \"missing\" (builtins.foldl' (acc: _x: acc) { a = 1; } []) == null").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(
            "let unsafeGetAttrPos = builtins.unsafeGetAttrPos \"missing\";
             in unsafeGetAttrPos (builtins.foldl' (acc: _x: acc) { a = 1; } []) == null"
        )
        .as_bool(),
        Ok(true)
    );

    let update_error = eval_whnf_owned(&lower("{} // builtins.foldl' (acc: _x: acc) (1 / 0) []"))
        .expect_err("attr update demands the right initial accumulator");
    assert!(matches!(
        update_error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let select_error = eval_whnf_owned(&lower("(builtins.foldl' (acc: _x: acc) (1 / 0) []).a"))
        .expect_err("attr selection demands the receiver initial accumulator");
    assert!(matches!(
        select_error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let has_attr_error = eval_whnf_owned(&lower(
        "builtins.hasAttr \"a\" (builtins.foldl' (acc: _x: acc) (1 / 0) [])",
    ))
    .expect_err("hasAttr demands the initial accumulator");
    assert!(matches!(
        has_attr_error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let break_attr_names_error =
        eval_whnf_owned(&lower("builtins.attrNames (builtins.break { a = 1; })"))
            .expect_err("attrNames keeps generic break identity thunks visible");
    assert!(matches!(
        break_attr_names_error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Thunk,
            ..
        }
    ));
}

#[test]
fn foldl_strict_primop_checks_curried_operator_results() {
    let ir = lower("builtins.foldl' (acc: 1) 0 [ 1 ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let op = args[0];
    let op_span = ir.arena.node(op).expect("operator argument exists").span;

    let error = eval_whnf(&ir).expect_err("foldl' requires curried binary operator");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: op,
            expected: "lambda",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), op_span);

    assert_eq!(
            eval("let builtins = { foldl' = op: initial: list: 42; }; in builtins.foldl' (acc: x: acc) 0 []")
                .as_int(),
            Ok(42)
        );
}

#[test]
fn sort_primop_orders_stably_with_comparator() {
    assert_eq!(
        eval_list_ints("builtins.sort builtins.lessThan [ 3 1 2 1 ]"),
        vec![1, 1, 2, 3]
    );
    assert_eq!(
        eval_list_ints("builtins.sort (a: b: builtins.lessThan b a) [ 3 1 2 ]"),
        vec![3, 2, 1]
    );
    assert_eq!(
        eval_list_ints("let sort = builtins.sort builtins.lessThan; in sort [ 3 1 2 ]"),
        vec![1, 2, 3]
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.concatStringsSep \",\" (builtins.map (x: x.name) (builtins.sort (a: b: a.key < b.key) [ { key = 1; name = \"a\"; } { key = 1; name = \"b\"; } { key = 0; name = \"c\"; } ]))"
        ),
        b"c,a,b"
    );
    assert_eq!(
            eval("let builtins = { sort = comparator: list: [ 42 ]; }; in builtins.sort (a: b: false) [] == [ 42 ]")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn sort_primop_checks_comparator_list_and_result_types() {
    assert_eq!(
        eval_list_ints("builtins.sort (1 / 0) []"),
        Vec::<i64>::new()
    );
    assert_eq!(eval_list_ints("builtins.sort 1 []"), Vec::<i64>::new());
    assert_eq!(
        eval_list_ints("let sort = builtins.sort 1; in sort []"),
        Vec::<i64>::new()
    );

    let ir = lower("builtins.sort (1 / 0) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;
    let error = eval_whnf_owned(&ir).expect_err("sort checks the list before comparator");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.sort 1 [ 1 ]");
    let error = eval_whnf_owned(&ir).expect_err("sort requires a comparator function");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("let sort = builtins.sort; in sort 1 []");
    let result = eval_whnf_owned(&ir).expect("first-class sort skips comparator for empty list");
    let list = result
        .heap()
        .get_list(result.value())
        .expect("result is a list");
    assert!(list.is_empty());

    let ir = lower(
        "let sort = builtins.sort; in sort (builtins.throw \"comparator\") (builtins.throw \"list\")",
    );
    let error = eval_whnf_owned(&ir).expect_err("first-class sort forces list before comparator");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"list");

    let ir = lower("builtins.sort (a: b: false) 1");
    let error = eval_whnf_owned(&ir).expect_err("sort requires a list");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.sort (a: b: 1) [ 1 2 ]");
    let error = eval_whnf_owned(&ir).expect_err("sort comparator must return bool");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.sort (a: b: false) [ (1 / 0) true ]");
    let error = eval_whnf_owned(&ir).expect_err("sort forces elements before comparison");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("builtins.sort 1 [ (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("sort validates comparator before elements");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.sort builtins.lessThan [ 1 (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("sort forces elements");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn sort_primop_matches_libcxx_small_range_comparator_order() {
    let ir = lower(
        "builtins.sort (a: b:
              if a == 2 && b == 1 then builtins.throw \"wrong-order\"
              else if a == 2 && b == 3 then builtins.throw \"2<3\"
              else a < b)
            [ 3 1 2 ]",
    );
    let error = eval_whnf_owned(&ir).expect_err("sort reaches the libc++ second comparison first");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"2<3");
}

#[test]
fn sort_primop_matches_libcxx_large_range_merge_order() {
    // libc++ insertion-sorts pointer-like values up to 128 elements; 129
    // elements reaches the recursive stable-sort merge path. C++ Nix
    // 2.24 observes this top-level merge comparison for the descending fixture.
    let ir = lower(
        "builtins.sort (a: b:
              if a == 1 && b == 66 then builtins.throw \"top-merge\"
              else a < b)
            (builtins.genList (i: 129 - i) 129)",
    );
    let error = eval_whnf_owned(&ir).expect_err("sort reaches the libc++ large-range merge path");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"top-merge");
}
