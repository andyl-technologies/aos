//! Tree-walk evaluator tests: builtins list 1.

use super::*;

#[test]
fn map_attrs_primop_preserves_names_and_maps_values_lazily() {
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames (builtins.mapAttrs (1 / 0) { z = 1; a = 2; })"),
        vec![b"a".to_vec(), b"z".to_vec()]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames (builtins.mapAttrs (1 / 0) {})"),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
        eval_string_bytes(
            "(builtins.mapAttrs (name: value: name + \":\" + builtins.toString value) { b = 2; a = 1; }).a"
        ),
        b"a:1"
    );
    assert_eq!(
            eval("let mapped = builtins.mapAttrs (name: value: value + 1) { b = 1 / 0; a = 1; }; in mapped.a")
                .as_int(),
            Ok(2)
        );
    assert_eq!(
        eval_string_bytes(
            "let mapAttrs = builtins.mapAttrs; mapped = mapAttrs (name: value: name) { a = 1; }; in mapped.a"
        ),
        b"a"
    );
    assert_eq!(
            eval(
                "let builtins = { mapAttrs = f: set: { local = true; }; }; in (builtins.mapAttrs (name: value: value) { a = 1; }).local"
            )
            .as_bool(),
            Ok(true)
        );
}

#[test]
fn map_attrs_constructs_a_large_batch_without_changing_names_or_values() {
    let bindings = (0..128)
        .map(|index| format!("k{index:03} = {index};"))
        .collect::<Vec<_>>()
        .join(" ");
    let source = format!(
        r#"
        let
          mapped = builtins.mapAttrs
            (name: value: name + ":" + builtins.toString value)
            {{ {bindings} }};
        in mapped.k000 == "k000:0"
           && mapped.k127 == "k127:127"
           && builtins.length (builtins.attrNames mapped) == 128
        "#
    );

    assert_eq!(eval(&source).as_bool(), Ok(true));
}

#[test]
fn map_attrs_primop_checks_set_before_function_and_defers_function_errors() {
    let ir = lower("builtins.mapAttrs (1 / 0) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let attrs_id = args[1];
    let attrs_span = ir.arena.node(attrs_id).expect("attrs arg exists").span;

    let error = eval_whnf_owned(&ir).expect_err("mapAttrs checks the set first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: attrs_id,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), attrs_span);

    assert_eq!(
        eval_list_string_bytes("builtins.attrNames (builtins.mapAttrs 1 { a = 1; })"),
        vec![b"a".to_vec()]
    );

    let ir = lower("(builtins.mapAttrs 1 { a = 1; }).a");
    let error = eval_whnf_owned(&ir).expect_err("mapAttrs rejects non-functions on demand");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("(builtins.mapAttrs (1 / 0) { a = 1; }).a");
    let error = eval_whnf_owned(&ir).expect_err("mapAttrs forces the function on demand");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn zip_attrs_with_primop_groups_union_names_and_value_lists() {
    assert_eq!(
        eval_list_string_bytes(
            "builtins.attrNames (builtins.zipAttrsWith (name: values: values) [ { b = 2; a = 1; } { a = 3; c = 4; } { b = 5; } ])"
        ),
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    );
    assert_eq!(
            eval("builtins.length (builtins.zipAttrsWith (name: values: values) [ { b = 2; a = 1; } { a = 3; c = 4; } { b = 5; } ]).a")
                .as_int(),
            Ok(2)
        );
    assert_eq!(
            eval("builtins.elemAt (builtins.zipAttrsWith (name: values: values) [ { b = 2; a = 1; } { a = 3; c = 4; } { b = 5; } ]).a 0")
                .as_int(),
            Ok(1)
        );
    assert_eq!(
            eval("builtins.elemAt (builtins.zipAttrsWith (name: values: values) [ { b = 2; a = 1; } { a = 3; c = 4; } { b = 5; } ]).a 1")
                .as_int(),
            Ok(3)
        );
    assert_eq!(
        eval_string_bytes(
            "(builtins.zipAttrsWith (name: values: name + \":\" + builtins.toString (builtins.length values)) [ { b = 2; a = 1; } { a = 3; c = 4; } { b = 5; } ]).b"
        ),
        b"b:2"
    );
    assert_eq!(
        eval(
            "builtins.elemAt
               (builtins.zipAttrsWith (name: values: values) [
                 (builtins.foldl' (acc: _x: acc) { a = 1; } [])
               ]).a
               0"
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
            eval("let zip = builtins.zipAttrsWith; zipped = zip (name: values: values) [ { a = 1; } ]; in builtins.elemAt zipped.a 0")
                .as_int(),
            Ok(1)
        );
    assert_eq!(
            eval(
                "let builtins = { zipAttrsWith = f: list: { local = true; }; }; in (builtins.zipAttrsWith (name: values: values) []).local"
            )
            .as_bool(),
            Ok(true)
        );
}

#[test]
fn zip_attrs_with_primop_force_order_and_result_laziness_match_cpp_nix() {
    let ir = lower("let zip = builtins.zipAttrsWith; in zip 1 (1 / 0)");
    let error = eval_whnf_owned(&ir).expect_err("zipAttrsWith checks function before list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.zipAttrsWith (name: values: values) 1");
    let error = eval_whnf_owned(&ir).expect_err("zipAttrsWith requires a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.attrNames (builtins.zipAttrsWith (name: values: values) [ 1 ])");
    let error = eval_whnf_owned(&ir).expect_err("zipAttrsWith requires attrset elements");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    assert_eq!(
        eval_list_string_bytes(
            "builtins.attrNames (builtins.zipAttrsWith (name: values: 1 / 0) [ { a = 1; } ])"
        ),
        vec![b"a".to_vec()]
    );
    assert_eq!(
        eval("builtins.length (builtins.zipAttrsWith (name: values: values) [ { a = 1 / 0; } ]).a")
            .as_int(),
        Ok(1)
    );

    let ir = lower("(builtins.zipAttrsWith (name: values: 1 / 0) [ { a = 1; } ]).a");
    let error = eval_whnf_owned(&ir).expect_err("zipAttrsWith applies function on value demand");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower(
        "builtins.elemAt (builtins.zipAttrsWith (name: values: values) [ { a = 1 / 0; } ]).a 0",
    );
    let error = eval_whnf_owned(&ir).expect_err("zipAttrsWith preserves lazy grouped values");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn higher_order_primops_accept_functor_sets() {
    assert_eq!(
        eval_json_bytes("builtins.map { __functor = self: x: x + 1; } [ 1 2 ]"),
        b"[2,3]".to_vec()
    );
    assert_eq!(
        eval("builtins.all { __functor = self: x: x; } [ true true ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_json_bytes("builtins.genList { __functor = self: x: x + 1; } 3"),
        b"[1,2,3]".to_vec()
    );
    assert_eq!(
        eval("builtins.foldl' { __functor = self: acc: x: acc + x; } 0 [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval_json_bytes("builtins.sort { __functor = self: a: b: a < b; } [ 3 1 2 ]"),
        b"[1,2,3]".to_vec()
    );
    assert_eq!(
        eval_string_bytes(
            "(builtins.mapAttrs { __functor = self: name: value: name + \":\" + builtins.toString value; } { a = 1; }).a"
        ),
        b"a:1"
    );
    assert_eq!(
        eval_json_bytes(
            "(builtins.zipAttrsWith { __functor = self: name: values: values; } [ { a = 1; } { a = 2; } ]).a"
        ),
        b"[1,2]".to_vec()
    );
    assert_eq!(
            eval("builtins.length (builtins.genericClosure { startSet = [ { key = 1; } ]; operator = { __functor = self: item: if item.key == 1 then [ { key = 2; } ] else []; }; })")
                .as_int(),
            Ok(2)
        );
}

#[test]
fn higher_order_primops_force_functor_values_on_demand() {
    assert_eq!(
        eval("builtins.length (builtins.map { __functor = 1; } [])").as_int(),
        Ok(0)
    );

    let error = eval_whnf_owned(&lower(
        "builtins.elemAt (builtins.map { __functor = 1; } [ 1 ]) 0",
    ))
    .expect_err("bad map functor is forced when the mapped element is forced");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("builtins.map {} [ 1 ]"))
        .expect_err("non-functor attrsets are not accepted as functions");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Attrs,
            ..
        }
    ));
}

#[test]
fn tail_primop_returns_tail_without_forcing_elements() {
    let ir = lower("builtins.tail [ 1 (1 / 0) true ]");
    let outcome = eval_whnf_owned(&ir).expect("tail evaluates");
    let heap = outcome.heap();
    let list = heap
        .get_list(outcome.value())
        .expect("tail result is heap-owned");

    assert_eq!(list.len(), 2);
    let lazy_division = list.get(0).expect("first tail element");
    assert_eq!(lazy_division.tag(), ValueTag::Thunk);
    let thunk = heap
        .get_thunk(lazy_division)
        .expect("first tail element remains a heap-owned thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );
    assert_eq!(
        list.get(1).expect("second tail element").as_bool(),
        Ok(true)
    );

    assert_eq!(
        eval_list_string_bytes(
            "let builtins = { tail = x: [ \"local\" ]; }; in builtins.tail [ 1 ]"
        ),
        vec![b"local".to_vec()]
    );
    assert_eq!(
        eval_list_ints("let f = builtins.tail; in f [ 1 2 3 ]"),
        vec![2, 3]
    );

    let ir = lower("let f = builtins.tail; in f [ 1 (1 / 0) true ]");
    let outcome = eval_whnf_owned(&ir).expect("first-class tail evaluates");
    let heap = outcome.heap();
    let list = heap
        .get_list(outcome.value())
        .expect("tail result is heap-owned");

    assert_eq!(list.len(), 2);
    let lazy_division = list.get(0).expect("first tail element");
    assert_eq!(lazy_division.tag(), ValueTag::Thunk);
}

#[test]
fn tail_primop_rejects_empty_lists() {
    let ir = lower("builtins.tail []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("tail requires a non-empty list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::EmptyListPrimOp {
            id: argument,
            op: "tail"
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn tail_primop_type_checks_argument() {
    let ir = lower("builtins.tail 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("tail requires a list");

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
fn function_args_primop_describes_lambda_formals_without_forcing_defaults() {
    let simple =
        eval_whnf_owned(&lower("builtins.functionArgs (x: x)")).expect("functionArgs evaluates");
    let attrs = simple
        .heap()
        .get_attrs(simple.value())
        .expect("simple lambda result is attrs");
    assert!(attrs.is_empty());

    let ir = lower("builtins.functionArgs ({ b ? (1 / 0), a, ... }@args: a)");
    let outcome = eval_whnf_owned(&ir).expect("functionArgs evaluates");
    let attrs = outcome
        .heap()
        .get_attrs(outcome.value())
        .expect("formal-set lambda result is attrs");
    let entries = attrs
        .iter_lexicographic()
        .map(|entry| {
            (
                ir.symbols
                    .resolve(entry.key)
                    .expect("entry key resolves")
                    .to_vec(),
                entry.value.as_bool().expect("entry value is bool"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(entries, vec![(b"a".to_vec(), false), (b"b".to_vec(), true)]);
    assert_eq!(
        eval("let r = builtins.functionArgs ({ b ? (1 / 0), a }: a); in r.a == false && r.b")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = builtins.functionArgs; r = f ({ a, b ? 1 }: a); in r.a == false && r.b")
            .as_bool(),
        Ok(true)
    );

    assert_eq!(
            eval("let builtins = { functionArgs = f: { local = true; }; }; in (builtins.functionArgs (x: x)).local")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn function_args_primop_type_checks_argument() {
    let ir = lower("builtins.functionArgs 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("functionArgs requires a lambda");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "function",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn functor_sets_are_not_function_predicates_or_function_args() {
    assert_eq!(
        eval("builtins.isFunction { __functor = self: x: x; }").as_bool(),
        Ok(false)
    );

    let ir = lower("builtins.functionArgs { __functor = self: { a }: a; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("functionArgs rejects functor attrsets");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "function",
            actual: ValueTag::Attrs
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn list_to_attrs_primop_builds_attrs_with_first_wins_duplicates() {
    assert_eq!(
        eval_list_string_bytes(
            "builtins.attrNames (builtins.listToAttrs [ { name = \"b\"; value = 1; } { name = \"a\"; value = 2; } ])"
        ),
        vec![b"a".to_vec(), b"b".to_vec()]
    );
    assert_eq!(
            eval("(builtins.listToAttrs [ { name = \"a\"; value = 1; } { name = \"a\"; value = 1 / 0; } ]).a")
                .as_int(),
            Ok(1)
        );
    assert_eq!(
        eval("(builtins.listToAttrs [ { name = \"a\"; value = 1; } { name = \"a\"; } ]).a")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let f = builtins.listToAttrs; in (f [ { name = \"a\"; value = 1; } ]).a").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval(
            "(builtins.listToAttrs [
               (builtins.foldl' (acc: _x: acc) { name = \"a\"; value = 1; } [])
             ]).a"
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
            eval("let builtins = { listToAttrs = list: { local = true; }; }; in (builtins.listToAttrs []).local")
                .as_bool(),
            Ok(true)
        );

    let ir = lower("builtins.listToAttrs [ { name = \"a\"; value = 1 / 0; } ]");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_primop(ir.root, &root)
        .expect("listToAttrs primop evaluates");
    let attrs = evaluator
        .heap
        .get_attrs(value)
        .expect("listToAttrs result is attrs");
    let entry = attrs
        .iter_lexicographic()
        .next()
        .expect("listToAttrs result has one attr");
    assert_eq!(ir.symbols.resolve(entry.key), Some(b"a".as_slice()));
    let value = entry.value;
    assert_eq!(value.tag(), ValueTag::Thunk);
    let thunk = evaluator
        .heap
        .get_thunk(value)
        .expect("attribute value remains a heap-owned thunk");
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
fn list_to_attrs_primop_type_checks_list_elements_and_names() {
    let ir = lower("builtins.listToAttrs 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("listToAttrs requires a list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.listToAttrs [ 1 ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("listToAttrs requires element attrsets");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.listToAttrs [ { name = 1; value = 2; } ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("listToAttrs requires string names");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn list_to_attrs_primop_reports_missing_name_value_pairs() {
    let ir = lower("builtins.listToAttrs [ {} ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("listToAttrs requires a name attribute");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing name attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(evaluator.symbols.resolve(symbol), Some(b"name".as_slice()));

    let ir = lower("builtins.listToAttrs [ { name = \"a\"; } ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("listToAttrs requires a value attribute");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing value attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(evaluator.symbols.resolve(symbol), Some(b"value".as_slice()));
}
