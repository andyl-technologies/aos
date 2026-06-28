//! Tree-walk evaluator tests: builtins list 3.

use super::*;

#[test]
fn all_and_any_primops_check_predicate_then_list_then_result() {
    let ir = lower("builtins.all (1 / 0) []");
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

    let error = eval_whnf(&ir).expect_err("all forces predicate before empty list result");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: predicate }
    );
    assert_eq!(error.span(), predicate_span);

    let ir = lower("builtins.any 1 []");
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

    let error = eval_whnf(&ir).expect_err("any requires a predicate function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: predicate,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), predicate_span);

    let error = eval_whnf_owned(&lower(
        "let a = builtins.all; in a (builtins.throw \"predicate\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class all forces predicate before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"predicate");

    let error = eval_whnf_owned(&lower(
        "let a = builtins.any; in a (builtins.throw \"predicate\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class any forces predicate before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"predicate");

    let error = eval_whnf_owned(&lower("let a = builtins.any; in a (x: false) 1"))
        .expect_err("first-class any requires a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.all (x: true) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf(&ir).expect_err("all requires a list after checking predicate");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    for source in [
        "builtins.all (x: 1) [ \"a\" ]",
        "builtins.any (x: 1) [ \"a\" ]",
    ] {
        let ir = lower(source);
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

        let error = eval_whnf(&ir).expect_err("predicate result must be bool");

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
}

#[test]
fn concat_map_primop_concatenates_mapped_lists_without_forcing_elements() {
    assert_eq!(
        eval("builtins.length (builtins.concatMap (x: [ x x ]) [ 1 2 ])").as_int(),
        Ok(4)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.concatMap (x: [ x x ]) [ 1 2 ]) 0").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.concatMap (x: [ x x ]) [ 1 2 ]) 3").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.length (builtins.concatMap (x: []) [ (1 / 0) ])").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("builtins.length (builtins.concatMap (x: [ (1 / 0) ]) [ 1 ])").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval(
            "builtins.elemAt (builtins.concatMap builtins.attrValues [ { a = 1; } { b = 2; } ]) 1"
        )
        .as_int(),
        Ok(2)
    );
    assert_eq!(
            eval("builtins.length (let f = builtins.concatMap; in f builtins.attrValues [ { a = 1; } { b = 2; } ])")
                .as_int(),
            Ok(2)
        );
    assert_eq!(
        eval("let f = x: []; xs = [ (1 / 0) ]; in builtins.length (builtins.concatMap f xs)")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
            eval("let builtins = { concatMap = f: list: [ 42 ]; }; in builtins.concatMap (x: []) [] == [ 42 ]")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn concat_map_primop_checks_function_then_list_then_results() {
    let ir = lower("builtins.concatMap (1 / 0) []");
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

    let error = eval_whnf_owned(&ir).expect_err("concatMap forces function before list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: function }
    );
    assert_eq!(error.span(), function_span);

    let ir = lower("builtins.concatMap 1 []");
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

    let error = eval_whnf_owned(&ir).expect_err("concatMap requires a function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);

    let error = eval_whnf_owned(&lower(
        "let f = builtins.concatMap; in f (builtins.throw \"function\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class concatMap forces function before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"function");

    let error = eval_whnf_owned(&lower("let f = builtins.concatMap; in f (x: [ x ]) 1"))
        .expect_err("first-class concatMap requires a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("let f = builtins.concatMap; in f (x: 1) [ \"a\" ]"))
        .expect_err("first-class concatMap requires list results");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.concatMap (x: [ x ]) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("concatMap checks list after function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.concatMap (x: 1) [ \"a\" ]");
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

    let error = eval_whnf_owned(&ir).expect_err("concatMap requires list results");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);
}

#[test]
fn group_by_primop_groups_by_string_key_without_forcing_elements() {
    assert_eq!(
        eval_list_string_bytes(
            "builtins.attrNames (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ])"
        ),
        vec![b"big".to_vec(), b"small".to_vec()]
    );
    assert_eq!(
            eval("builtins.length (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ]).small")
                .as_int(),
            Ok(2)
        );
    assert_eq!(
            eval("builtins.elemAt (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ]).small 0")
                .as_int(),
            Ok(1)
        );
    assert_eq!(
            eval("builtins.elemAt (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ]).big 0")
                .as_int(),
            Ok(3)
        );
    assert_eq!(
        eval("builtins.length (builtins.groupBy builtins.typeOf [ 1 \"x\" 2 ]).int").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval(
            "builtins.length (let f = builtins.groupBy; in f builtins.typeOf [ 1 \"x\" 2 ]).string"
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.length (builtins.groupBy (x: \"k\") [ (1 / 0) ]).k").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let f = x: \"k\"; xs = [ (1 / 0) ]; in builtins.length (builtins.groupBy f xs).k")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let g = builtins.groupBy; in builtins.length (g (x: \"k\") [ (1 / 0) ]).k").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.groupBy (x: x) [ \"b\" \"a\" \"b\" ]).b 1 == \"b\"")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
            eval("let builtins = { groupBy = f: list: { local = [ 42 ]; }; }; in builtins.groupBy (x: \"k\") [] == { local = [ 42 ]; }")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn group_by_primop_checks_function_then_list_then_key_results() {
    let ir = lower("builtins.groupBy (1 / 0) []");
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

    let error = eval_whnf_owned(&ir).expect_err("groupBy forces function before list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: function }
    );
    assert_eq!(error.span(), function_span);

    let ir = lower("builtins.groupBy 1 []");
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

    let error = eval_whnf_owned(&ir).expect_err("groupBy requires a function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);

    let error = eval_whnf_owned(&lower(
        "let f = builtins.groupBy; in f (builtins.throw \"function\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class groupBy forces function before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"function");

    let error = eval_whnf_owned(&lower("let f = builtins.groupBy; in f (x: \"k\") 1"))
        .expect_err("first-class groupBy requires a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("let f = builtins.groupBy; in f (x: 1) [ \"a\" ]"))
        .expect_err("first-class groupBy requires string keys");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.groupBy (x: \"k\") 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("groupBy checks list after function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.groupBy (x: 1) [ \"a\" ]");
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

    let error = eval_whnf_owned(&ir).expect_err("groupBy requires string keys");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);
}

#[test]
fn generic_closure_primop_computes_discovery_order_closure() {
    let source = r#"builtins.genericClosure {
            startSet = [
              { key = 1; value = "one"; }
              { key = 2; value = "two"; }
            ];
            operator = item:
              if item.key == 1 then [ { key = 3; value = "three"; } ]
              else if item.key == 2 then [ { key = 4; value = "four"; } ]
              else [];
        }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"[{"key":1,"value":"one"},{"key":2,"value":"two"},{"key":3,"value":"three"},{"key":4,"value":"four"}]"#.to_vec()
        );
    assert_eq!(
        eval(
            r#"builtins.length (builtins.genericClosure {
                 startSet = [
                   (builtins.foldl' (acc: _x: acc) { key = "root"; } [])
                 ];
                 operator = item: [];
               })"#
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval(
            r#"builtins.length (builtins.genericClosure (
                 builtins.foldl' (acc: _x: acc) {
                   startSet = [ { key = "root"; } ];
                   operator = item: [];
                 } []
               ))"#
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
            eval_json_bytes(
                r#"let f = builtins.genericClosure; in f {
                    startSet = [ { key = 1; value = "start"; } ];
                    operator = item:
                      if item.key == 1 then [
                        { key = 2; value = "two"; }
                        { key = 3; value = "three"; }
                      ]
                      else if item.key == 2 then [ { key = 4; value = "four"; } ]
                      else if item.key == 3 then [ { key = 5; value = "five"; } ]
                      else [];
                }"#
            ),
            br#"[{"key":1,"value":"start"},{"key":2,"value":"two"},{"key":3,"value":"three"},{"key":4,"value":"four"},{"key":5,"value":"five"}]"#.to_vec()
        );
}

#[test]
fn generic_closure_primop_keeps_first_item_for_duplicate_keys() {
    assert_eq!(
        eval_json_bytes(
            r#"builtins.genericClosure {
                    startSet = [
                      { key = 1; value = "first"; }
                      { key = 1; value = "second"; }
                      { key = 2; value = "third"; }
                    ];
                    operator = item: [];
                }"#
        ),
        br#"[{"key":1,"value":"first"},{"key":2,"value":"third"}]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(
            r#"builtins.genericClosure {
                    startSet = [ { key = [ 1 2 ]; value = "start"; } ];
                    operator = item: [
                      { key = [ 1 2 ]; value = "duplicate"; }
                      { key = [ 1 3 ]; value = "next"; }
                    ];
                }"#
        ),
        br#"[{"key":[1,2],"value":"start"},{"key":[1,3],"value":"next"}]"#.to_vec()
    );

    let dir = unique_temp_dir("generic-closure-path-keys");
    let first_path = dir.join("first.txt");
    let second_path = dir.join("second.txt");
    fs::write(&first_path, b"first").expect("first temp file writes");
    fs::write(&second_path, b"second").expect("second temp file writes");
    let first_path = path_source(&first_path);
    let second_path = path_source(&second_path);
    let source = format!(
        r#"builtins.map (item: item.value) (builtins.genericClosure {{
                startSet = [
                  {{ key = {first_path}; value = "first"; }}
                  {{ key = {first_path}; value = "duplicate"; }}
                  {{ key = {second_path}; value = "second"; }}
                ];
                operator = item: [];
            }})"#
    );
    assert_eq!(eval_json_bytes(&source), br#"["first","second"]"#.to_vec());
}

#[test]
fn generic_closure_primop_does_not_force_operator_for_empty_start_set() {
    assert_eq!(
        eval("builtins.length (builtins.genericClosure { startSet = []; })").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("builtins.length (builtins.genericClosure { startSet = []; operator = 1; })").as_int(),
        Ok(0)
    );
}

#[test]
fn generic_closure_primop_checks_start_items_operator_and_results() {
    let error = eval_whnf_owned(&lower("builtins.genericClosure 1"))
        .expect_err("genericClosure requires an attrset");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("builtins.genericClosure { operator = item: []; }"))
        .expect_err("genericClosure requires startSet");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = 1; operator = item: []; }",
    ))
    .expect_err("genericClosure startSet must be a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ 1 ]; operator = 1; }",
    ))
    .expect_err("genericClosure checks nonempty operator before start items");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ 1 ]; operator = item: []; }",
    ))
    .expect_err("genericClosure start items must be attrsets");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.genericClosure {
                startSet = [ { value = "missing"; } ];
                operator = item: [];
            }"#,
    ))
    .expect_err("genericClosure items require key attributes");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ { key = 1; } ]; }",
    ))
    .expect_err("genericClosure requires operator after nonempty startSet");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ { key = 1; } ]; operator = 1; }",
    ))
    .expect_err("genericClosure operator must be a function");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ { key = 1; } ]; operator = item: 1; }",
    ))
    .expect_err("genericClosure operator must return lists");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ { key = 1; } ]; operator = item: [ 2 ]; }",
    ))
    .expect_err("genericClosure generated items must be attrsets");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.genericClosure {
                startSet = [
                  { key = { a = 1; }; value = "first"; }
                  { key = { a = 1; }; value = "second"; }
                ];
                operator = item: [];
            }"#,
    ))
    .expect_err("genericClosure rejects incomparable duplicate keys");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "number, string, path, or list",
            actual: ValueTag::Attrs,
            ..
        }
    ));
}

#[test]
fn generic_closure_primop_checks_generated_keys_when_popped() {
    let error = eval_whnf_owned(&lower(
        r#"builtins.genericClosure {
                startSet = [ { key = 1; } ];
                operator = item:
                  if item.key == 1 then [
                    { key = 2; }
                    { value = "missing"; }
                  ]
                  else if item.key == 2 then builtins.throw "visited two"
                  else [];
            }"#,
    ))
    .expect_err("generated key validation waits until work item is popped");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected generated work item to run before later missing key");
    };
    assert_eq!(message, b"visited two");
}

#[test]
fn gen_list_primop_builds_lazy_indexed_elements() {
    assert_eq!(
        eval("builtins.length (builtins.genList (x: builtins.throw \"generated\") 2)").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.genList (x: x * x) 5) 4").as_int(),
        Ok(16)
    );
    assert_eq!(
        eval_string_bytes("builtins.concatStringsSep \",\" (builtins.genList builtins.toString 3)"),
        b"0,1,2"
    );
    assert_eq!(
        eval("let g = builtins.genList; in builtins.elemAt (g (x: x + 1) 2) 1").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let n = 2; f = x: x + 1; in builtins.elemAt (builtins.genList f n) 1").as_int(),
        Ok(2)
    );

    let error = eval_whnf_owned(&lower(
        "builtins.elemAt (builtins.genList (x: builtins.throw \"generated\") 2) 0",
    ))
    .expect_err("generated element is forced only when selected");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"generated");
}

#[test]
fn gen_list_primop_checks_length_before_generator() {
    let ir = lower("builtins.genList (builtins.throw \"function\") (builtins.throw \"length\")");

    let error = eval_whnf_owned(&ir).expect_err("genList forces length before generator");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"length");

    let error = eval_whnf_owned(&lower(
        "let g = builtins.genList; in g (builtins.throw \"function\") (builtins.throw \"length\")",
    ))
    .expect_err("first-class genList forces length before generator");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"length");

    let ir = lower("builtins.genList 1 0");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let generator = args[0];
    let generator_span = ir
        .arena
        .node(generator)
        .expect("generator argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("genList checks generator after length");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: generator,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), generator_span);

    let error = eval_whnf_owned(&lower(
        "builtins.length (builtins.genList (builtins.throw \"function\") 0)",
    ))
    .expect_err("genList checks generator even for empty results");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"function");

    let ir = lower("builtins.genList (x: x) 1.2");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let length = args[1];
    let length_span = ir.arena.node(length).expect("length argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("genList length must be an integer");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: length,
            expected: "int",
            actual: ValueTag::Float,
        }
    );
    assert_eq!(error.span(), length_span);

    let ir = lower("builtins.genList (x: x) (-1)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let length = args[1];
    let length_span = ir.arena.node(length).expect("length argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("genList rejects negative lengths");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::NegativeListLength {
            id: length,
            length: -1
        }
    );
    assert_eq!(error.span(), length_span);
}

#[test]
fn map_primop_builds_lazy_mapped_elements() {
    assert_eq!(
        eval("builtins.length (builtins.map (x: x + 1) [ 1 2 ])").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.map (x: x + 1) [ 1 2 ]) 0").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.map (x: x + 1) [ 1 2 ]) 1").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.concatStringsSep \",\" (builtins.map builtins.toString [ 1 true null ])"
        ),
        b"1,1,"
    );
    assert_eq!(
        eval("let m = builtins.map; in builtins.elemAt (m (x: x + 1) [ 1 ]) 0").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let xs = []; in builtins.length (builtins.map (builtins.throw \"function\") xs)")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("let f = x: x + 1; xs = [ 1 ]; in builtins.elemAt (builtins.map f xs) 0").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.length (builtins.map (x: builtins.throw \"mapped\") [ 1 ])").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.length (builtins.map (x: x) [ (builtins.throw \"element\") ])").as_int(),
        Ok(1)
    );

    let error = eval_whnf_owned(&lower(
        "builtins.elemAt (builtins.map (x: builtins.throw \"mapped\") [ 1 ]) 0",
    ))
    .expect_err("mapped element is forced only when selected");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"mapped");

    let error = eval_whnf_owned(&lower(
        "builtins.elemAt (builtins.map (x: x) [ (builtins.throw \"element\") ]) 0",
    ))
    .expect_err("source element thunk is still lazy until selected");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"element");
}
