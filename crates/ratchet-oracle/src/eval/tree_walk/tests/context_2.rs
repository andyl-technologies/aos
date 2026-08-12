//! Tree-walk evaluator tests: context 2.

use super::*;

#[test]
fn intersect_attrs_primop_takes_names_from_left_and_values_from_right() {
    assert_eq!(
        eval_list_string_bytes(
            "builtins.attrNames (builtins.intersectAttrs { z = 1; a = 1 / 0; b = 3; } { z = 4; a = 5; c = 6; })"
        ),
        vec![b"a".to_vec(), b"z".to_vec()]
    );
    assert_eq!(
        eval("let r = builtins.intersectAttrs { a = 1 / 0; } { a = 2; }; in r.a").as_int(),
        Ok(2)
    );
    assert_eq!(
            eval("let builtins = { intersectAttrs = left: right: { local = true; }; }; in (builtins.intersectAttrs {} {}).local")
                .as_bool(),
            Ok(true)
        );

    let ir = lower("builtins.intersectAttrs { a = 1; } { a = 1 / 0; }");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_primop(ir.root, &root)
        .expect("intersectAttrs primop evaluates");
    let attrs = evaluator
        .heap
        .get_attrs(value)
        .expect("intersectAttrs result is attrs");
    let entry = attrs
        .iter_lexicographic()
        .next()
        .expect("intersectAttrs result has one attr");
    assert_eq!(ir.symbols.resolve(entry.key), Some(b"a".as_slice()));
    let value = entry.value;
    assert_eq!(value.tag(), ValueTag::Thunk);
    let thunk = evaluator
        .heap
        .get_thunk(value)
        .expect("selected right value remains a heap-owned thunk");
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
fn intersect_attrs_primop_type_checks_arguments_in_order() {
    let ir = lower("builtins.intersectAttrs 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let left = args[0];
    let left_span = ir.arena.node(left).expect("left argument exists").span;

    let error = eval_whnf(&ir).expect_err("intersectAttrs checks the left set first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: left,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), left_span);

    let ir = lower("builtins.intersectAttrs {} 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let right = args[1];
    let right_span = ir.arena.node(right).expect("right argument exists").span;

    let error = eval_whnf(&ir).expect_err("intersectAttrs requires a right attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: right,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), right_span);
}

#[test]
fn cat_attrs_primop_collects_present_attrs_in_list_order() {
    let outcome = eval_whnf_owned(&lower(
        "builtins.catAttrs \"a\" [ { a = 1; } { b = 1 / 0; } { a = 2; } ]",
    ))
    .expect("catAttrs evaluates");
    let list = outcome
        .heap()
        .get_list(outcome.value())
        .expect("catAttrs returns a list");

    assert_eq!(list.len(), 2);
    assert_eq!(list.get(0).expect("first").as_int(), Ok(1));
    assert_eq!(list.get(1).expect("second").as_int(), Ok(2));
    let shadowed = eval_whnf_owned(&lower(
        "let builtins = { catAttrs = name: list: [ true ]; }; in builtins.catAttrs \"a\" []",
    ))
    .expect("shadowed catAttrs evaluates");
    let shadowed_list = shadowed
        .heap()
        .get_list(shadowed.value())
        .expect("shadowed catAttrs returns a list");
    assert_eq!(
        shadowed_list.get(0).expect("first local value").as_bool(),
        Ok(true)
    );

    let ir = lower("builtins.catAttrs \"a\" [ { a = 1 / 0; } { b = 2; } ]");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_primop(ir.root, &root)
        .expect("catAttrs primop evaluates");
    let list = evaluator
        .heap
        .get_list(value)
        .expect("catAttrs returns a heap-owned list");
    assert_eq!(list.len(), 1);
    let value = list.get(0).expect("selected attr exists");
    assert_eq!(value.tag(), ValueTag::Thunk);
    let thunk = evaluator
        .heap
        .get_thunk(value)
        .expect("selected attr value remains a heap-owned thunk");
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
fn cat_attrs_primop_type_checks_arguments_and_elements_in_order() {
    let ir = lower("builtins.catAttrs 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let name = args[0];
    let name_span = ir.arena.node(name).expect("name argument exists").span;

    let error = eval_whnf(&ir).expect_err("catAttrs checks the name before the list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: name,
            expected: "string",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), name_span);

    let ir = lower("builtins.catAttrs \"a\" 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf(&ir).expect_err("catAttrs requires a list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.catAttrs \"a\" [ 1 ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("catAttrs requires attrset elements");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), list_span);
}

#[test]
fn ceil_and_floor_primops_round_numbers_to_ints() {
    assert_eq!(eval("builtins.ceil 1").as_int(), Ok(1));
    assert_eq!(eval("builtins.ceil 1.2").as_int(), Ok(2));
    assert_eq!(eval("builtins.ceil (-1.2)").as_int(), Ok(-1));
    assert_eq!(eval("builtins.floor 1").as_int(), Ok(1));
    assert_eq!(eval("builtins.floor 1.8").as_int(), Ok(1));
    assert_eq!(eval("builtins.floor (-1.2)").as_int(), Ok(-2));
    assert_eq!(
        eval("let builtins = { ceil = x: 42; }; in builtins.ceil 1.2").as_int(),
        Ok(42)
    );
    assert_eq!(
        eval("let builtins = { floor = x: 42; }; in builtins.floor 1.8").as_int(),
        Ok(42)
    );
}

#[test]
fn ceil_and_floor_primops_type_check_arguments() {
    for source in ["builtins.ceil true", "builtins.floor true"] {
        let ir = lower(source);
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("rounding requires a number");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "number",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), argument_span);
    }
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn ceil_and_floor_primops_saturate_int_range_boundaries() {
    for source in [
        "builtins.ceil 9223372036854775807.0",
        "builtins.ceil 9223372036854775808.0",
        "builtins.floor 9223372036854775807.0",
        "builtins.floor 9223372036854775808.0",
    ] {
        assert_eq!(eval(source).as_int(), Ok(i64::MAX));
    }
}

#[test]
fn seq_primop_forces_first_to_whnf_and_returns_second() {
    assert_eq!(eval("builtins.seq { x = 1 / 0; } 2").as_int(), Ok(2));
    assert_eq!(
        eval("builtins.length (builtins.seq 1 [ (1 / 0) ])").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let builtins = { seq = first: second: 42; }; in builtins.seq (1 / 0) 0").as_int(),
        Ok(42)
    );
}

#[test]
fn seq_primop_reports_forcing_errors_left_to_right() {
    let ir = lower("builtins.seq (1 / 0) 2");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let first = args[0];
    let first_span = ir.arena.node(first).expect("first argument exists").span;

    let error = eval_whnf(&ir).expect_err("seq forces first argument first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: first }
    );
    assert_eq!(error.span(), first_span);

    let ir = lower("builtins.seq 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let second = args[1];
    let IrData::Node(second_body) = ir.arena.node(second).expect("second argument exists").data
    else {
        panic!("second argument is a thunk allocation");
    };
    let second_span = ir
        .arena
        .node(second_body)
        .expect("second thunk body exists")
        .span;

    let error = eval_whnf(&ir).expect_err("seq returns and demands second argument");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: second_body }
    );
    assert_eq!(error.span(), second_span);
}

#[test]
fn deep_seq_primop_forces_nested_values_and_returns_second() {
    assert_eq!(eval("builtins.deepSeq [ 1 [ 2 ] ] 3").as_int(), Ok(3));
    assert_eq!(
        eval("builtins.deepSeq { a = { b = 1; }; } 3").as_int(),
        Ok(3)
    );
    assert_eq!(eval("builtins.deepSeq (x: x) 3").as_int(), Ok(3));
    assert_eq!(
        eval("let x = { a = x; }; in builtins.deepSeq x 3").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("let x = [ x ]; in builtins.deepSeq x 3").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("let builtins = { deepSeq = first: second: 42; }; in builtins.deepSeq [ (1 / 0) ] 0")
            .as_int(),
        Ok(42)
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn deep_seq_primop_preserves_transient_roots_under_gc_stress() {
    let ir = lower("builtins.deepSeq [ (x: x) (y: y) ] 3");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress deepSeq evaluates list children");

    assert_eq!(outcome.value().as_int(), Ok(3));

    let ir = lower("builtins.deepSeq { a = x: x; b = y: y; } 3");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress deepSeq evaluates attrset values");

    assert_eq!(outcome.value().as_int(), Ok(3));

    let ir = lower("let x = [ (y: y) x ]; in builtins.deepSeq x 3");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress deepSeq preserves recursive list identity");

    assert_eq!(outcome.value().as_int(), Ok(3));

    let ir = lower("let x = { f = y: y; self = x; }; in builtins.deepSeq x 3");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress deepSeq preserves recursive attrset identity");

    assert_eq!(outcome.value().as_int(), Ok(3));
}

#[test]
fn deep_seq_primop_reports_nested_forcing_errors_before_second() {
    let ir = lower("builtins.deepSeq [ (1 / 0) ] (2 / 0)");
    let error = eval_whnf(&ir).expect_err("deepSeq forces list elements first");
    let TreeWalkErrorKind::DivisionByZero { id: first } = error.kind() else {
        panic!("expected first list element division by zero");
    };
    let first_span = ir.arena.node(first).expect("first error node exists").span;
    assert_eq!(error.span(), first_span);

    let ir = lower("builtins.deepSeq { a = 1 / 0; } 2");
    let error = eval_whnf(&ir).expect_err("deepSeq forces attr values");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let source = "builtins.deepSeq { z = 1 / 0; a = 2 / 0; } 1";
    let ir = lower(source);
    let error = eval_whnf(&ir).expect_err("deepSeq forces attr values in source order");
    let z_error_start = source.find("1 / 0").expect("z error expression exists") as u32;
    assert_eq!(
        error.span(),
        Span::new(z_error_start, z_error_start + "1 / 0".len() as u32)
    );

    let ir = lower("builtins.deepSeq [ 1 ] (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let second = args[1];
    let IrData::Node(second_body) = ir.arena.node(second).expect("second argument exists").data
    else {
        panic!("second argument is a thunk allocation");
    };
    let second_span = ir
        .arena
        .node(second_body)
        .expect("second thunk body exists")
        .span;

    let error = eval_whnf(&ir).expect_err("deepSeq returns and demands second argument");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: second_body }
    );
    assert_eq!(error.span(), second_span);
}

#[test]
fn has_context_primop_reports_string_context_presence() {
    assert_eq!(eval("builtins.hasContext \"x\"").as_bool(), Ok(false));
    assert_eq!(
        eval("let builtins = { hasContext = x: true; }; in builtins.hasContext \"x\"").as_bool(),
        Ok(true)
    );

    let ir = lower("builtins.hasContext \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("hasContext argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"x".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    assert_eq!(
        evaluator
            .eval_has_context_primop(argument, argument_span, value)
            .expect("hasContext evaluates")
            .as_bool(),
        Ok(true)
    );
}

#[test]
fn has_context_primop_type_checks_argument() {
    let ir = lower("builtins.hasContext 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("hasContext requires a string");

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
fn get_context_primop_reflects_sparse_context_attrs() {
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames (builtins.getContext \"x\")"),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
            eval("let builtins = { getContext = x: { local = true; }; }; in (builtins.getContext \"x\").local")
                .as_bool(),
            Ok(true)
        );

    let ir = lower("builtins.getContext \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("getContext argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source_path = b"/nix/store/source";
    let drv_path = b"/nix/store/derivation.drv";
    let deep_path = b"/nix/store/deep.drv";
    let context = StringContext::new(vec![
        ContextElement::single_output(drv_path.to_vec(), b"out".to_vec())
            .expect("output context is valid"),
        ContextElement::opaque_path(source_path.to_vec()).expect("source context is valid"),
        ContextElement::deep_derivation(deep_path.to_vec()).expect("deep context is valid"),
        ContextElement::single_output(drv_path.to_vec(), b"dev".to_vec())
            .expect("output context is valid"),
    ]);
    let value = evaluator
        .heap
        .alloc_string(NixString::new(b"x".to_vec(), context))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_get_context_primop(ir.root, root.span, argument, argument_span, value)
        .expect("getContext evaluates");

    let source_key = evaluator
        .symbols
        .intern(source_path)
        .expect("source key interns");
    let drv_key = evaluator.symbols.intern(drv_path).expect("drv key interns");
    let deep_key = evaluator
        .symbols
        .intern(deep_path)
        .expect("deep key interns");
    let path_key = evaluator.symbols.intern(b"path").expect("path key interns");
    let outputs_key = evaluator
        .symbols
        .intern(b"outputs")
        .expect("outputs key interns");
    let all_outputs_key = evaluator
        .symbols
        .intern(b"allOutputs")
        .expect("allOutputs key interns");
    let top = evaluator
        .heap
        .get_attrs(result)
        .expect("getContext returns attrs");

    let source = evaluator
        .heap
        .get_attrs(top.get(source_key).expect("source context exists"))
        .expect("source context value is attrs");
    assert_eq!(
        source
            .get(path_key)
            .expect("opaque path marker exists")
            .as_bool(),
        Ok(true)
    );
    assert!(source.get(outputs_key).is_none());
    assert!(source.get(all_outputs_key).is_none());

    let drv = evaluator
        .heap
        .get_attrs(top.get(drv_key).expect("drv context exists"))
        .expect("drv context value is attrs");
    assert!(drv.get(path_key).is_none());
    assert!(drv.get(all_outputs_key).is_none());
    let outputs = evaluator
        .heap
        .get_list(drv.get(outputs_key).expect("outputs marker exists"))
        .expect("outputs marker is a list");
    assert_eq!(outputs.len(), 2);
    assert_eq!(
        evaluator
            .heap
            .get_string(outputs.get(0).expect("first output"))
            .expect("first output is a string")
            .bytes(),
        b"dev"
    );
    assert_eq!(
        evaluator
            .heap
            .get_string(outputs.get(1).expect("second output"))
            .expect("second output is a string")
            .bytes(),
        b"out"
    );

    let deep = evaluator
        .heap
        .get_attrs(top.get(deep_key).expect("deep context exists"))
        .expect("deep context value is attrs");
    assert!(deep.get(path_key).is_none());
    assert!(deep.get(outputs_key).is_none());
    assert_eq!(
        deep.get(all_outputs_key)
            .expect("deep marker exists")
            .as_bool(),
        Ok(true)
    );
}

#[test]
fn get_context_primop_type_checks_argument() {
    let ir = lower("builtins.getContext 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("getContext requires a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn append_context_primop_round_trips_reflected_context() {
    assert_eq!(
            eval_json_bytes(
                r#"builtins.getContext (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = {
                        allOutputs = true;
                        outputs = [ "out" "dev" "" "out" ];
                    };
                })"#
            ),
            br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv":{"allOutputs":true,"outputs":["","dev","out"]}}"#.to_vec()
        );
    assert_eq!(
        eval(
            r#"let append = builtins.appendContext "x"; in
                   builtins.hasContext (append {
                     "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                   })"#
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(
            r#"builtins.hasContext (
                   builtins.appendContext "x"
                     (builtins.foldl' (acc: _x: acc) {
                       "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                     } [])
                 )"#
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(
            r#"builtins.hasContext (
                   builtins.appendContext "x" {
                     "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" =
                       builtins.foldl' (acc: _x: acc) { path = true; } [];
                   }
                 )"#
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_string_bytes(
            r#"let builtins = { appendContext = string: context: "shadow"; };
                   in builtins.appendContext "x" {}"#
        ),
        b"shadow"
    );
}

#[test]
fn append_context_primop_unions_context_and_ignores_false_unknown_markers() {
    assert_eq!(
            eval_json_bytes(
                r#"builtins.getContext (
                    builtins.appendContext
                      (builtins.appendContext "x" {
                        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                      })
                      {
                        "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other" = {
                          path = true;
                          extra = 1 / 0;
                        };
                        "/nix/store/cccccccccccccccccccccccccccccccc-empty" = {
                          path = false;
                          allOutputs = false;
                          outputs = [];
                          extra = 1 / 0;
                        };
                      }
                  )"#
            ),
            br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other":{"path":true}}"#.to_vec()
        );
}

#[test]
fn append_context_primop_forcing_order_matches_cpp_nix() {
    let error = eval_whnf_owned(&lower(r#"builtins.appendContext 1 (throw "boom")"#))
        .expect_err("appendContext checks first argument before context argument");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"let f = builtins.appendContext 1; in f (builtins.throw "boom")"#,
    ))
    .expect_err("curried appendContext checks first argument before context argument");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.appendContext "x" {
                "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-z" = builtins.throw "z";
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a" = builtins.throw "a";
            }"#,
    ))
    .expect_err("appendContext forces reflected entries in source order");
    assert!(
        matches!(
            error.kind(),
            TreeWalkErrorKind::Thrown {
                message,
                ..
            } if message.as_slice() == b"z"
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn append_context_primop_rejects_invalid_reflected_contexts() {
    let error = eval_whnf_owned(&lower("builtins.appendContext 1 {}"))
        .expect_err("appendContext requires a string first argument");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(r#"builtins.appendContext { outPath = "abc"; } {}"#))
        .expect_err("appendContext does not coerce attrsets for its first argument");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Attrs,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(r#"builtins.appendContext "x" 1"#))
        .expect_err("appendContext requires reflected context attrs");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    for path in [
        "not-a-store-path",
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src/child",
        "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-src",
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bad name",
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-.",
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-..",
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let source = format!(r#"builtins.appendContext "x" {{ "{path}" = {{ path = true; }}; }}"#);
        let error = eval_whnf_owned(&lower(&source))
            .expect_err("appendContext rejects invalid reflected context keys");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::StringContextKeyNotStorePath { .. }
            ),
            "unexpected error for {path}: {error:?}"
        );
    }

    let error = eval_whnf_owned(&lower(
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = 1;
            }"#,
    ))
    .expect_err("reflected context entries must be attrs");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = 1; };
            }"#,
    ))
    .expect_err("path marker must be a bool");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { allOutputs = 1; };
            }"#,
    ))
    .expect_err("allOutputs marker must be a bool");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { outputs = 1; };
            }"#,
    ))
    .expect_err("outputs marker must be a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { outputs = [ (1 / 0) ]; };
            }"#,
    ))
    .expect_err("non-empty outputs require a derivation path before forcing outputs");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextPathNotDerivation { .. }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { allOutputs = true; };
            }"#,
    ))
    .expect_err("allOutputs requires a derivation path");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextPathNotDerivation { .. }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.appendContext "x" {
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = { outputs = [ 1 ]; };
            }"#,
    ))
    .expect_err("output names must be strings");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.appendContext "x" {
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = {
                    outputs = [
                      (builtins.appendContext "out" {
                        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                      })
                    ];
                };
            }"#,
    ))
    .expect_err("output names must not carry string context");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "appendContext",
            ..
        }
    ));
}
