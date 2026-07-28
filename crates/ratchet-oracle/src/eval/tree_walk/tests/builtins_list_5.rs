//! Tree-walk evaluator tests: builtins list 5.

use super::*;

#[test]
fn string_comparisons_use_bytes_not_contexts() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::new(&ir);
    let node = *ir.arena.node(ir.root).expect("root exists");
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let output =
        ContextElement::single_output(b"/nix/store/derivation.drv".to_vec(), b"out".to_vec())
            .expect("output context is valid");
    let left = evaluator
        .heap
        .alloc_string(NixString::new(
            b"same".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("left string allocates");
    let right = evaluator
        .heap
        .alloc_string(NixString::new(
            b"same".to_vec(),
            StringContext::singleton(output).expect("output context allocates"),
        ))
        .expect("right string allocates");

    assert_eq!(
        evaluator
            .compare_strings(ir.root, &node, ComparisonOp::Le, left, right)
            .expect("strings compare")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
        evaluator
            .compare_strings(ir.root, &node, ComparisonOp::Ge, left, right)
            .expect("strings compare")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
        evaluator
            .compare_strings(ir.root, &node, ComparisonOp::Lt, left, right)
            .expect("strings compare")
            .as_bool(),
        Ok(false)
    );
}

#[test]
fn list_comparisons_are_lexicographic() {
    assert_eq!(eval("[1 2] < [1 3]").as_bool(), Ok(true));
    assert_eq!(eval("[1 3] > [1 2]").as_bool(), Ok(true));
    assert_eq!(eval("[1 2] <= [1 2]").as_bool(), Ok(true));
    assert_eq!(eval("[1 2] >= [1 3]").as_bool(), Ok(false));
    assert_eq!(eval("[1] < [1 0]").as_bool(), Ok(true));
    assert_eq!(eval("[1 0] > [1]").as_bool(), Ok(true));
    assert_eq!(eval("[] < [0]").as_bool(), Ok(true));
    assert_eq!(eval("[1 \"a\"] < [1 \"b\"]").as_bool(), Ok(true));
    assert_eq!(eval("[[1 2]] < [[1 3]]").as_bool(), Ok(true));
    assert_eq!(
        eval("let f = x: x; prefix = [ f ]; in (prefix ++ [ 1 ]) < (prefix ++ [ 2 ])").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in [ nan 1 ] < [ nan 2 ]")
            .as_bool(),
        Ok(true)
    );
}

#[test]
fn list_comparisons_short_circuit() {
    assert_eq!(eval("[1 (1 / 0)] < [2 (1 / 0)]").as_bool(), Ok(true));
    assert_eq!(eval("[2 (1 / 0)] < [1 (1 / 0)]").as_bool(), Ok(false));

    let ir = lower("[1 (1 / 0)] <= [1 (2 / 0)]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("comparison root has binary payload");
    };
    let right = ir.arena.node(rhs).expect("rhs exists");
    let IrData::Children(right_elements) = right.data else {
        panic!("rhs list has children");
    };
    let right_elements = ir
        .arena
        .child_slice(right_elements)
        .expect("rhs elements exist");
    let throwing_thunk = ir.arena.node(right_elements[1]).expect("thunk exists");
    let IrData::Node(throwing_element) = throwing_thunk.data else {
        panic!("list element is a thunk");
    };
    let throwing_span = ir
        .arena
        .node(throwing_element)
        .expect("throwing element exists")
        .span;

    let error = eval_whnf(&ir).expect_err("equal prefix forces next element");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero {
            id: throwing_element
        }
    );
    assert_eq!(error.span(), throwing_span);
}

#[test]
fn list_comparisons_handle_recursive_container_equality() {
    assert_eq!(eval("let xs = [ xs ]; in xs < xs").as_bool(), Ok(false));
    assert_eq!(eval("let xs = [ xs ]; in xs <= xs").as_bool(), Ok(true));
    assert_eq!(
        eval("let s = rec { a = s; }; in [s] < [s]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("let s = rec { a = s; }; in [s] <= [s]").as_bool(),
        Ok(true)
    );
}

#[test]
fn structural_equality_still_forces_shared_list_elements() {
    let error = eval_whnf(&lower("let xs = [ (1 / 0) ]; in xs == xs"))
        .expect_err("shared throwing list element is forced");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn copied_attrsets_do_not_gain_shared_identity_through_list_equality() {
    assert_eq!(
        eval(r#"let s = { a = builtins.throw "copied child"; }; in [builtins.removeAttrs s []] == [s]"#)
            .as_bool(),
        Ok(false)
    );
}

#[test]
fn list_comparisons_type_check_operands_left_to_right() {
    let rhs_ir = lower("[1] < true");
    let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("comparison root has binary payload");
    };
    let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&rhs_ir).expect_err("boolean rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "list",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), rhs_span);

    let nested_ir = lower("[1] < [\"a\"]");
    let error = eval_whnf_owned(&nested_ir).expect_err("string element is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: nested_ir.root,
            expected: "number",
            actual: ValueTag::String,
        }
    );
    assert_eq!(
        error.span(),
        nested_ir
            .arena
            .node(nested_ir.root)
            .expect("root exists")
            .span
    );

    let lhs_ir = lower("false < [(1 / 0)]");
    let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
    let IrData::Binary { lhs, .. } = root.data else {
        panic!("comparison root has binary payload");
    };
    let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

    let error = eval_whnf(&lhs_ir).expect_err("boolean lhs is invalid before rhs");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: lhs,
            expected: "number, string, path, or list",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), lhs_span);
}

#[test]
fn comparisons_force_operands_before_type_checks() {
    let rhs_ir = lower("1 < true");
    let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("comparison root has binary payload");
    };
    let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&rhs_ir).expect_err("boolean rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "number",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), rhs_span);

    let string_rhs_ir = lower("1 < \"a\"");
    let root = string_rhs_ir
        .arena
        .node(string_rhs_ir.root)
        .expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("comparison root has binary payload");
    };
    let rhs_span = string_rhs_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&string_rhs_ir).expect_err("string rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "number",
            actual: ValueTag::String,
        }
    );
    assert_eq!(error.span(), rhs_span);

    let string_left_ir = lower("\"a\" < true");
    let root = string_left_ir
        .arena
        .node(string_left_ir.root)
        .expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("comparison root has binary payload");
    };
    let rhs_span = string_left_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&string_left_ir).expect_err("boolean rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "string",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), rhs_span);

    let rhs_error_ir = lower("\"a\" < (1 / 0)");
    let root = rhs_error_ir
        .arena
        .node(rhs_error_ir.root)
        .expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("comparison root has binary payload");
    };
    let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);

    let lhs_ir = lower("false < (1 / 0)");
    let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("comparison root has binary payload");
    };
    let rhs_span = lhs_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&lhs_ir).expect_err("rhs evaluation error wins before lhs type");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn comparisons_force_annotated_fold_results() {
    // `lib/lists.nix`'s `findFirstIndex` compares a let-bound strict-fold
    // result. Analysis can preserve that result behind a thunk even though
    // direct scalar operands normally arrive in WHNF.
    let source = r#"let
      pred = x: x == 2;
      resultIndex = builtins.foldl' (
        index: el:
        if index < 0 then
          if pred el then -index - 1 else index - 1
        else
          index
      ) (-1) [ 1 2 3 ];
    in
    if resultIndex < 0 then null else resultIndex"#;
    let mut ir = lower(source);
    crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");

    assert_eq!(
        eval_whnf_owned(&ir)
            .expect("annotated fold result compares")
            .value()
            .as_int(),
        Ok(1),
    );
}

#[test]
fn boolean_binary_operators_short_circuit() {
    assert_eq!(eval("true && true").as_bool(), Ok(true));
    assert_eq!(eval("true && false").as_bool(), Ok(false));
    assert_eq!(eval("false && (1 ++ 2)").as_bool(), Ok(false));

    assert_eq!(eval("true || (1 ++ 2)").as_bool(), Ok(true));
    assert_eq!(eval("false || true").as_bool(), Ok(true));
    assert_eq!(eval("false || false").as_bool(), Ok(false));

    assert_eq!(eval("false -> (1 ++ 2)").as_bool(), Ok(true));
    assert_eq!(eval("true -> true").as_bool(), Ok(true));
    assert_eq!(eval("true -> false").as_bool(), Ok(false));
}

#[test]
fn boolean_binary_operators_type_check_evaluated_rhs() {
    let ir = lower("true && 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("and root has binary payload");
    };
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&ir).expect_err("integer rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "bool",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn malformed_operator_payloads_are_reported() {
    let cases = [
        (IrKind::UnaryOp, "unary payload"),
        (IrKind::BinOp, "binary payload"),
    ];

    for (index, (kind, expected)) in cases.into_iter().enumerate() {
        let root = IrId::new(0);
        let span = Span::new(20 + index as u32, 21 + index as u32);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(kind, span, EffectClass::pure(), IrData::None)],
            Vec::new(),
        );
        let ir = empty_ir(root, arena);
        let error = eval_whnf(&ir).expect_err("malformed operator is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: root,
                kind,
                expected,
            }
        );
        assert_eq!(error.span(), span);
    }
}

#[test]
fn malformed_attr_access_payloads_are_reported() {
    let cases = [
        (IrKind::Select, "select payload"),
        (IrKind::HasAttr, "has-attr payload"),
    ];

    for (index, (kind, expected)) in cases.into_iter().enumerate() {
        let root = IrId::new(0);
        let span = Span::new(30 + index as u32, 31 + index as u32);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(kind, span, EffectClass::pure(), IrData::None)],
            Vec::new(),
        );
        let ir = empty_ir(root, arena);
        let error = eval_whnf(&ir).expect_err("malformed attr access is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: root,
                kind,
                expected,
            }
        );
        assert_eq!(error.span(), span);
    }
}

#[test]
fn assert_evaluates_body_only_when_condition_is_true() {
    assert_eq!(eval("assert true; 5").as_int(), Ok(5));

    let ir = lower("assert false; (1 ++ 2)");
    let lazy_body = eval_whnf(&ir).expect_err("false assertion stops before body");
    assert_eq!(
        lazy_body.kind(),
        TreeWalkErrorKind::AssertionFailed { id: ir.root }
    );
}

#[test]
fn assert_false_reports_assertion_span() {
    let ir = lower("assert false; 1");
    let error = eval_whnf(&ir).expect_err("assertion fails");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::AssertionFailed { id: ir.root }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );
}

#[test]
fn assert_condition_must_be_bool() {
    let ir = lower("assert 1; 2");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Pair { first, .. } = root.data else {
        panic!("assert root has pair payload");
    };
    let condition_span = ir.arena.node(first).expect("condition exists").span;

    let error = eval_whnf(&ir).expect_err("integer condition is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: first,
            expected: "bool",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), condition_span);
}

#[test]
fn malformed_assert_payloads_are_reported() {
    let root = IrId::new(0);
    let span = Span::new(30, 35);
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Assert,
            span,
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let ir = empty_ir(root, arena);
    let error = eval_whnf(&ir).expect_err("malformed assert is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidPayload {
            id: root,
            kind: IrKind::Assert,
            expected: "assert payload",
        }
    );
    assert_eq!(error.span(), span);
}
