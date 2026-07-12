//! Tree-walk evaluator tests: numeric.

use super::*;

#[test]
fn dynamic_attrset_bindings_evaluate_even_with_false_dynamic_flag() {
    let key = IrId::new(0);
    let value = IrId::new(1);
    let root = IrId::new(2);
    let shape = IrShapeId::new(0);
    let span = Span::new(0, 12);
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("symbol interns");
    let ir = manual_ir_with_attr_tables(
        root,
        vec![
            pure_node(IrKind::Str, Span::new(3, 8), IrData::Symbol(a)),
            pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
            pure_node(
                IrKind::AttrSet,
                span,
                IrData::AttrSet {
                    shape,
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
        ],
        symbols,
        vec![IrBinding {
            key: IrAttrPathSegment::Dynamic(key),
            position: None,
            value,
        }],
        vec![IrShape::new(Vec::new().into_boxed_slice())],
    );
    let outcome = eval_whnf_owned(&ir).expect("dynamic key evaluates");
    let attrs = outcome
        .heap()
        .get_attrs(outcome.value())
        .expect("attrset is heap-owned");

    assert_eq!(attrs.get(a).expect("dynamic key exists").as_int(), Ok(1));
}

#[test]
fn attr_path_auto_call_records_empty_arg_repr_decision() {
    let ir = lower("{ selected ? 7 }: { selected = selected; }");
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &[b"selected".to_vec()],
        TreeWalkOptions::default(),
        None,
    )
    .expect("formal-set auto-call attr path evaluates");

    assert_eq!(outcome.value().as_int(), Ok(7));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 1);
    assert_eq!(snapshot.reasons.small_shape_stable, 1);
}

#[test]
fn attr_path_outcome_records_projected_shaped_select_cache_terminal_states() {
    let ir = lower("{ selected = let f = x: x.a; in (f { a = 1; }) + (f { a = 2; }); }");
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &[b"selected".to_vec()],
        TreeWalkOptions::default(),
        None,
    )
    .expect("attr path selected expression evaluates");

    assert_eq!(outcome.value().as_int(), Ok(3));
    let snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(snapshot.shaped_select_sites.monomorphic, 1);
}

#[test]
fn malformed_thunk_payloads_are_reported_through_list_children() {
    let root = IrId::new(0);
    let child = IrId::new(1);
    let root_span = Span::new(0, 7);
    let child_span = Span::new(2, 5);
    let ir = empty_ir(
        root,
        IrArena::from_raw_parts(
            vec![
                pure_node(
                    IrKind::List,
                    root_span,
                    IrData::Children(IrChildSlice::new(0, 1)),
                ),
                pure_node(IrKind::ThunkAlloc, child_span, IrData::None),
            ],
            vec![child],
        ),
    );

    let error = eval_whnf_owned(&ir).expect_err("malformed thunk child is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidPayload {
            id: child,
            kind: IrKind::ThunkAlloc,
            expected: "thunk body",
        }
    );
    assert_eq!(error.span(), child_span);
}

#[test]
fn malformed_thunk_body_ids_are_reported_through_list_children() {
    let root = IrId::new(0);
    let child = IrId::new(1);
    let missing = IrId::new(99);
    let root_span = Span::new(0, 7);
    let child_span = Span::new(2, 5);
    let ir = empty_ir(
        root,
        IrArena::from_raw_parts(
            vec![
                pure_node(
                    IrKind::List,
                    root_span,
                    IrData::Children(IrChildSlice::new(0, 1)),
                ),
                pure_node(IrKind::ThunkAlloc, child_span, IrData::Node(missing)),
            ],
            vec![child],
        ),
    );

    let error = eval_whnf_owned(&ir).expect_err("missing thunk body is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::ThunkAllocation {
            id: child,
            source: crate::eval::TreeWalkThunkAllocationError::Downgrade(
                crate::compile::FrameLocalThunkDowngradeError::MissingThunkBody {
                    id: child,
                    body: missing,
                },
            ),
        }
    );
    assert_eq!(error.span(), child_span);
}

#[test]
fn if_evaluates_only_the_selected_branch() {
    assert_eq!(eval("if true then 1 else 2").as_int(), Ok(1));
    assert_eq!(eval("if false then 1 else 2").as_int(), Ok(2));

    let lazy_else = eval("if true then 7 else (1 ++ 2)");
    assert_eq!(lazy_else.as_int(), Ok(7));

    let lazy_then = eval("if false then (1 ++ 2) else 9");
    assert_eq!(lazy_then.as_int(), Ok(9));
}

#[test]
fn if_condition_must_be_bool() {
    let ir = lower("if 1 then 2 else 3");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Triple { first, .. } = root.data else {
        panic!("if root has triple payload");
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
fn malformed_if_payloads_are_reported() {
    let root = IrId::new(0);
    let span = Span::new(10, 12);
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::If,
            span,
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let ir = empty_ir(root, arena);
    let error = eval_whnf(&ir).expect_err("malformed if is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidPayload {
            id: root,
            kind: IrKind::If,
            expected: "if payload",
        }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn unary_not_evaluates_boolean_operands() {
    assert_eq!(eval("!true").as_bool(), Ok(false));
    assert_eq!(eval("!false").as_bool(), Ok(true));
}

#[test]
fn unary_not_rejects_non_bool_operands() {
    let ir = lower("!1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Unary { operand, .. } = root.data else {
        panic!("not root has unary payload");
    };
    let operand_span = ir.arena.node(operand).expect("operand exists").span;

    let error = eval_whnf(&ir).expect_err("integer operand is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: operand,
            expected: "bool",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), operand_span);
}

// Baseline float ABI test (direct `as_float`); the variant boxes floats, so its
// float path is covered by scalars.rs boxing round-trips + the parity battery.
// See cutover plan section 7.
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn numeric_unary_negation_handles_ints_and_floats() {
    assert_eq!(eval("-1").as_int(), Ok(-1));
    assert_eq!(eval("-1.5").as_float(), Ok(-1.5));

    let operand = IrId::new(0);
    let root = IrId::new(1);
    let ir = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(1, 2), IrData::Int(i64::MIN)),
            pure_node(
                IrKind::UnaryOp,
                Span::new(0, 2),
                IrData::Unary {
                    op: UnaryOpKind::Neg,
                    operand,
                },
            ),
        ],
    );

    let value = eval_whnf(&ir).expect("pinned Nix 2.24 wraps i64::MIN negation");
    assert_eq!(value.as_int(), Ok(i64::MIN));
}

#[test]
fn numeric_unary_negation_rejects_non_numbers() {
    let ir = lower("-true");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Unary { operand, .. } = root.data else {
        panic!("negation root has unary payload");
    };
    let operand_span = ir.arena.node(operand).expect("operand exists").span;

    let error = eval_whnf(&ir).expect_err("boolean negation operand is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: operand,
            expected: "number",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), operand_span);
}

#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn numeric_arithmetic_handles_ints_and_float_promotion() {
    assert_eq!(eval("1 + 2").as_int(), Ok(3));
    assert_eq!(eval("5 - 8").as_int(), Ok(-3));
    assert_eq!(eval("2 * 3").as_int(), Ok(6));
    assert_eq!(eval("1 + 2.5").as_float(), Ok(3.5));
    assert_eq!(eval("1.5 + 2.0").as_float(), Ok(3.5));
    assert_eq!(eval("1.5 + 2").as_float(), Ok(3.5));
    assert_eq!(eval("5 - 1.5").as_float(), Ok(3.5));
    assert_eq!(eval("5.5 - 2").as_float(), Ok(3.5));
    assert_eq!(eval("2 * 0.5").as_float(), Ok(1.0));
    assert_eq!(eval("2.5 * 2").as_float(), Ok(5.0));
    assert_eq!(eval("5 / 2.0").as_float(), Ok(2.5));
    assert_eq!(eval("5.0 / 2").as_float(), Ok(2.5));
}

#[test]
fn integer_division_truncates_toward_zero() {
    assert_eq!(eval("7 / 2").as_int(), Ok(3));
    assert_eq!(eval("7 / (-2)").as_int(), Ok(-3));
    assert_eq!(eval("(-7) / 2").as_int(), Ok(-3));
}

#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn float_or_mixed_division_returns_float() {
    assert_eq!(eval("7 / 2.0").as_float(), Ok(3.5));
    assert_eq!(eval("7.0 / 2").as_float(), Ok(3.5));
}

#[test]
fn division_by_zero_errors_at_operator_span() {
    let ir = lower("1 / 0");
    let error = eval_whnf(&ir).expect_err("integer division by zero is invalid");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: ir.root }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );

    let float_ir = lower("1.0 / -0.0");
    let error = eval_whnf(&float_ir).expect_err("float division by zero is invalid");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: float_ir.root }
    );
    assert_eq!(
        error.span(),
        float_ir
            .arena
            .node(float_ir.root)
            .expect("root exists")
            .span
    );
}

#[test]
fn integer_add_sub_mul_wrap_on_overflow() {
    let cases = [
        (BinOpKind::Add, i64::MAX, 1, i64::MIN),
        (BinOpKind::Sub, i64::MIN, 1, i64::MAX),
        (BinOpKind::Mul, i64::MAX, 2, -2),
    ];

    for (op, left, right, expected) in cases {
        let value = eval_whnf(&int_binary_ir(op, left, right)).expect("arithmetic evaluates");

        assert_eq!(value.as_int(), Ok(expected));
    }
}

#[test]
fn integer_division_overflow_errors_at_operator_span() {
    let ir = int_binary_ir(BinOpKind::Div, i64::MIN, -1);
    let root_span = ir.arena.node(ir.root).expect("root exists").span;
    let error = eval_whnf(&ir).expect_err("integer division overflows");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::ArithmeticOverflow {
            id: ir.root,
            op: ArithmeticOp::Div,
        }
    );
    assert_eq!(error.span(), root_span);
}

#[test]
fn numeric_operators_force_rhs_before_type_checks() {
    let rhs_ir = lower("1 + true");
    let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("addition root has binary payload");
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

    let lhs_ir = lower("true - (1 / 0)");
    let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("subtraction root has binary payload");
    };
    let rhs_span = lhs_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&lhs_ir).expect_err("rhs evaluation error wins before lhs type");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);

    let lhs_type_ir = lower("true - false");
    let root = lhs_type_ir
        .arena
        .node(lhs_type_ir.root)
        .expect("root exists");
    let IrData::Binary { lhs, .. } = root.data else {
        panic!("subtraction root has binary payload");
    };
    let lhs_span = lhs_type_ir.arena.node(lhs).expect("lhs exists").span;

    let error = eval_whnf(&lhs_type_ir).expect_err("boolean lhs is invalid after rhs force");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: lhs,
            expected: "number",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), lhs_span);
}

#[test]
fn scalar_equality_handles_inline_values() {
    assert_eq!(eval("1 == 1").as_bool(), Ok(true));
    assert_eq!(eval("1 == 2").as_bool(), Ok(false));
    assert_eq!(eval("1 == 1.0").as_bool(), Ok(true));
    assert_eq!(eval("1 != 1.5").as_bool(), Ok(true));
    assert_eq!(eval("true == true").as_bool(), Ok(true));
    assert_eq!(eval("true != false").as_bool(), Ok(true));
    assert_eq!(eval("null == null").as_bool(), Ok(true));
    assert_eq!(eval("null == false").as_bool(), Ok(false));
    assert_eq!(eval("1 == true").as_bool(), Ok(false));
}

#[test]
fn string_equality_compares_bytes() {
    assert_eq!(eval("\"a\" == \"a\"").as_bool(), Ok(true));
    assert_eq!(eval("\"a\" == \"b\"").as_bool(), Ok(false));
    assert_eq!(eval("\"a\" != \"b\"").as_bool(), Ok(true));
    assert_eq!(eval("\"line\\n\" == \"line\\n\"").as_bool(), Ok(true));
    assert_eq!(eval("\"a\" == 1").as_bool(), Ok(false));
    assert_eq!(eval("1 != \"a\"").as_bool(), Ok(true));
}

#[test]
fn string_equality_ignores_contexts() {
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
            .values_equal(ir.root, &node, left, right, EqualityContext::Direct)
            .expect("strings compare"),
        true
    );
}

#[test]
fn list_equality_is_structural_and_short_circuits() {
    assert_eq!(eval("[1 \"a\" null] == [1 \"a\" null]").as_bool(), Ok(true));
    assert_eq!(eval("[1] != [1 2]").as_bool(), Ok(true));
    assert_eq!(eval("[1 2] == [1 3]").as_bool(), Ok(false));
    assert_eq!(eval("[1 (1 / 0)] == [2 (1 / 0)]").as_bool(), Ok(false));
    assert_eq!(eval("let f = x: x; in [ f ] == [ f ]").as_bool(), Ok(true));
    assert_eq!(eval("[ (x: x) ] == [ (x: x) ]").as_bool(), Ok(false));
    assert_eq!(
        eval("let v = { a = x: x; }; in [ v.a ] == [ v.a ]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("let v = { a = x: x; }; xs = [ v.a ]; in xs == xs").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let xs = [ (1 / 0) ]; in [ xs ] == [ xs ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in [ nan ] == [ nan ]")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
            eval(
                "[ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ] == [ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ]"
            )
            .as_bool(),
            Ok(false)
        );
}

#[test]
fn structural_equality_handles_recursive_containers() {
    assert_eq!(eval("let xs = [ xs ]; in xs == xs").as_bool(), Ok(true));
    assert_eq!(
        eval("let left = [ right 1 ]; right = [ left 1 ]; in left == right").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let left = [ right 1 ]; right = [ left 2 ]; in left == right").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("let s = rec { a = s; }; in s == s").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let left = rec { a = left; value = 1; }; right = rec { a = right; value = 1; }; in left == right").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let left = { a = [ left ]; value = 1; }; right = { a = [ right ]; value = 1; }; in left == right").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let left = rec { a = left; value = 1; }; right = rec { a = right; value = 2; }; in left == right").as_bool(),
        Ok(false)
    );
}

#[test]
fn attrset_equality_is_structural_and_short_circuits() {
    assert_eq!(
        eval("{ b = 2; a = 1; } == { a = 1; b = 2; }").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("{ a = 1; } == { a = 1; b = 1 / 0; }").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("{ a = 1; z = 1 / 0; } == { a = 2; z = 1 / 0; }").as_bool(),
        Ok(false)
    );
    let z_first = lower("{ z = 1 / 0; a = 1; } == { a = 2; z = 1 / 0; }");
    let z_error = eval_whnf(&z_first).expect_err("symbol-order comparison forces z first");
    let TreeWalkErrorKind::DivisionByZero { .. } = z_error.kind() else {
        panic!("expected division by zero from z value");
    };
    assert_eq!(
        eval("{ a = { x = 1; }; } == { a = { x = 1; }; }").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = x: x; in { inherit f; } == { inherit f; }").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let s = { a = 1 / 0; }; in [ s ] == [ s ]").as_bool(),
        Ok(true)
    );
}

#[test]
fn derivation_attrset_equality_uses_out_path_identity() {
    assert_eq!(
        eval(r#"let d = { type = "derivation"; outPath = "/a"; drvPath = "/a.drv"; }; in d == (d // { dummy = 1; })"#).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(
            r#"{ type = "derivation"; outPath = "/a"; drvPath = "/first.drv"; } == { type = "derivation"; outPath = "/a"; drvPath = "/second.drv"; dummy = 1; }"#
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(
            r#"{ type = "derivation"; outPath = "/a"; drvPath = "/a.drv"; } == { type = "derivation"; outPath = "/b"; drvPath = "/a.drv"; }"#
        )
        .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(r#"{ outPath = "/a"; a = 1; } == { outPath = "/a"; a = 2; }"#).as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(r#"{ type = 1; outPath = "/a"; a = 1; } == { type = 1; outPath = "/a"; a = 2; }"#)
            .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(r#"{ type = "derivation"; drvPath = "/a.drv"; } == { type = "derivation"; drvPath = "/a.drv"; dummy = 1; }"#).as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(r#"{ type = "derivation"; outPath = 1; } == { type = "derivation"; outPath = 1; dummy = 1; }"#).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(r#"{ a = 1; } == { type = throw "type"; outPath = "/a"; }"#).as_bool(),
        Ok(false)
    );

    let error = eval_whnf(&lower(
        r#"{ type = throw "type"; outPath = "/a"; } == { a = 1; }"#,
    ))
    .expect_err("left derivation type probe forces the type attr");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown derivation type probe error");
    };
    assert_eq!(message, b"type");
}

#[test]
fn direct_function_equality_is_always_false() {
    assert_eq!(eval("let f = x: x; in f == f").as_bool(), Ok(false));
    assert_eq!(eval("let f = x: x; in f != f").as_bool(), Ok(true));
    assert_eq!(
        eval("let f = x: x; g = x: x; in f == g").as_bool(),
        Ok(false)
    );
    assert_eq!(eval("(x: x) == 1").as_bool(), Ok(false));

    let ir = lower("1");
    let mut evaluator = TreeWalk::new(&ir);
    let node = ir.arena.node(ir.root).expect("root exists");
    let ptr = NonNull::<HeapObject>::dangling();
    let lambda = Value::lambda(ptr).expect("aligned lambda pointer");
    let primop = Value::primop(ptr).expect("aligned primop pointer");
    assert_eq!(
        evaluator.values_equal(ir.root, node, primop, primop, EqualityContext::Direct),
        Ok(false)
    );
    assert_eq!(
        evaluator.values_equal(ir.root, node, lambda, primop, EqualityContext::Direct),
        Ok(false)
    );
}

#[test]
fn scalar_equality_evaluates_operands_left_to_right() {
    let rhs_ir = lower("false == (1 / 0)");
    let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("equality root has binary payload");
    };
    let rhs_id = rhs;
    let rhs_span = rhs_ir.arena.node(rhs_id).expect("rhs exists").span;
    let error = eval_whnf(&rhs_ir).expect_err("rhs division by zero is evaluated");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: rhs_id }
    );
    assert_eq!(error.span(), rhs_span);

    let lhs_ir = lower("(1 / 0) == false");
    let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
    let IrData::Binary { lhs, .. } = root.data else {
        panic!("equality root has binary payload");
    };
    let lhs_id = lhs;
    let lhs_span = lhs_ir.arena.node(lhs_id).expect("lhs exists").span;
    let error = eval_whnf(&lhs_ir).expect_err("lhs division by zero is evaluated first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: lhs_id }
    );
    assert_eq!(error.span(), lhs_span);
}

#[test]
fn raw_thunk_equality_is_unsupported() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::new(&ir);
    let node = ir.arena.node(ir.root).expect("root exists");
    let ptr = NonNull::<HeapObject>::dangling();
    let left = Value::thunk(ptr).expect("aligned thunk pointer");
    let right = Value::thunk(ptr).expect("aligned thunk pointer");

    let error = evaluator
        .values_equal(ir.root, node, left, right, EqualityContext::Direct)
        .expect_err("raw thunk equality is not supported");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedEqualityType {
            id: ir.root,
            left: ValueTag::Thunk,
            right: ValueTag::Thunk,
        }
    );
    assert_eq!(error.span(), node.span);
}

#[test]
fn numeric_comparisons_handle_ints_floats_and_promotion() {
    assert_eq!(eval("1 < 2").as_bool(), Ok(true));
    assert_eq!(eval("2 > 1").as_bool(), Ok(true));
    assert_eq!(eval("2 <= 2").as_bool(), Ok(true));
    assert_eq!(eval("2 >= 3").as_bool(), Ok(false));
    assert_eq!(eval("1 < 1.5").as_bool(), Ok(true));
    assert_eq!(eval("1.5 >= 2").as_bool(), Ok(false));
}

#[test]
fn string_comparisons_use_byte_order() {
    assert_eq!(eval("\"a\" < \"b\"").as_bool(), Ok(true));
    assert_eq!(eval("\"b\" > \"a\"").as_bool(), Ok(true));
    assert_eq!(eval("\"a\" <= \"a\"").as_bool(), Ok(true));
    assert_eq!(eval("\"a\" >= \"b\"").as_bool(), Ok(false));
    assert_eq!(eval("\"Z\" < \"a\"").as_bool(), Ok(true));
    assert_eq!(eval("\"a\\n\" < \"aa\"").as_bool(), Ok(true));
}

#[test]
fn path_comparisons_use_byte_order() {
    let dir = unique_temp_dir("path-ordering");
    let first_path = dir.join("first.txt");
    let second_path = dir.join("second.txt");
    fs::write(&first_path, b"first").expect("first temp file writes");
    fs::write(&second_path, b"second").expect("second temp file writes");
    let first_path = path_source(&first_path);
    let second_path = path_source(&second_path);

    assert_eq!(
        eval(&format!("{first_path} < {second_path}")).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!("{second_path} > {first_path}")).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!("{first_path} <= {first_path}")).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!("builtins.lessThan {first_path} {second_path}")).as_bool(),
        Ok(true)
    );
}
