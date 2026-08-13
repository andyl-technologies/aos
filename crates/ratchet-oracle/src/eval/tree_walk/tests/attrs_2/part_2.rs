//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn select_requires_attrset_receivers() {
    let ir = lower("(1).a");
    let error = eval_whnf(&ir).expect_err("integer receiver is not an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: ir.root,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );

    let nested = lower("({ a = 1; }).a.b");
    let nested_error =
        eval_whnf_owned(&nested).expect_err("integer intermediate is not an attrset");

    assert_eq!(
        nested_error.kind(),
        TreeWalkErrorKind::Type {
            id: nested.root,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(
        nested_error.span(),
        nested.arena.node(nested.root).expect("root exists").span
    );
}

#[test]
fn select_evaluates_nested_static_and_dynamic_paths() {
    assert_eq!(
        eval("({ a = { b = { c = 1 + 2; }; }; }).a.b.c").as_int(),
        Ok(3)
    );
    assert_eq!(eval("({ a = { b = 1 + 2; }; }).a.b").as_int(), Ok(3));
    assert_eq!(eval("({ a = 1; }).${\"a\"}").as_int(), Ok(1));
    assert_eq!(eval("({ ab = 3; }).${\"a\" + \"b\"}").as_int(), Ok(3));
    assert_eq!(
        eval("let name = \"a\"; in { a = { b = 2; }; }.${name}.b").as_int(),
        Ok(2)
    );
    assert_eq!(eval("({}).${\"a\"}.${1 / 0} or 2").as_int(), Ok(2));
    assert_eq!(eval("(1).${\"a\"} or 2").as_int(), Ok(2));

    let error_ir = lower("({ a = 1 / 0; }).a.b or 2");
    let error = eval_whnf_owned(&error_ir).expect_err("intermediate thunk errors win");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let null_key = lower("({ a = 1; }).${null} or 2");
    let null_node = null_key
        .arena
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.kind == IrKind::Null)
        .map(|(index, _)| IrId::new(index as u32))
        .expect("null key expression exists");
    let null_error = eval_whnf_owned(&null_key).expect_err("select dynamic null key is invalid");

    assert_eq!(
        null_error.kind(),
        TreeWalkErrorKind::Type {
            id: null_node,
            expected: "string",
            actual: ValueTag::Null,
        }
    );
    assert_eq!(
        null_error.span(),
        null_key
            .arena
            .node(null_node)
            .expect("null key expression exists")
            .span
    );

    for (source, actual) in [
        (
            "({ value = 9; }).${ { __toString = self: \"value\"; } }",
            ValueTag::Attrs,
        ),
        ("({ \"/tmp/x\" = 5; }).${/tmp/x}", ValueTag::Path),
    ] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("dynamic selects require string keys");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "string",
                actual: observed,
                ..
            } if observed == actual
        ));
    }

    let context_key = lower(
        r#"({ name = 7; }).${builtins.appendContext "name" {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source" = { path = true; };
               }}"#,
    );
    let error = eval_whnf_owned(&context_key).expect_err("dynamic select rejects string context");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "dynamic attribute name",
            ..
        }
    ));
}

#[test]
fn flat_slow_select_bridge_preserves_tree_walk_surface_semantics() {
    assert_eq!(eval("({ b = 2; a = 1; }).a").as_int(), Ok(1));
    assert_eq!(
        eval(r#"let key = "b"; in ({ a = 1; b = 2; }).${key}"#).as_int(),
        Ok(2)
    );
    assert_eq!(eval("({}).missing or 4").as_int(), Ok(4));
    assert_eq!(eval("({ a = 1 / 0; } ? a)").as_bool(), Ok(true));
    assert_eq!(eval("({ a = 1; } ? b)").as_bool(), Ok(false));

    let ir = lower("({ a = 1; }).b");
    let error = eval_whnf_owned(&ir).expect_err("missing select remains a tree-walk miss");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));
}

#[test]
fn select_defaults_with_dynamic_keys_match_pinned_order() {
    assert_eq!(eval("({ a = 1; }).${\"a\"} or (1 / 0)").as_int(), Ok(1));
    assert_eq!(eval("({}).${\"a\"} or 2").as_int(), Ok(2));
    assert_eq!(eval("({ a = {}; }).${\"a\"}.${\"b\"} or 2").as_int(), Ok(2));
    assert_eq!(eval("({ a = 1; }).${\"a\"}.${\"b\"} or 2").as_int(), Ok(2));
    assert_eq!(eval("(1).${\"a\"} or 2").as_int(), Ok(2));
    assert_eq!(eval("({}).${\"missing\"}.${null} or 2").as_int(), Ok(2));

    let receiver_error = lower("((1 / 0)).${\"a\"} or 2");
    let error =
        eval_whnf_owned(&receiver_error).expect_err("receiver errors before default fallback");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    for source in [
        "({}).${1 / 0} or 2",
        "(1).${1 / 0} or 2",
        "({ a = 1; }).a.${1 / 0} or 2",
    ] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("reached dynamic key errors before default");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    for (source, actual) in [
        ("({}).${null} or 2", ValueTag::Null),
        ("({}).${/tmp/x} or 2", ValueTag::Path),
        (
            "({}).${ { __toString = self: \"value\"; } } or 2",
            ValueTag::Attrs,
        ),
    ] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("dynamic select defaults require string keys");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "string",
                actual: observed,
                ..
            } if observed == actual
        ));
    }

    let context_key = lower(
        r#"({}).${builtins.appendContext "name" {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source" = { path = true; };
               }} or 2"#,
    );
    let error =
        eval_whnf_owned(&context_key).expect_err("dynamic select defaults reject string context");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "dynamic attribute name",
            ..
        }
    ));
}

#[test]
fn select_evaluates_receiver_and_reached_dynamic_keys_in_order() {
    let ir = lower("(1 / 0).${\"a\"}");
    let error = eval_whnf_owned(&ir).expect_err("receiver errors before dynamic key success");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    let division = ir
        .arena
        .nodes()
        .iter()
        .find(|node| node.kind == IrKind::BinOp)
        .expect("division node exists");
    assert_eq!(error.span(), division.span);

    let dynamic_error = lower("({}).${1 / 0} or 2");
    let error = eval_whnf_owned(&dynamic_error)
        .expect_err("first dynamic key errors before default fallback");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}
