//! Tree-walk evaluator tests: control.

use super::*;

#[test]
fn absent_pinned_builtin_attrs_use_defaults() {
    for (name, source) in [
        ("exec", "builtins.exec or 42"),
        ("fetchClosure", "builtins.fetchClosure or 42"),
        ("outputOf", "builtins.outputOf or 42"),
        ("toHashFormat", "builtins.toHashFormat or 42"),
    ] {
        assert_eq!(eval(source).as_int(), Ok(42));
        assert_eq!(
            eval_with_options(source, TreeWalkOptions::with_eval_mode(EvalMode::Pure)).as_int(),
            Ok(42),
            "{name} should remain absent/defaultable under pure evaluation",
        );

        let attr_probe = format!("builtins ? {name}");
        assert_eq!(
            eval(&attr_probe).as_bool(),
            Ok(false),
            "{name} should be absent from the default builtins attrset",
        );
        assert_eq!(
            eval_with_options(&attr_probe, TreeWalkOptions::with_eval_mode(EvalMode::Pure))
                .as_bool(),
            Ok(false),
            "{name} should be absent from the pure builtins attrset",
        );
    }
}

#[test]
fn lib_catalogue_entries_are_not_builtin_attrs() {
    for name in LIB_NOT_BUILTIN_NAMES {
        let source = format!(r#"builtins.hasAttr "{name}" builtins"#);

        assert_eq!(
            eval(&source).as_bool(),
            Ok(false),
            "{name} must not be exposed as a builtin attr",
        );
    }
}

#[test]
fn add_error_context_returns_success_without_evaluating_context_message() {
    assert_eq!(eval("builtins.addErrorContext 1 7").as_int(), Ok(7));
    assert_eq!(
        eval(r#"builtins.addErrorContext (builtins.throw "context") 7"#).as_int(),
        Ok(7)
    );
    assert_eq!(
        eval(r#"let add = builtins.addErrorContext; in add (builtins.throw "context") 7"#).as_int(),
        Ok(7)
    );
    assert_eq!(
        eval(r#"let add = builtins.addErrorContext (builtins.throw "context"); in add 7"#).as_int(),
        Ok(7)
    );
}

#[test]
fn add_error_context_attaches_context_to_expression_errors() {
    let error = eval_whnf_owned(&lower(
        r#"builtins.addErrorContext "ctx" (builtins.throw "boom")"#,
    ))
    .expect_err("addErrorContext attaches to throw");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"boom");
    assert_error_contexts(&error, &[b"ctx"]);

    let error = eval_whnf_owned(&lower(
        r#"builtins.addErrorContext "ctx" (builtins.abort "boom")"#,
    ))
    .expect_err("addErrorContext attaches to abort");
    let TreeWalkErrorKind::Aborted { message, .. } = error.kind() else {
        panic!("expected aborted error");
    };
    assert_eq!(message, b"boom");
    assert_error_contexts(&error, &[b"ctx"]);

    let error = eval_whnf_owned(&lower(r#"builtins.addErrorContext "ctx" (1 + true)"#))
        .expect_err("addErrorContext attaches to ordinary errors");
    assert!(matches!(error.kind(), TreeWalkErrorKind::Type { .. }));
    assert_error_contexts(&error, &[b"ctx"]);
}

#[test]
fn add_error_context_preserves_outer_to_inner_context_order() {
    let error = eval_whnf_owned(&lower(
            r#"builtins.addErrorContext "outer" (builtins.addErrorContext "inner" (builtins.throw "boom"))"#,
        ))
        .expect_err("nested addErrorContext attaches both contexts");

    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"boom");
    assert_error_contexts(&error, &[b"outer", b"inner"]);
}

#[test]
fn add_error_context_supports_first_class_application() {
    for source in [
        r#"let add = builtins.addErrorContext "ctx"; in add (builtins.throw "boom")"#,
        r#"let add = builtins.addErrorContext; in add "ctx" (builtins.throw "boom")"#,
    ] {
        let error =
            eval_whnf_owned(&lower(source)).expect_err("first-class addErrorContext attaches");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"boom");
        assert_error_contexts(&error, &[b"ctx"]);
    }
}

#[test]
fn add_error_context_message_failures_match_cpp_nix_ordering() {
    let error = eval_whnf_owned(&lower(
        r#"builtins.addErrorContext 1 (builtins.throw "boom")"#,
    ))
    .expect_err("invalid context message wins after wrapped expression fails");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));
    assert_error_contexts(&error, &[ADD_ERROR_CONTEXT_MESSAGE_CONTEXT]);

    let error = eval_whnf_owned(&lower(
        r#"builtins.addErrorContext {} (builtins.throw "boom")"#,
    ))
    .expect_err("non-coercible attrset context gets addErrorContext context");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Attrs,
            ..
        }
    ));
    assert_error_contexts(&error, &[ADD_ERROR_CONTEXT_MESSAGE_CONTEXT]);

    let error = eval_whnf_owned(&lower(
        r#"builtins.addErrorContext (builtins.throw "context") (builtins.throw "boom")"#,
    ))
    .expect_err("context expression error wins");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown context error");
    };
    assert_eq!(message, b"context");
    assert_error_contexts(&error, &[]);

    let error = eval_whnf_owned(&lower(
            r#"builtins.addErrorContext ({ __toString = self: builtins.throw "context"; }) (builtins.throw "boom")"#,
        ))
        .expect_err("__toString throw wins while coercing the context message");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown context error");
    };
    assert_eq!(message, b"context");
    assert_error_contexts(&error, &[]);

    let error = eval_whnf_owned(&lower(
        r#"builtins.addErrorContext ({ __toString = self: 1; }) (builtins.throw "boom")"#,
    ))
    .expect_err("__toString result type error wins while coercing the context message");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));
    assert_error_contexts(&error, &[]);
}

#[test]
fn try_eval_catches_add_error_context_wrapped_throw() {
    assert_eq!(
        eval(
            r#"(builtins.tryEval (builtins.addErrorContext "ctx" (builtins.throw "boom"))).success"#
        )
        .as_bool(),
        Ok(false)
    );
    let error = eval_whnf_owned(&lower(
        r#"builtins.tryEval (builtins.addErrorContext 1 (builtins.throw "boom"))"#,
    ))
    .expect_err("tryEval does not catch context message type errors");
    assert!(matches!(error.kind(), TreeWalkErrorKind::Type { .. }));
    assert_error_contexts(&error, &[ADD_ERROR_CONTEXT_MESSAGE_CONTEXT]);
}

#[test]
fn throw_and_abort_raise_distinct_errors() {
    let ir = lower("builtins.throw \"boom\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let message_id = args[0];
    let message_span = ir.arena.node(message_id).expect("message exists").span;

    let error = eval_whnf_owned(&ir).expect_err("throw raises");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Thrown {
            id: message_id,
            message: b"boom".to_vec(),
        }
    );
    assert_eq!(error.span(), message_span);

    let error = eval_whnf_owned(&lower("let f = builtins.throw; in f \"boom\""))
        .expect_err("first-class throw raises");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"boom");

    let ir = lower("builtins.abort \"boom\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let message_id = args[0];
    let message_span = ir.arena.node(message_id).expect("message exists").span;

    let error = eval_whnf_owned(&ir).expect_err("abort raises");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Aborted {
            id: message_id,
            message: b"boom".to_vec(),
        }
    );
    assert_eq!(error.span(), message_span);

    let error = eval_whnf_owned(&lower("let f = builtins.abort; in f \"boom\""))
        .expect_err("first-class abort raises");
    let TreeWalkErrorKind::Aborted { message, .. } = error.kind() else {
        panic!("expected aborted error");
    };
    assert_eq!(message, b"boom");
}

#[test]
fn throw_and_abort_coerce_messages_before_raising() {
    let ir = lower("builtins.throw { __toString = self: \"coerced\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let message_id = args[0];

    let error = eval_whnf_owned(&ir).expect_err("throw raises after coercion");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Thrown {
            id: message_id,
            message: b"coerced".to_vec(),
        }
    );

    for source in ["builtins.throw 1", "builtins.abort 1"] {
        let ir = lower(source);
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let message_id = args[0];
        let message_span = ir.arena.node(message_id).expect("message exists").span;

        let error = eval_whnf_owned(&ir).expect_err("message coercion fails first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: message_id,
                expected: "string",
                actual: ValueTag::Int,
            },
            "{source}"
        );
        assert_eq!(error.span(), message_span, "{source}");
    }
}

#[test]
fn throw_and_abort_remain_lazy_until_demanded() {
    assert_eq!(
        eval("let x = builtins.throw \"boom\"; in 1").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("{ a = builtins.abort \"boom\"; b = 2; }.b").as_int(),
        Ok(2)
    );

    let error = eval_whnf_owned(&lower("builtins.seq (builtins.throw \"boom\") 1"))
        .expect_err("seq demands throw");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"boom");

    let error = eval_whnf_owned(&lower("builtins.deepSeq [ (builtins.abort \"boom\") ] 1"))
        .expect_err("deepSeq demands abort");
    let TreeWalkErrorKind::Aborted { message, .. } = error.kind() else {
        panic!("expected aborted error");
    };
    assert_eq!(message, b"boom");
}

#[test]
fn try_eval_catches_throw_and_assertion_failures() {
    assert_eq!(
        eval("(builtins.tryEval (builtins.throw \"boom\")).success").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("(builtins.tryEval (builtins.throw \"boom\")).value").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("(let t = builtins.tryEval; in t (builtins.throw \"boom\")).success").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("(builtins.tryEval (assert false; 1)).success").as_bool(),
        Ok(false)
    );
    assert_eq!(eval("(builtins.tryEval 7).success").as_bool(), Ok(true));
    assert_eq!(eval("(builtins.tryEval 7).value").as_int(), Ok(7));
}

#[test]
fn try_eval_catches_missing_search_path() {
    assert_eq!(
        eval(r#"let throw = builtins.abort "Error!"; in (builtins.tryEval <foobaz>).success"#)
            .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(r#"let throw = builtins.abort "Error!"; in (builtins.tryEval <foobaz>).value"#)
            .as_bool(),
        Ok(false)
    );
}

#[test]
fn try_eval_does_not_catch_unsupported_ambient_search_path() {
    let mut options = TreeWalkOptions::default();
    options.set_reject_ambient_search_path(true);
    let error = eval_whnf_owned_with_options(&lower("builtins.tryEval <foobaz>"), options)
        .expect_err("tryEval should not catch disabled ambient search-path access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedAmbientSearchPath { .. }
    ));
}

#[test]
fn try_eval_is_shallow() {
    assert_eq!(
        eval("(builtins.tryEval { x = builtins.throw \"boom\"; }).success").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isAttrs (builtins.tryEval { x = builtins.throw \"boom\"; }).value")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("(builtins.tryEval [ (builtins.throw \"boom\") ]).success").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.length (builtins.tryEval [ (builtins.throw \"boom\") ]).value").as_int(),
        Ok(1)
    );

    let error = eval_whnf_owned(&lower(
        "builtins.deepSeq (builtins.tryEval { x = builtins.throw \"boom\"; }) true",
    ))
    .expect_err("deepSeq demands the latent throw inside tryEval's value");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"boom");
}

#[test]
fn try_eval_does_not_catch_fatal_or_type_errors() {
    let error = eval_whnf_owned(&lower("builtins.tryEval (builtins.abort \"boom\")"))
        .expect_err("tryEval does not catch abort");
    let TreeWalkErrorKind::Aborted { message, .. } = error.kind() else {
        panic!("expected aborted error");
    };
    assert_eq!(message, b"boom");

    let error = eval_whnf_owned(&lower("builtins.tryEval (1 + true)"))
        .expect_err("tryEval does not catch type errors");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "number",
            actual: ValueTag::Bool,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("builtins.tryEval ({ }).missing"))
        .expect_err("tryEval does not catch missing attrs");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let error = eval_whnf_owned(&lower("builtins.tryEval (builtins.elemAt [] 0)"))
        .expect_err("tryEval does not catch list bounds errors");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::ListIndexOutOfBounds { .. }
    ));
}

#[test]
fn unavailable_current_system_behaves_like_missing_attr() {
    let ir = lower("builtins.currentSystem");
    let error = eval_whnf_owned(&ir).expect_err("currentSystem is unavailable");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute {
            id: ir.root,
            symbol: symbol_for(&ir, b"currentSystem")
        }
    );
}

#[test]
fn current_system_uses_configured_target_and_system_stays_absent() {
    let options = TreeWalkOptions::with_current_system(b"aos-test-target".to_vec())
        .expect("currentSystem is valid");

    assert_eq!(
        eval_string_bytes_with_options("builtins.currentSystem", options.clone()),
        b"aos-test-target"
    );
    assert_eq!(
        eval_with_options("builtins ? currentSystem", options.clone()).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_with_options("builtins ? system", options.clone()).as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.system or \"fallback\"", options),
        b"fallback"
    );
}

#[test]
fn unavailable_current_time_behaves_like_missing_attr() {
    let ir = lower("builtins.currentTime");
    let error = eval_whnf_owned(&ir).expect_err("currentTime is unavailable");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute {
            id: ir.root,
            symbol: symbol_for(&ir, b"currentTime")
        }
    );
}

#[test]
fn pure_eval_mode_hides_configured_impure_constants() {
    let mut options =
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec()).expect("system valid");
    options.set_current_time(1_700_000_000).expect("time valid");
    options.set_eval_mode(EvalMode::Pure);

    assert_eq!(
        eval_with_options("builtins ? currentSystem", options.clone()).as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval_with_options("builtins ? currentTime", options.clone()).as_bool(),
        Ok(false)
    );
    assert!(matches!(
        eval_whnf_owned_with_options(&lower("builtins.currentSystem"), options.clone())
            .expect_err("pure eval hides currentSystem")
            .kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));
    assert!(matches!(
        eval_whnf_owned_with_options(&lower("builtins.currentTime"), options)
            .expect_err("pure eval hides currentTime")
            .kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));
}

#[test]
fn bare_current_time_remains_unresolved_global() {
    let ir = lower("currentTime");
    let error = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid"),
    )
    .expect_err("currentTime is not a bare global");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnresolvedGlobalVar {
            id: ir.root,
            symbol: symbol_for(&ir, b"currentTime"),
        }
    );
}

#[test]
fn bare_builtin_attrs_are_unresolved_globals() {
    let ir = lower("length");
    let error = eval_whnf_owned(&ir).expect_err("shadowable builtin attrs are not bare globals");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnresolvedGlobalVar {
            id: ir.root,
            symbol: symbol_for(&ir, b"length"),
        }
    );
}

#[test]
fn first_class_builtin_selects_respect_shadowing() {
    assert_eq!(
        eval("let builtins = { length = x: 42; }; in builtins.length [ 1 ]").as_int(),
        Ok(42)
    );
    assert_eq!(
        eval("let builtins = {}; in builtins.length or 42").as_int(),
        Ok(42)
    );
    assert_eq!(
        eval_string_bytes("let builtins = { storeDir = \"local\"; }; in builtins.storeDir"),
        b"local"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { currentSystem = \"local\"; }; in builtins.currentSystem"
        ),
        b"local"
    );
    assert_eq!(
        eval("let builtins = { break = value: 42; }; in builtins.break 1").as_int(),
        Ok(42)
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { getEnv = name: \"local\"; }; in builtins.getEnv \"HOME\""
        ),
        b"local"
    );
}

#[test]
fn length_primop_returns_list_spine_length_without_forcing_elements() {
    assert_eq!(eval("builtins.length []").as_int(), Ok(0));
    assert_eq!(eval("builtins.length [ 1 (1 / 0) true ]").as_int(), Ok(3));
    assert_eq!(
        eval("let builtins = { length = x: 42; }; in builtins.length [ 1 ]").as_int(),
        Ok(42)
    );
}

#[test]
fn length_primop_type_checks_argument() {
    let ir = lower("builtins.length 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("length requires a list");

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
fn attr_names_primop_returns_sorted_names_without_forcing_values() {
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames { z = 1 / 0; a = 2; b = true; }"),
        vec![b"a".to_vec(), b"b".to_vec(), b"z".to_vec()]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames { a = 1; A = 1; aa = 1; _ = 1; }"),
        vec![b"A".to_vec(), b"_".to_vec(), b"a".to_vec(), b"aa".to_vec()]
    );
    assert_eq!(
        eval_list_string_bytes(
            "let builtins = { attrNames = x: [ \"local\" ]; }; in builtins.attrNames { a = 1; }"
        ),
        vec![b"local".to_vec()]
    );
}

#[test]
fn attrset_literal_iteration_uses_symbol_collation_order() {
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames { z = 1; A = 2; aa = 3; _ = 4; a = 5; }"),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ]
    );
    assert_eq!(
        eval_list_ints("builtins.attrValues { z = 1; A = 2; aa = 3; _ = 4; a = 5; }"),
        vec![2, 4, 5, 3, 1]
    );
}

#[test]
fn attr_names_primop_type_checks_argument() {
    let ir = lower("builtins.attrNames 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("attrNames requires an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn attr_values_primop_returns_sorted_values_without_forcing_them() {
    let ir = lower("builtins.attrValues { z = 1 / 0; a = 2; }");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator.eval_root().expect("attrValues evaluates");
    let values = {
        let list = evaluator
            .heap
            .get_list(value)
            .expect("result is a heap-owned list");
        list.as_slice().to_vec()
    };

    assert_eq!(values.len(), 2);
    let first = evaluator
        .force_value(ir.root, span, values[0])
        .expect("first value forces");
    assert_eq!(first.as_int(), Ok(2));
    let lazy_division = values[1];
    assert_eq!(lazy_division.tag(), ValueTag::Thunk);
    let thunk = evaluator
        .heap
        .get_thunk(lazy_division)
        .expect("second value remains a heap-owned thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );

    assert_eq!(
        eval_string_bytes(
            "builtins.concatStringsSep \",\" (builtins.attrValues { a = \"a\"; _ = \"_\"; aa = \"aa\"; A = \"A\"; })"
        ),
        b"A,_,a,aa"
    );

    assert_eq!(
        eval_list_string_bytes(
            "let builtins = { attrValues = x: [ \"local\" ]; }; in builtins.attrValues { a = 1; }"
        ),
        vec![b"local".to_vec()]
    );
}

#[test]
fn attr_values_primop_type_checks_argument() {
    let ir = lower("builtins.attrValues 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("attrValues requires an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);
}
