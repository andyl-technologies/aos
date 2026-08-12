//! Split-out `expr_eval.rs` test group (split).

use super::*;

#[test]
fn native_expression_diagnostic_source_must_match_selected_range() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr_with_diagnostic_source("let x = 1; in x", "repl-input.nix", "x + 1", 14..15)
        .expect_err("mismatched diagnostic source should be rejected");

    assert!(
        matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Internal { message })
                if message.contains("diagnostic source does not match")
        ),
        "{err:?}"
    );
    Ok(())
}

#[test]
fn native_expression_type_error_reports_operand_labels() -> Result<()> {
    let native = NixNative::new(0)?;
    for source in ["1 + \"x\"", "1 > \"x\"", "1 <= \"x\""] {
        let err = native
            .eval_expr(source)
            .expect_err("type errors are native evaluation errors");

        let Some(NativeEvalError::EvalError { message }) = err.downcast_ref::<NativeEvalError>()
        else {
            panic!("type error should surface as a native eval error: {err:?}");
        };
        assert!(message.contains("aos_nix::eval::type"), "{message}");
        assert!(message.contains("left operand"), "{message}");
        assert!(message.contains("right operand"), "{message}");
        assert!(message.contains(source), "{message}");
        assert!(!message.contains("builtins.toJSON"), "{message}");
        assert!(!message.contains("OutOfBounds"), "{message}");
    }

    Ok(())
}

#[test]
fn native_expression_type_error_reports_add_error_context_labels() -> Result<()> {
    let native = NixNative::new(0)?;
    let source = r#"builtins.addErrorContext "ctx" (1 + true)"#;
    let err = native
        .eval_expr(source)
        .expect_err("type errors with logical context are native evaluation errors");

    let Some(NativeEvalError::EvalError { message }) = err.downcast_ref::<NativeEvalError>() else {
        panic!("type error should surface as a native eval error: {err:?}");
    };
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(message.contains("while evaluating: ctx"), "{message}");
    assert!(message.contains(source), "{message}");
    assert!(!message.contains("builtins.toJSON"), "{message}");
    Ok(())
}

#[test]
fn native_expression_eval_summarizes_and_expands_logical_traces_by_verbosity() -> Result<()> {
    let source = r#"
        builtins.addErrorContext "one" (
          builtins.addErrorContext "two" (
            builtins.addErrorContext "three" (
              builtins.addErrorContext "four" (builtins.throw "boom")
            )
          )
        )
    "#;

    let summary_err = NixNative::new(0)?
        .eval_expr(source)
        .expect_err("throw should render a summarized native trace");
    let Some(NativeEvalError::EvalError { message: summary }) =
        summary_err.downcast_ref::<NativeEvalError>()
    else {
        panic!("throw should surface as a native eval error: {summary_err:?}");
    };
    let summary_trace = summary
        .split("Evaluation trace:")
        .nth(1)
        .expect("summary diagnostic should include an appended trace");
    assert!(
        summary_trace.contains("while evaluating: one at expr.nix:"),
        "{summary}"
    );
    assert!(summary_trace.contains("1 more frame hidden"), "{summary}");
    assert!(
        !summary_trace.contains("while evaluating: four"),
        "{summary}"
    );

    let full_err = NixNative::new(1)?
        .eval_expr(source)
        .expect_err("throw should render a full native trace");
    let Some(NativeEvalError::EvalError { message: full }) =
        full_err.downcast_ref::<NativeEvalError>()
    else {
        panic!("throw should surface as a native eval error: {full_err:?}");
    };
    let full_trace = full
        .split("Evaluation trace:")
        .nth(1)
        .expect("full diagnostic should include an appended trace");
    assert!(
        full_trace.contains("while evaluating: four at expr.nix:"),
        "{full}"
    );
    assert!(!full_trace.contains("hidden"), "{full}");
    Ok(())
}

#[test]
fn native_expression_import_error_does_not_attribute_root_trace_context_to_child_source()
-> Result<()> {
    let root = unique_temp_dir("native-expression-imported-trace-source");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let child = root.join("child.nix");
    let child_source = format!(r#"let padding = "{}"; in 1 + true"#, "a".repeat(256));
    fs::write(&child, child_source.as_bytes())?;
    let expr = format!(
        r#"builtins.addErrorContext "root context" (import {})"#,
        child.to_string_lossy()
    );
    let source = json_wrapper_source(&expr);
    let source_map = WrappedSourceMap {
        prefix_len: JSON_WRAPPER_PREFIX.len(),
        expr_len: expr.len(),
    };
    let diagnostic_source = NativeDiagnosticSource::new("expr.nix", &expr, Some(source_map));
    let native = NixNative::new(1)?;
    let ir = native.lower_native_source(&source, Some(source_map), Some(diagnostic_source))?;
    let error = native
        .eval_ir(&ir)
        .expect_err("imported child type error should fail native evaluation");
    let native_error =
        native_eval_error_with_source_trace(error, diagnostic_source, EvalTraceStyle::Full);

    let NativeEvalError::EvalError { message } = native_error else {
        panic!("imported child type error should surface as native eval error");
    };
    let trace = message
        .split("Evaluation trace:")
        .nth(1)
        .expect("diagnostic should include an appended trace");
    assert!(
        trace.contains("while evaluating: root context"),
        "{message}"
    );
    assert!(
        !trace.contains(&format!(
            "while evaluating: root context at {}",
            child.to_string_lossy()
        )),
        "{message}"
    );
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_json_preflight_ignores_malformed_empty_builtins_attr_paths() {
    use crate::compile::{IrArena, IrInlineCacheSiteId, IrNode};
    use crate::syntax::SymbolTable;

    let mut symbols = SymbolTable::new();
    let builtins = symbols.intern(b"builtins").expect("symbol interns");
    let ir = Ir {
        root: IrId::new(1),
        arena: IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::GlobalVar,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::GlobalVar {
                        site: IrInlineCacheSiteId::new(0),
                        symbol: builtins,
                    },
                ),
                IrNode::new(
                    IrKind::Select,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::Select {
                        site: IrInlineCacheSiteId::new(0),
                        receiver: IrId::new(0),
                        path: IrAttrPathId::new(0),
                        default: None,
                    },
                ),
            ],
            Vec::new(),
        ),
        facts: IrFacts::conservative(2),
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: vec![Vec::<IrAttrPathSegment>::new().into_boxed_slice()].into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };

    assert_eq!(
        builtins_global_native_json_fallback_feature(&ir, 0, &TreeWalkOptions::new()),
        None
    );
}

#[test]
fn native_expression_eval_rejects_cli_sensitive_builtins() -> Result<()> {
    let native = NixNative::new(0)?;

    for source in [
        r#"builtins.getEnv "HOME""#,
        "builtins.nixPath",
        "builtins.builtins",
        "builtins.currentTime",
        "builtins ? currentSystem",
        "builtins.attrNames builtins",
        "builtins.fetchMercurial",
        "<nixpkgs>",
        r#"derivation { name = "x"; system = "x86_64-linux"; builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder"; }"#,
        r#"builtins.derivation { name = "x"; system = "x86_64-linux"; builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder"; }"#,
    ] {
        let err = native
            .eval_expr(source)
            .expect_err("CLI-sensitive expressions must fall back");
        assert!(
            matches!(
                err.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { span: Some(_), .. })
            ),
            "{source}"
        );
    }

    Ok(())
}

#[test]
fn native_expression_eval_reports_flakes_as_the_fallback_feature() -> Result<()> {
    let native = NixNative::new(0)?;

    for source in [
        r#"builtins.getFlake "github:NixOS/nixpkgs/0000000000000000000000000000000000000000""#,
        "builtins.getFlake or null",
    ] {
        let err = native
            .eval_expr(source)
            .expect_err("flake expressions must fall back");
        assert!(
            matches!(
                err.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                    if feature == "flakes"
            ),
            "{source}: {err:?}"
        );
    }

    Ok(())
}

#[test]
fn native_expression_eval_supports_pure_flake_ref_helpers() -> Result<()> {
    let native = NixNative::new(0)?;

    assert_eq!(
        native.eval_expr(r#"builtins.parseFlakeRef "github:NixOS/nixpkgs/23.05?dir=lib""#)?,
        r#"{"dir":"lib","owner":"NixOS","ref":"23.05","repo":"nixpkgs","type":"github"}"#
    );
    assert_eq!(
        native.eval_expr(r#"let parse = builtins.parseFlakeRef; in parse "nixpkgs/unstable""#)?,
        r#"{"id":"nixpkgs","ref":"unstable","type":"indirect"}"#
    );
    assert_eq!(
        native.eval_expr(
            r#"let b = { inherit (builtins) parseFlakeRef; }; in b.parseFlakeRef "nixpkgs/unstable""#
        )?,
        r#"{"id":"nixpkgs","ref":"unstable","type":"indirect"}"#
    );
    assert_eq!(
        native.eval_expr(
            r#"let render = builtins.flakeRefToString; in render {
                dir = "lib";
                owner = "NixOS";
                ref = "23.05";
                repo = "nixpkgs";
                type = "github";
            }"#
        )?,
        r#""github:NixOS/nixpkgs/23.05?dir=lib""#
    );
    assert_eq!(
        native.eval_expr(
            r#"let b = { inherit (builtins) flakeRefToString; }; in b.flakeRefToString {
                type = "indirect";
                id = "nixpkgs";
            }"#
        )?,
        r#""flake:nixpkgs""#
    );

    Ok(())
}

#[test]
fn native_expression_eval_uses_configured_current_system_and_time() -> Result<()> {
    let native = NixNative::with_options(
        0,
        TreeWalkOptions::with_current_system(b"aos-test-target".to_vec())?,
    )?;

    assert_eq!(
        native.eval_expr("builtins.currentSystem")?,
        "\"aos-test-target\""
    );
    assert_eq!(
        native.eval_expr(r#"builtins.currentSystem or "fallback""#)?,
        "\"aos-test-target\""
    );

    let native = NixNative::with_options(0, TreeWalkOptions::with_current_time(1_700_000_000)?)?;
    assert_eq!(native.eval_expr("builtins.currentTime")?, "1700000000");
    assert_eq!(
        native.eval_expr("builtins.currentTime or 42")?,
        "1700000000"
    );
    Ok(())
}

#[test]
fn configured_native_expression_eval_still_rejects_reified_builtins_inventory() -> Result<()> {
    let native = NixNative::with_options(
        0,
        TreeWalkOptions::with_current_system(b"aos-test-target".to_vec())?,
    )?;

    let err = native
        .eval_expr("builtins.attrNames builtins")
        .expect_err("reified builtins inventory should still fall back");
    assert!(
        matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { span: Some(_), .. })
        ),
        "{err:?}"
    );
    Ok(())
}

#[test]
fn native_expression_eval_supports_legacy_let_attrsets() -> Result<()> {
    let native = NixNative::new(0)?;
    assert_eq!(native.eval_expr("let { body = 1; }")?, "1");
    assert_eq!(native.eval_expr("let { x = 1; body = x + 1; }")?, "2");
    assert_eq!(native.eval_expr("let { body.foo = 1; }")?, r#"{"foo":1}"#);
    assert_eq!(
        native.eval_expr(r#"let { "${"body"}" = "interp"; }"#)?,
        r#""interp""#
    );
    assert_eq!(
        native.eval_expr(r#"let { name = "body"; ${name} = "dynamic"; }"#)?,
        r#""dynamic""#
    );
    assert_eq!(native.eval_expr(r#"let { "body" = "ok"; }"#)?, r#""ok""#);
    Ok(())
}

#[test]
fn native_expression_eval_handles_functor_application() -> Result<()> {
    let native = NixNative::new(0)?;
    let json = native.eval_expr("({ __functor = self: x: x + 1; } 1)")?;

    assert_eq!(json, "2");
    Ok(())
}

#[test]
fn native_expression_eval_keeps_non_functor_attrset_application_fallback_eligible() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr("({} 1)")
        .expect_err("non-functor attrset application should fall back to the CLI");

    assert!(matches!(
        err.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::Unsupported { feature, span: Some(_) })
            if feature.contains("type error")
    ));
    Ok(())
}

#[test]
fn native_expression_eval_reports_missing_import_as_eval_error() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr(r#"import "/tmp/aos-nix-native-missing-import.nix""#)
        .expect_err("missing imports should report native eval errors");

    assert!(matches!(
        err.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::EvalError { .. })
    ));
    assert_eq!(native.name(), "aos-nix");
    Ok(())
}
