//! Tests for `NixNative::eval_expr` strict-JSON evaluation and its
//! fallback-eligibility boundaries.

use super::*;

#[test]
fn native_eval_error_reports_invalid_ir_as_eval_error() {
    let error = TreeWalkError::new(
        TreeWalkErrorKind::InvalidNodeKind {
            id: IrId::new(0),
            kind: IrKind::Formal,
        },
        Span::new(0, 1),
    );

    let native = native_eval_error(error, None);

    let NativeEvalError::EvalError { message } = native else {
        panic!("invalid IR should not fall back to native CLI");
    };
    assert!(message.contains("invalid tree-walk node Formal"));
}

#[test]
fn native_expression_eval_renders_strict_json() -> Result<()> {
    let native = NixNative::new(0)?;

    assert_eq!(native.eval_expr("1 + 1")?, "2");
    assert_eq!(native.eval_expr("1 # trailing comment")?, "1");
    assert_eq!(native.eval_expr(r#""x""#)?, r#""x""#);
    assert_eq!(
        native.eval_expr(r#"{ b = 1; a = [ true null "x" ]; }"#)?,
        r#"{"a":[true,null,"x"],"b":1}"#
    );

    Ok(())
}

#[test]
fn native_expression_eval_uses_configured_parse_cache() -> Result<()> {
    let root = unique_temp_dir("native-expression-parse-cache");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let cache_root = root.join("parse");
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(&cache_root);
    let native = NixNative::with_options(0, options)?;
    let expr = "1 + 1";

    assert_eq!(native.eval_expr(expr)?, "2");

    let cache = ParseCache::new(&cache_root);
    let entry = cache.entry_for_source(json_wrapper_source(expr).as_bytes());
    assert!(
        entry.is_complete(),
        "native expression evaluation should populate the parse-cache entry"
    );

    assert_eq!(native.eval_expr(expr)?, "2");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_parse_cache_preserves_frontend_error_spans() -> Result<()> {
    let root = unique_temp_dir("native-expression-parse-cache-error");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(root.join("parse"));
    let native = NixNative::with_options(0, options)?;

    let err = native
        .eval_expr("let { body = 1; }")
        .expect_err("frontend gaps should fall back through the cached path");

    assert_parse_source_report(&err);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_expression_parse_error_uses_source_report() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr("let { body = 1; }")
        .expect_err("parse errors should stay fallback-eligible");

    assert_parse_source_report(&err);
    Ok(())
}

#[test]
fn native_expression_duplicate_attr_reports_multiple_labels() -> Result<()> {
    let native = NixNative::new(0)?;
    for source in ["{ a = 1; a = 2; }", "{ a.b = 1; a.b = 2; }"] {
        let err = native
            .eval_expr(source)
            .expect_err("duplicate attr paths should stay fallback-eligible");

        let Some(NativeEvalError::Unsupported {
            feature,
            span: Some(_),
        }) = err.downcast_ref::<NativeEvalError>()
        else {
            panic!("duplicate attr paths should stay unsupported fallback errors: {err:?}");
        };
        assert!(
            feature.contains("aos_nix::parse::duplicate_attribute"),
            "{feature}"
        );
        assert!(feature.contains("first definition"), "{feature}");
        assert!(feature.contains("duplicate definition"), "{feature}");
        assert!(feature.contains(source), "{feature}");
        assert!(!feature.contains("OutOfBounds"), "{feature}");
        assert!(!feature.contains("builtins.toJSON"), "{feature}");
    }
    Ok(())
}

fn assert_parse_source_report(err: &anyhow::Error) {
    let Some(NativeEvalError::Unsupported {
        feature,
        span: Some(_),
    }) = err.downcast_ref::<NativeEvalError>()
    else {
        panic!("parse errors should stay unsupported fallback errors: {err:?}");
    };
    assert!(
        feature.contains("native expression parse failure"),
        "{feature}"
    );
    assert!(feature.contains("aos_nix::parse::"), "{feature}");
    assert!(feature.contains("expr.nix"), "{feature}");
    assert!(feature.contains("let { body = 1; }"), "{feature}");
    assert!(!feature.contains("builtins.toJSON"), "{feature}");
}

#[test]
fn native_expression_scope_error_uses_source_report() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr("let ${name} = 1; in 1")
        .expect_err("scope errors should stay fallback-eligible");

    assert_scope_source_report(&err);
    Ok(())
}

#[test]
fn native_expression_parse_cache_preserves_scope_error_report() -> Result<()> {
    let root = unique_temp_dir("native-expression-scope-cache-error");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let mut options = TreeWalkOptions::new();
    options.set_parse_cache_root(root.join("parse"));
    let native = NixNative::with_options(0, options)?;

    let err = native
        .eval_expr("let ${name} = 1; in 1")
        .expect_err("scope errors should stay fallback-eligible through the cached path");

    assert_scope_source_report(&err);

    fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_scope_source_report(err: &anyhow::Error) {
    let Some(NativeEvalError::Unsupported {
        feature,
        span: Some(_),
    }) = err.downcast_ref::<NativeEvalError>()
    else {
        panic!("scope errors should stay unsupported fallback errors: {err:?}");
    };
    assert!(
        feature.contains("native expression resolve failure"),
        "{feature}"
    );
    assert!(
        feature.contains("aos_nix::resolve::dynamic_let_binding"),
        "{feature}"
    );
    assert!(feature.contains("expr.nix"), "{feature}");
    assert!(feature.contains("let ${name} = 1; in 1"), "{feature}");
    assert!(!feature.contains("builtins.toJSON"), "{feature}");
}

#[test]
fn configured_cpp_nix_native_expression_eval_matches_cli_json() -> Result<()> {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured native eval_expr check");
        return Ok(());
    };
    let native = NixNative::new(0)?;

    for source in [
        "1 + 1",
        "1 # trailing comment",
        r#""x""#,
        r#"{ b = 1; a = [ true null "x" ]; }"#,
        r#"builtins.toJSON { a = "x"; }"#,
    ] {
        let output = Command::new(&oracle)
            .args(["--eval", "--strict", "--json", "--expr", source])
            .output()?;
        assert!(
            output.status.success(),
            "C++ Nix oracle unexpectedly rejected {source:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = String::from_utf8(output.stdout)?.trim().to_string();
        assert_eq!(native.eval_expr(source)?, expected, "{source}");
    }

    Ok(())
}

#[test]
fn native_expression_eval_reports_semantic_errors() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr("1 + true")
        .expect_err("type errors are native evaluation errors");

    let Some(NativeEvalError::EvalError { message }) = err.downcast_ref::<NativeEvalError>() else {
        panic!("type error should surface as a native eval error: {err:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(message.contains("expr.nix"), "{message}");
    assert!(message.contains("1 + true"), "{message}");
    assert!(!message.contains("builtins.toJSON"), "{message}");

    for source in ["length", "currentTime"] {
        let err = native
            .eval_expr(source)
            .expect_err("unresolved globals are native evaluation errors");

        assert!(
            matches!(
                err.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::EvalError { message })
                    if message.contains("unresolved global variable")
            ),
            "{source}: {err:?}"
        );
    }
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
                    EffectClass::Pure,
                    IrData::Symbol(builtins),
                ),
                IrNode::new(
                    IrKind::Select,
                    Span::new(0, 8),
                    EffectClass::Pure,
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
fn native_expression_eval_keeps_frontend_gaps_fallback_eligible() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr("let { body = 1; }")
        .expect_err("frontend gaps should fall back to the CLI");

    assert!(matches!(
        err.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::Unsupported { feature, .. })
            if feature.contains("native expression parse failure")
    ));
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
fn native_expression_eval_keeps_missing_features_fallback_eligible() -> Result<()> {
    let native = NixNative::new(0)?;
    let err = native
        .eval_expr(r#"builtins.import "/tmp/aos-nix-native-missing-import.nix""#)
        .expect_err("unsupported features are still reported as unsupported");

    assert!(matches!(
        err.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::Unsupported { feature, span: Some(_) })
            if feature.contains("effectful expression evaluation")
                || feature.contains("CLI-sensitive builtin evaluation")
                || feature.contains("unsupported tree-walk primop")
    ));
    assert_eq!(native.name(), "aos-nix");
    Ok(())
}
