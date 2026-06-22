//! Tree-walk test support: pinned-surface and rejection assertions.

use super::super::*;
use super::eval::lower;
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvalErrorClass {
    Parse,
    Type,
    Throw,
    Assertion,
    Abort,
}

pub(crate) fn assert_cpp_nix_error_classes_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for (source, expected) in [
        ("if true then 1", EvalErrorClass::Parse),
        ("if 1 then 2 else 3", EvalErrorClass::Type),
        (
            r#"builtins.throw "class-throw-sentinel""#,
            EvalErrorClass::Throw,
        ),
        ("assert false; 2", EvalErrorClass::Assertion),
        (
            r#"builtins.abort "class-abort-sentinel""#,
            EvalErrorClass::Abort,
        ),
    ] {
        assert_eq!(
            cpp_nix_eval_failure_class(oracle, source),
            expected,
            "C++ Nix oracle error class diverged for {source:?}",
        );
        assert_eq!(
            tree_walk_eval_failure_class(source),
            expected,
            "tree-walk error class diverged for {source:?}",
        );
    }
}

fn cpp_nix_eval_failure_class(oracle: &str, source: &str) -> EvalErrorClass {
    let output = Command::new(oracle)
        .args(["--eval", "--strict", "--json", "--expr", source])
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly accepted {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    classify_cpp_nix_eval_failure(&stderr)
        .unwrap_or_else(|| panic!("unclassified C++ Nix error for {source:?}: {stderr}"))
}

fn classify_cpp_nix_eval_failure(stderr: &str) -> Option<EvalErrorClass> {
    if stderr.contains("syntax error") {
        Some(EvalErrorClass::Parse)
    } else if stderr.contains("evaluation aborted")
        || stderr.contains("calling the 'abort' builtin")
    {
        Some(EvalErrorClass::Abort)
    } else if stderr.contains("calling the 'throw' builtin") {
        Some(EvalErrorClass::Throw)
    } else if stderr.contains("assertion") && stderr.contains("failed") {
        Some(EvalErrorClass::Assertion)
    } else if stderr.contains("expected ") && stderr.contains(" but found ") {
        Some(EvalErrorClass::Type)
    } else {
        None
    }
}

fn tree_walk_eval_failure_class(source: &str) -> EvalErrorClass {
    let parsed = match parse_str(source) {
        Ok(parsed) => parsed,
        Err(_) => return EvalErrorClass::Parse,
    };
    let resolved = resolve_ast(parsed).expect("source resolves");
    let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
    let error = eval_whnf_owned(&ir).expect_err("tree-walk rejects expression");
    match error.kind() {
        TreeWalkErrorKind::Type { .. } => EvalErrorClass::Type,
        TreeWalkErrorKind::Thrown { .. } => EvalErrorClass::Throw,
        TreeWalkErrorKind::AssertionFailed { .. } => EvalErrorClass::Assertion,
        TreeWalkErrorKind::Aborted { .. } => EvalErrorClass::Abort,
        kind => panic!("unclassified tree-walk error for {source:?}: {kind:?}"),
    }
}

pub(crate) fn assert_cpp_nix_json_matches_tree_walk(oracle: &str, source: &str) {
    let reference = cpp_nix_eval_json(oracle, source);
    let candidate = eval_json_bytes(source);
    assert_eq!(candidate, reference, "expression diverged: {source}");
}

pub(crate) fn assert_cpp_nix_json_matches_tree_walk_with_options_and_env(
    oracle: &str,
    source: &str,
    options: TreeWalkOptions,
    env: &[(&str, &str)],
) {
    let reference = cpp_nix_eval_json_with_env(oracle, source, env);
    let candidate = eval_json_bytes_with_options(source, options);
    assert_eq!(candidate, reference, "expression diverged: {source}");
}

pub(crate) fn assert_cpp_nix_json_matches_tree_walk_with_nix_options(
    oracle: &str,
    source: &str,
    nix_options: &[(&str, &str)],
    options: TreeWalkOptions,
) {
    let reference = cpp_nix_eval_json_with_nix_options(oracle, source, nix_options);
    let candidate = eval_cpp_json_bytes_with_options(source, options);
    assert_eq!(candidate, reference, "expression diverged: {source}");
}

pub(crate) fn assert_pinned_cpp_nix_builtin_surface_matches_registry(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    let mut options =
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec()).expect("system valid");
    options.set_current_time(1_700_000_000).expect("time valid");

    let fixture = pinned_builtin_names_json();
    for source in [
        "builtins.attrNames builtins",
        "builtins.attrNames builtins.builtins",
    ] {
        let reference = cpp_nix_eval_json_with_pinned_builtin_surface_features(oracle, source);
        assert_eq!(
            reference, fixture,
            "{source} should match the pinned builtin surface fixture",
        );

        let candidate = eval_json_bytes_with_options(source, options.clone());
        assert_eq!(candidate, reference, "expression diverged: {source}");
    }

    let type_source = "builtins.typeOf builtins.builtins";
    let reference = cpp_nix_eval_json_with_pinned_builtin_surface_features(oracle, type_source);
    let candidate = eval_json_bytes_with_options(type_source, options.clone());
    assert_eq!(candidate, reference, "expression diverged: {type_source}");

    for name in LIB_NOT_BUILTIN_NAMES {
        let source = format!("builtins.hasAttr {} builtins", nix_string_literal(name));
        let reference = cpp_nix_eval_json_with_pinned_builtin_surface_features(oracle, &source);
        assert_eq!(
            reference, b"false",
            "{name} should not appear in pinned C++ Nix builtins",
        );

        let candidate = eval_json_bytes_with_options(&source, options.clone());
        assert_eq!(candidate, reference, "expression diverged: {source}");
    }
}

pub(crate) fn assert_pinned_present_unimplemented_builtin_stubs_match_registry(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for name in PRESENT_UNIMPLEMENTED_BUILTIN_STUBS {
        let type_source = format!("builtins.typeOf (builtins.{name} or 42)");
        let reference =
            cpp_nix_eval_json_with_pinned_builtin_surface_features(oracle, &type_source);
        assert_eq!(
            reference, b"\"lambda\"",
            "{name} should select as a pinned C++ Nix builtin function",
        );
        let candidate = eval_json_bytes(&type_source);
        assert_eq!(candidate, reference, "expression diverged: {type_source}");

        let args_source =
            format!("builtins.attrNames (builtins.functionArgs (builtins.{name} or 42))");
        let reference =
            cpp_nix_eval_json_with_pinned_builtin_surface_features(oracle, &args_source);
        assert_eq!(
            reference, b"[]",
            "{name} should expose primop-style empty functionArgs",
        );
        let candidate = eval_json_bytes(&args_source);
        assert_eq!(candidate, reference, "expression diverged: {args_source}");
    }
}

pub(crate) fn assert_cpp_nix_identity_constants_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        "builtins.true",
        "builtins.false",
        "builtins.null",
        "builtins.true == true",
        "builtins.false == false",
        "builtins.null == null",
        "builtins ? true",
        "builtins ? false",
        "builtins ? null",
        "builtins ? storeDir",
        "builtins ? nixVersion",
        "builtins ? langVersion",
        "builtins.typeOf builtins.true",
        "builtins.typeOf builtins.false",
        "builtins.typeOf builtins.null",
        "builtins.storeDir",
        "builtins.typeOf builtins.storeDir",
        "builtins.storeDir or \"fallback\"",
        "builtins.nixVersion",
        "builtins.typeOf builtins.nixVersion",
        "builtins.nixVersion or \"fallback\"",
        "builtins.langVersion",
        "builtins.typeOf builtins.langVersion",
        "builtins.langVersion or 42",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    let options = TreeWalkOptions::with_env_var(
        b"AOS_NIX_TEST_GET_ENV".to_vec(),
        b"configured-value".to_vec(),
    );
    for source in [
        r#"builtins.getEnv "AOS_NIX_TEST_GET_ENV""#,
        r#"let getEnv = builtins.getEnv; in getEnv "AOS_NIX_TEST_GET_ENV""#,
    ] {
        assert_cpp_nix_json_matches_tree_walk_with_options_and_env(
            oracle,
            source,
            options.clone(),
            &[("AOS_NIX_TEST_GET_ENV", "configured-value")],
        );
    }
}

pub(crate) fn assert_cpp_nix_to_json_matches_tree_walk(oracle: &str, source: &str) {
    let wrapped = format!("builtins.toJSON ({source})");
    let reference = cpp_nix_eval_string(oracle, &wrapped);
    let candidate = eval_string_bytes(&wrapped);
    assert_eq!(candidate, reference, "toJSON expression diverged: {source}");
}

pub(crate) fn assert_cpp_nix_to_xml_matches_tree_walk(oracle: &str, source: &str) {
    let wrapped = format!("builtins.toXML ({source})");
    let reference = cpp_nix_eval_string(oracle, &wrapped);
    let candidate = eval_string_bytes(&wrapped);
    assert_eq!(candidate, reference, "toXML expression diverged: {source}");
}

pub(crate) fn assert_cpp_nix_and_tree_walk_reject_expression(oracle: &str, source: &str) {
    let output = Command::new(oracle)
        .args(["--eval", "--strict", "--json", "--expr", source])
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly accepted {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let ir = lower(source);
    eval_whnf_owned(&ir).expect_err("tree-walk rejects expression");
}

pub(crate) fn assert_cpp_nix_parse_and_aos_frontend_reject_expression(oracle: &str, source: &str) {
    let output = Command::new(oracle)
        .args(["--parse", "--expr", source])
        .output()
        .expect("C++ Nix oracle parses expression");
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly parsed {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let Ok(parsed) = parse_str(source) else {
        return;
    };
    let Ok(resolved) = resolve_ast(parsed) else {
        return;
    };
    assert!(
        aos_nix_dialect::nix_lower(resolved).is_err(),
        "AOS frontend unexpectedly accepted {source:?}"
    );
}

pub(crate) fn assert_cpp_nix_and_parser_reject_non_associative_operator(
    oracle: &str,
    source: &str,
    operator: &'static str,
) {
    let output = Command::new(oracle)
        .args(["--parse", "--expr", source])
        .output()
        .expect("C++ Nix oracle parses expression");
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly parsed {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let error = parse_str(source).expect_err("parser rejects operator chaining");
    assert_eq!(
        error.kind(),
        &ParseErrorKind::NonAssociativeOperator { operator }
    );
}

pub(crate) fn assert_cpp_nix_and_tree_walk_reject_with_final_error(
    oracle: &str,
    source: &str,
    expected_message: &str,
    matches_kind: impl FnOnce(&TreeWalkErrorKind) -> bool,
) {
    let output = Command::new(oracle)
        .args(["--eval", "--strict", "--json", "--expr", source])
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly accepted {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let actual_message = stderr.lines().rev().find_map(|line| {
        line.trim_start()
            .strip_prefix("error: ")
            .filter(|message| !message.is_empty())
    });
    assert_eq!(
        actual_message,
        Some(expected_message),
        "C++ Nix oracle error for {source:?} did not end with {expected_message:?}: {stderr}"
    );

    let ir = lower(source);
    let error = eval_whnf_owned(&ir).expect_err("tree-walk rejects expression");
    let kind = error.kind();
    assert!(
        matches_kind(&kind),
        "tree-walk error for {source:?} did not match {expected_message:?}: {error:?}"
    );
}

pub(crate) fn assert_cpp_nix_and_tree_walk_reject_with_final_error_and_nix_options(
    oracle: &str,
    source: &str,
    nix_options: &[(&str, &str)],
    options: TreeWalkOptions,
    expected_message: &str,
    matches_kind: impl FnOnce(&TreeWalkErrorKind) -> bool,
) {
    let output = cpp_nix_eval_stderr_output_with_nix_options(oracle, source, nix_options);
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly accepted {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let actual_message = stderr.lines().rev().find_map(|line| {
        line.trim_start()
            .strip_prefix("error: ")
            .filter(|message| !message.is_empty())
    });
    assert_eq!(
        actual_message,
        Some(expected_message),
        "C++ Nix oracle error for {source:?} did not end with {expected_message:?}: {stderr}"
    );

    let ir = lower(source);
    let error =
        eval_whnf_owned_with_options(&ir, options).expect_err("tree-walk rejects expression");
    let kind = error.kind();
    assert!(
        matches_kind(&kind),
        "tree-walk error for {source:?} did not match {expected_message:?}: {error:?}"
    );
}

pub(crate) fn assert_cpp_nix_and_tree_walk_throw_message(
    oracle: &str,
    source: &str,
    expected_message: &str,
) {
    let output = Command::new(oracle)
        .args(["--eval", "--strict", "--json", "--expr", source])
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly accepted {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let actual_message = stderr.lines().rev().find_map(|line| {
        line.trim_start()
            .strip_prefix("error: ")
            .filter(|message| !message.is_empty())
    });
    assert_eq!(
        actual_message,
        Some(expected_message),
        "C++ Nix oracle error for {source:?} did not end with {expected_message:?}: {stderr}"
    );

    let ir = lower(source);
    let error = eval_whnf_owned(&ir).expect_err("tree-walk rejects expression");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown tree-walk error for {source:?}, got {error:?}");
    };
    assert_eq!(message, expected_message.as_bytes());
}

pub(crate) fn assert_cpp_nix_and_tree_walk_reject_json(oracle: &str, source: &str) {
    let output = Command::new(oracle)
        .args(["--eval", "--strict", "--json", "--expr", source])
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly accepted {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let ir = lower(&format!("builtins.toJSON ({source})"));
    eval_whnf_owned(&ir).expect_err("tree-walk rejects expression");
}

pub(crate) fn assert_cpp_nix_number_printing_matches_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        "1",
        "(-2)",
        "9223372036854775807",
        "(-9223372036854775807 - 1)",
        "1.0",
        "1.25",
        "1.23456789",
        "(-0.0)",
        "0.0001",
        "0.00001",
        "100000.0",
        "1000000.0",
        "((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))",
        "(1.0e308 * 1.0e308)",
        "(builtins.sub 0.0 (1.0e308 * 1.0e308))",
    ] {
        let reference = cpp_nix_eval_raw(oracle, source);
        let candidate =
            eval_number_raw_bytes(&lower(source)).expect("tree-walk renders raw number");
        assert_eq!(
            candidate, reference,
            "raw number rendering diverged for {source}"
        );
    }

    for source in [
        "builtins.toString 1",
        "builtins.toString (-2)",
        "builtins.toString 9223372036854775807",
        "builtins.toString (-9223372036854775807 - 1)",
        "builtins.toString 1.0",
        "builtins.toString 1.25",
        "builtins.toString 1.23456789",
        "builtins.toString (-0.0)",
        "builtins.toString 0.00001",
        "builtins.toString 0.0000001",
        "builtins.toString 1000000.0",
        "builtins.toString ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))",
        "builtins.toString (1.0e308 * 1.0e308)",
        "builtins.toString (builtins.sub 0.0 (1.0e308 * 1.0e308))",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }
}

pub(crate) fn assert_pinned_absent_experimental_builtin_attrs_match_registry(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for name in ["exec", "fetchClosure", "outputOf"] {
        let has_attr = format!(r#"builtins.hasAttr "{name}" builtins"#);
        let reference = cpp_nix_eval_json_with_pinned_builtin_surface_features(oracle, &has_attr);
        assert_eq!(
            reference, b"false",
            "{name} should be absent from the pinned flakes builtin surface"
        );
        let candidate = eval_json_bytes(&has_attr);
        assert_eq!(candidate, reference, "expression diverged: {has_attr}");

        let default = format!("builtins.{name} or 42");
        let reference = cpp_nix_eval_json_with_pinned_builtin_surface_features(oracle, &default);
        assert_eq!(
            reference, b"42",
            "{name} absence should allow select-default fallback"
        );
        let candidate = eval_json_bytes(&default);
        assert_eq!(candidate, reference, "expression diverged: {default}");
    }
}
