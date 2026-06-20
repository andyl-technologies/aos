use super::super::ThunkState;
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    ptr::NonNull,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::compile::{
    EffectClass, FrameId, FrameInfo, IrArena, IrBinding, IrData, IrInlineCacheSiteId, IrNode,
    IrShape, IrWithChain, lower as lower_ir, resolve as resolve_ast,
};
use crate::runtime::builtins::{BUILTINS, Builtin, BuiltinDirect, BuiltinEffect, direct_builtin};
use crate::string::{ContextElement, StringContext};
use crate::syntax::{ParseErrorKind, Symbol, SymbolTable, parse_bytes, parse_str};
use crate::value::HeapObject;

const PINNED_BUILTIN_SURFACE_EXPERIMENTAL_FEATURES: &str = "flakes";

const PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES: &[&str] = &[
    "abort",
    "add",
    "addDrvOutputDependencies",
    "addErrorContext",
    "all",
    "any",
    "appendContext",
    "attrNames",
    "attrValues",
    "baseNameOf",
    "bitAnd",
    "bitOr",
    "bitXor",
    "break",
    "builtins",
    "catAttrs",
    "ceil",
    "compareVersions",
    "concatLists",
    "concatMap",
    "concatStringsSep",
    "convertHash",
    "currentSystem",
    "currentTime",
    "deepSeq",
    "derivation",
    "derivationStrict",
    "dirOf",
    "div",
    "elem",
    "elemAt",
    "false",
    "fetchGit",
    "fetchMercurial",
    "fetchTarball",
    "fetchTree",
    "fetchurl",
    "filter",
    "filterSource",
    "findFile",
    "flakeRefToString",
    "floor",
    "foldl'",
    "fromJSON",
    "fromTOML",
    "functionArgs",
    "genList",
    "genericClosure",
    "getAttr",
    "getContext",
    "getEnv",
    "getFlake",
    "groupBy",
    "hasAttr",
    "hasContext",
    "hashFile",
    "hashString",
    "head",
    "import",
    "intersectAttrs",
    "isAttrs",
    "isBool",
    "isFloat",
    "isFunction",
    "isInt",
    "isList",
    "isNull",
    "isPath",
    "isString",
    "langVersion",
    "length",
    "lessThan",
    "listToAttrs",
    "map",
    "mapAttrs",
    "match",
    "mul",
    "nixPath",
    "nixVersion",
    "null",
    "parseDrvName",
    "parseFlakeRef",
    "partition",
    "path",
    "pathExists",
    "placeholder",
    "readDir",
    "readFile",
    "readFileType",
    "removeAttrs",
    "replaceStrings",
    "scopedImport",
    "seq",
    "sort",
    "split",
    "splitVersion",
    "storeDir",
    "storePath",
    "stringLength",
    "sub",
    "substring",
    "tail",
    "throw",
    "toFile",
    "toJSON",
    "toPath",
    "toString",
    "toXML",
    "trace",
    "traceVerbose",
    "true",
    "tryEval",
    "typeOf",
    "unsafeDiscardOutputDependency",
    "unsafeDiscardStringContext",
    "unsafeGetAttrPos",
    "warn",
    "zipAttrsWith",
];

const PRESENT_UNIMPLEMENTED_BUILTIN_STUBS: &[&str] = &["fetchMercurial"];

const VERSION_GATED_BUILTIN_NAMES: &[&str] = &[
    "addDrvOutputDependencies",
    "convertHash",
    "fetchTree",
    "readFileType",
    "warn",
];

const LIB_NOT_BUILTIN_NAMES: &[&str] = &[
    "toLower",
    "toUpper",
    "toTOML",
    "concatStrings",
    "stringToCharacters",
    "splitString",
    "hasPrefix",
    "hasSuffix",
    "optionalString",
    "removePrefix",
    "removeSuffix",
    "escapeShellArg",
    "versionAtLeast",
    "versionOlder",
    "foldr",
    "foldl",
    "reverse",
    "range",
    "remove",
    "zipWith",
    "flatten",
    "unique",
    "last",
    "init",
    "take",
    "drop",
    "count",
    "imap0",
    "forEach",
    "optionals",
    "mapAttrsToList",
    "filterAttrs",
    "recursiveUpdate",
    "attrByPath",
    "optionalAttrs",
    "mapAttrs'",
    "genAttrs",
    "nameValuePair",
    "id",
    "const",
    "flip",
    "composeManyExtensions",
    "pipe",
    "fix",
    "makeExtensible",
    "importJSON",
    "importTOML",
];

fn lower(source: &str) -> Ir {
    lower_ir(resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"))
        .expect("source lowers")
}

fn lower_bytes(source: &[u8]) -> Ir {
    lower_ir(resolve_ast(parse_bytes(source).expect("source parses")).expect("source resolves"))
        .expect("source lowers")
}

fn eval(source: &str) -> Value {
    eval_whnf(&lower(source)).expect("source evaluates")
}

fn eval_with_options(source: &str, options: TreeWalkOptions) -> Value {
    eval_whnf_with_options(&lower(source), options).expect("source evaluates")
}

fn eval_owned_with_source(source_name: &[u8], source: &str) -> EvalOutcome {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        source_name.to_vec(),
        source.as_bytes().to_vec(),
    );
    let value = evaluator.eval_root().expect("source evaluates");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    EvalOutcome {
        value,
        heap: evaluator.heap,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        derivations,
    }
}

fn eval_string_bytes_with_source(source_name: &[u8], source: &str) -> Vec<u8> {
    let outcome = eval_owned_with_source(source_name, source);
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is a heap-owned string");
    string.bytes().to_vec()
}

fn eval_string_bytes(source: &str) -> Vec<u8> {
    let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is a heap-owned string");
    string.bytes().to_vec()
}

fn eval_string_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    let outcome = eval_whnf_owned_with_options(&lower(source), options).expect("source evaluates");
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is a heap-owned string");
    string.bytes().to_vec()
}

fn eval_path_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    let outcome = eval_whnf_owned_with_options(&lower(source), options).expect("source evaluates");
    let path = outcome
        .heap()
        .get_path(outcome.value())
        .expect("result is a heap-owned path");
    path.bytes().to_vec()
}

fn eval_json_bytes(source: &str) -> Vec<u8> {
    eval_string_bytes(&format!("builtins.toJSON ({source})"))
}

fn eval_json_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    eval_string_bytes_with_options(&format!("builtins.toJSON ({source})"), options)
}

fn eval_cpp_json_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    let ir = lower(source);
    let root = ir.root;
    let root_span = ir.arena.node(root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator.eval_root().expect("source evaluates");
    let mut bytes = Vec::new();
    let mut context = StringContext::empty();
    evaluator
        .write_json_value(
            root,
            root_span,
            root,
            root_span,
            value,
            &mut bytes,
            &mut context,
        )
        .expect("value serializes as JSON");
    bytes
}

fn pinned_builtin_name_bytes() -> Vec<Vec<u8>> {
    PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES
        .iter()
        .map(|name| name.as_bytes().to_vec())
        .collect()
}

fn pinned_builtin_names_json() -> Vec<u8> {
    serde_json::to_vec(PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES)
        .expect("pinned builtin fixture serializes")
}

fn eval_xml_bytes(source: &str) -> Vec<u8> {
    eval_string_bytes(&format!("builtins.toXML ({source})"))
}

fn cpp_nix_oracle() -> String {
    std::env::var("AOS_NIX_ORACLE").unwrap_or_else(|_| "nix-instantiate".to_owned())
}

fn trim_command_stdout(mut stdout: Vec<u8>) -> Vec<u8> {
    while matches!(stdout.last(), Some(b'\n' | b'\r')) {
        let _ = stdout.pop();
    }
    stdout
}

fn cpp_nix_version(oracle: &str) -> String {
    let output = Command::new(oracle)
        .arg("--version")
        .output()
        .expect("C++ Nix oracle runs");
    assert!(
        output.status.success(),
        "C++ Nix oracle version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(trim_command_stdout(output.stdout)).expect("version is UTF-8")
}

fn assert_pinned_cpp_nix_oracle(oracle: &str) {
    let version = cpp_nix_version(oracle);
    let pinned = std::str::from_utf8(PINNED_NIX_VERSION).expect("pinned version is UTF-8");
    assert!(
        version.ends_with(&format!(" {pinned}")) || version.ends_with(&format!("(Nix) {pinned}")),
        "expected pinned C++ Nix {pinned} oracle, got {version}"
    );
    eprintln!("C++ Nix oracle: {version}");
}

fn cpp_nix_eval_json(oracle: &str, source: &str) -> Vec<u8> {
    let mut command = Command::new(oracle);
    command.args(["--eval", "--strict", "--json", "--expr", source]);
    let output = command
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    trim_command_stdout(output.stdout)
}

fn cpp_nix_eval_raw(oracle: &str, source: &str) -> Vec<u8> {
    let mut command = Command::new(oracle);
    command.args(["--eval", "--strict", "--expr", source]);
    let output = command
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    trim_command_stdout(output.stdout)
}

fn cpp_nix_eval_json_with_nix_options(
    oracle: &str,
    source: &str,
    options: &[(&str, &str)],
) -> Vec<u8> {
    let mut command = Command::new(oracle);
    for (name, value) in options {
        command.args(["--option", name, value]);
    }
    command.args(["--eval", "--strict", "--json", "--expr", source]);
    let output = command
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    trim_command_stdout(output.stdout)
}

fn cpp_nix_eval_stderr_with_nix_options(
    oracle: &str,
    source: &str,
    options: &[(&str, &str)],
) -> Vec<u8> {
    let output = cpp_nix_eval_stderr_output_with_nix_options(oracle, source, options);
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stderr
}

fn cpp_nix_eval_failure_stderr_with_nix_options(
    oracle: &str,
    source: &str,
    options: &[(&str, &str)],
) -> Vec<u8> {
    let output = cpp_nix_eval_stderr_output_with_nix_options(oracle, source, options);
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly succeeded for {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    output.stderr
}

fn cpp_nix_eval_stderr_output_with_nix_options(
    oracle: &str,
    source: &str,
    options: &[(&str, &str)],
) -> std::process::Output {
    let mut command = Command::new(oracle);
    let path = std::env::var_os("PATH");
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    command.env("HOME", "/homeless-shelter");
    command.args(["--option", "trace-verbose", "false"]);
    command.args(["--option", "abort-on-warn", "false"]);
    for (name, value) in options {
        command.args(["--option", name, value]);
    }
    command.args(["--eval", "--strict", "--expr", source]);
    command
        .output()
        .expect("C++ Nix oracle evaluates expression")
}

fn cpp_nix_eval_stderr(oracle: &str, source: &str) -> Vec<u8> {
    cpp_nix_eval_stderr_with_nix_options(oracle, source, &[])
}

fn cpp_nix_eval_json_with_pinned_builtin_surface_features(oracle: &str, source: &str) -> Vec<u8> {
    cpp_nix_eval_json_with_nix_options(
        oracle,
        source,
        &[(
            "experimental-features",
            PINNED_BUILTIN_SURFACE_EXPERIMENTAL_FEATURES,
        )],
    )
}

fn cpp_nix_eval_json_with_env(oracle: &str, source: &str, env: &[(&str, &str)]) -> Vec<u8> {
    let mut command = Command::new(oracle);
    command.args(["--eval", "--strict", "--json", "--expr", source]);
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    trim_command_stdout(output.stdout)
}

fn cpp_nix_eval_string(oracle: &str, source: &str) -> Vec<u8> {
    let json = cpp_nix_eval_json(oracle, source);
    serde_json::from_slice::<String>(&json)
        .expect("C++ Nix oracle returned a JSON string")
        .into_bytes()
}

fn assert_cpp_nix_json_matches_tree_walk(oracle: &str, source: &str) {
    let reference = cpp_nix_eval_json(oracle, source);
    let candidate = eval_json_bytes(source);
    assert_eq!(candidate, reference, "expression diverged: {source}");
}

fn assert_cpp_nix_json_matches_tree_walk_with_options_and_env(
    oracle: &str,
    source: &str,
    options: TreeWalkOptions,
    env: &[(&str, &str)],
) {
    let reference = cpp_nix_eval_json_with_env(oracle, source, env);
    let candidate = eval_json_bytes_with_options(source, options);
    assert_eq!(candidate, reference, "expression diverged: {source}");
}

fn assert_cpp_nix_json_matches_tree_walk_with_nix_options(
    oracle: &str,
    source: &str,
    nix_options: &[(&str, &str)],
    options: TreeWalkOptions,
) {
    let reference = cpp_nix_eval_json_with_nix_options(oracle, source, nix_options);
    let candidate = eval_cpp_json_bytes_with_options(source, options);
    assert_eq!(candidate, reference, "expression diverged: {source}");
}

fn assert_pinned_cpp_nix_builtin_surface_matches_registry(oracle: &str) {
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

fn assert_pinned_present_unimplemented_builtin_stubs_match_registry(oracle: &str) {
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

fn assert_cpp_nix_identity_constants_match_tree_walk(oracle: &str) {
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

fn assert_cpp_nix_to_json_matches_tree_walk(oracle: &str, source: &str) {
    let wrapped = format!("builtins.toJSON ({source})");
    let reference = cpp_nix_eval_string(oracle, &wrapped);
    let candidate = eval_string_bytes(&wrapped);
    assert_eq!(candidate, reference, "toJSON expression diverged: {source}");
}

fn assert_cpp_nix_to_xml_matches_tree_walk(oracle: &str, source: &str) {
    let wrapped = format!("builtins.toXML ({source})");
    let reference = cpp_nix_eval_string(oracle, &wrapped);
    let candidate = eval_string_bytes(&wrapped);
    assert_eq!(candidate, reference, "toXML expression diverged: {source}");
}

fn assert_cpp_nix_and_tree_walk_reject_expression(oracle: &str, source: &str) {
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

fn assert_cpp_nix_parse_and_aos_frontend_reject_expression(oracle: &str, source: &str) {
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
        lower_ir(resolved).is_err(),
        "AOS frontend unexpectedly accepted {source:?}"
    );
}

fn assert_cpp_nix_and_parser_reject_non_associative_operator(
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

fn assert_cpp_nix_and_tree_walk_reject_with_final_error(
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

fn assert_cpp_nix_and_tree_walk_reject_with_final_error_and_nix_options(
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

fn assert_cpp_nix_and_tree_walk_throw_message(oracle: &str, source: &str, expected_message: &str) {
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

fn assert_cpp_nix_and_tree_walk_reject_json(oracle: &str, source: &str) {
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

fn unique_temp_dir(prefix: &str) -> PathBuf {
    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_nanos();
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "aos-nix-{prefix}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp directory creates");
    dir
}

fn temp_file_with_bytes(prefix: &str, bytes: &[u8]) -> (PathBuf, PathBuf) {
    let dir = unique_temp_dir(prefix);
    let path = dir.join("data.txt");
    fs::write(&path, bytes).expect("temp file writes");
    (dir, path)
}

fn git_signature_with_offset(seconds: i64, offset_minutes: i32) -> git2::Signature<'static> {
    let time = git2::Time::new(seconds, offset_minutes);
    git2::Signature::new("AOS Test", "aos@example.invalid", &time).expect("git signature creates")
}

fn git_commit_index(repo: &git2::Repository, message: &str, seconds: i64) -> git2::Oid {
    git_commit_index_with_offset(repo, message, seconds, 0)
}

fn git_commit_index_with_offset(
    repo: &git2::Repository,
    message: &str,
    seconds: i64,
    offset_minutes: i32,
) -> git2::Oid {
    let mut index = repo.index().expect("git index opens");
    index.write().expect("git index writes");
    let tree_id = index.write_tree().expect("git tree writes");
    let tree = repo.find_tree(tree_id).expect("git tree exists");
    let signature = git_signature_with_offset(seconds, offset_minutes);
    let parent_commits = repo
        .head()
        .ok()
        .and_then(|head| head.peel_to_commit().ok())
        .into_iter()
        .collect::<Vec<_>>();
    let parents = parent_commits.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .expect("git commit creates")
}

fn git_commit_file(
    repo: &git2::Repository,
    relative_path: &str,
    contents: &[u8],
    seconds: i64,
) -> git2::Oid {
    git_commit_file_with_offset(repo, relative_path, contents, seconds, 0)
}

fn git_commit_file_with_offset(
    repo: &git2::Repository,
    relative_path: &str,
    contents: &[u8],
    seconds: i64,
    offset_minutes: i32,
) -> git2::Oid {
    let workdir = repo.workdir().expect("test repo has workdir");
    let path = workdir.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("git fixture parent creates");
    }
    fs::write(&path, contents).expect("git fixture file writes");
    let mut index = repo.index().expect("git index opens");
    index
        .add_path(Path::new(relative_path))
        .expect("git fixture path stages");
    index.write().expect("git index writes");
    git_commit_index_with_offset(repo, "fixture commit", seconds, offset_minutes)
}

fn git_repo_with_file(prefix: &str) -> (PathBuf, git2::Oid) {
    let dir = unique_temp_dir(prefix);
    let repo = git2::Repository::init(&dir).expect("git fixture repo initializes");
    let oid = git_commit_file(&repo, "data.txt", b"git-data", 1_700_000_000);
    (dir, oid)
}

fn git_repo_with_tag(prefix: &str) -> (PathBuf, git2::Oid) {
    let (dir, oid) = git_repo_with_file(prefix);
    let repo = git2::Repository::open(&dir).expect("git fixture repo opens");
    let object = repo
        .find_object(oid, Some(git2::ObjectType::Commit))
        .expect("git fixture commit object exists");
    repo.tag_lightweight("v1", &object, false)
        .expect("git fixture tag creates");
    (dir, oid)
}

fn git_repo_with_submodule(prefix: &str) -> (PathBuf, PathBuf, git2::Oid) {
    let sub_dir = unique_temp_dir(&format!("{prefix}-sub"));
    let sub_repo = git2::Repository::init(&sub_dir).expect("git submodule repo initializes");
    git_commit_file(&sub_repo, "sub.txt", b"submodule-data", 1_700_000_000);

    let parent_dir = unique_temp_dir(prefix);
    let parent_repo = git2::Repository::init(&parent_dir).expect("git parent repo initializes");
    fs::write(parent_dir.join("root.txt"), b"root-data").expect("git parent file writes");
    let sub_url = path_source(&sub_dir);
    let mut submodule = parent_repo
        .submodule(&sub_url, Path::new("deps/sub"), true)
        .expect("git submodule adds");
    submodule.clone(None).expect("git submodule clones");
    submodule
        .add_finalize()
        .expect("git submodule add finalizes");
    let mut index = parent_repo.index().expect("git parent index opens");
    index
        .add_path(Path::new("root.txt"))
        .expect("git parent root file stages");
    index.write().expect("git parent index writes");
    drop(index);
    let oid = git_commit_index(&parent_repo, "parent fixture commit", 1_700_000_060);
    (parent_dir, sub_dir, oid)
}

fn append_tar_bytes<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    mode: u32,
    bytes: &[u8],
) {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).expect("tar path is valid");
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_cksum();
    builder
        .append(&header, bytes)
        .expect("tar fixture entry appends");
}

fn fetch_tarball_fixture(prefix: &str) -> (PathBuf, PathBuf) {
    let dir = unique_temp_dir(prefix);
    let archive_path = dir.join("root.tar.gz");
    let file = fs::File::create(&archive_path).expect("tarball fixture creates");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_tar_bytes(&mut builder, "root/file.txt", 0o644, b"data");
    append_tar_bytes(&mut builder, "root/sub/nested.txt", 0o644, b"inner");
    let encoder = builder.into_inner().expect("tar fixture finalizes");
    encoder.finish().expect("gzip fixture finalizes");
    (dir, archive_path)
}

fn gzip_encoded_http_fixture(
    url_path: &str,
    plain_body: &[u8],
) -> (String, String, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("HTTP fixture binds");
    let address = listener
        .local_addr()
        .expect("HTTP fixture address resolves");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, plain_body).expect("HTTP fixture gzip writes");
    let body = encoder.finish().expect("HTTP fixture gzip finalizes");
    let body_hash = format!("{:x}", Sha256::digest(&body));
    let response_header = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("HTTP fixture accepts request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read =
                std::io::Read::read(&mut stream, &mut buffer).expect("HTTP fixture reads request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        std::io::Write::write_all(&mut stream, response_header.as_bytes())
            .expect("HTTP fixture writes response header");
        std::io::Write::write_all(&mut stream, &body).expect("HTTP fixture writes response body");
        request
    });

    (format!("http://{address}{url_path}"), body_hash, handle)
}

fn assert_http_fixture_requested_identity(request: Vec<u8>, operation: &str) {
    let request = String::from_utf8(request).expect("HTTP request is UTF-8");
    assert!(
        request
            .lines()
            .any(|line| line.eq_ignore_ascii_case("accept-encoding: identity")),
        "{operation} HTTP request should ask for raw identity bytes, got: {request:?}"
    );
}

fn path_source(path: &Path) -> String {
    path.to_str().expect("temp path is UTF-8").to_owned()
}

fn nix_string_literal(text: &str) -> String {
    let mut out = String::from("\"");
    for byte in text.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            byte => out.push(char::from(byte)),
        }
    }
    out.push('"');
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddMatrixKind {
    Int,
    Float,
    String,
    Path,
    Bool,
    Null,
    List,
    PlainAttrs,
    ToStringAttrs,
    OutPathAttrs,
    Lambda,
    Primop,
}

#[derive(Debug)]
struct AddMatrixOperand {
    kind: AddMatrixKind,
    source: String,
}

fn add_operator_matrix_operands(prefix: &str) -> (PathBuf, Vec<AddMatrixOperand>) {
    let dir = unique_temp_dir(prefix);
    let path = dir.join("matrix.txt");
    fs::write(&path, b"matrix").expect("matrix path writes");
    let path = path_source(&path);
    let operands = vec![
        AddMatrixOperand {
            kind: AddMatrixKind::Int,
            source: "1".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Float,
            source: "1.5".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::String,
            source: r#""s""#.to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Path,
            source: path,
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Bool,
            source: "true".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Null,
            source: "null".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::List,
            source: "[ 1 ]".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::PlainAttrs,
            source: "{ a = 1; }".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::ToStringAttrs,
            source: r#"{ __toString = self: "attrs"; }"#.to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::OutPathAttrs,
            source: r#"{ outPath = "out"; }"#.to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Lambda,
            source: "x: x".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Primop,
            source: "builtins.length".to_owned(),
        },
    ];
    (dir, operands)
}

fn add_operator_matrix_source(left: &AddMatrixOperand, right: &AddMatrixOperand) -> String {
    format!("builtins.seq (({}) + ({})) true", left.source, right.source)
}

fn add_operator_matrix_kind_is_string_coercible(kind: AddMatrixKind) -> bool {
    matches!(
        kind,
        AddMatrixKind::String
            | AddMatrixKind::Path
            | AddMatrixKind::ToStringAttrs
            | AddMatrixKind::OutPathAttrs
    )
}

fn add_operator_matrix_cell_is_legal(left: AddMatrixKind, right: AddMatrixKind) -> bool {
    matches!(
        (left, right),
        (
            AddMatrixKind::Int | AddMatrixKind::Float,
            AddMatrixKind::Int | AddMatrixKind::Float
        )
    ) || (matches!(
        left,
        AddMatrixKind::String
            | AddMatrixKind::Path
            | AddMatrixKind::ToStringAttrs
            | AddMatrixKind::OutPathAttrs
    ) && add_operator_matrix_kind_is_string_coercible(right))
}

fn eval_list_string_bytes(source: &str) -> Vec<Vec<u8>> {
    let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
    let list = outcome
        .heap()
        .get_list(outcome.value())
        .expect("result is a heap-owned list");
    list.iter()
        .map(|value| {
            outcome
                .heap()
                .get_string(*value)
                .expect("element is a heap-owned string")
                .bytes()
                .to_vec()
        })
        .collect()
}

fn eval_list_string_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<Vec<u8>> {
    let outcome = eval_whnf_owned_with_options(&lower(source), options).expect("source evaluates");
    let list = outcome
        .heap()
        .get_list(outcome.value())
        .expect("result is a heap-owned list");
    list.iter()
        .map(|value| {
            outcome
                .heap()
                .get_string(*value)
                .expect("element is a heap-owned string")
                .bytes()
                .to_vec()
        })
        .collect()
}

fn eval_list_ints(source: &str) -> Vec<i64> {
    let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
    let list = outcome
        .heap()
        .get_list(outcome.value())
        .expect("result is a heap-owned list");
    list.iter()
        .map(|value| value.as_int().expect("element is an int"))
        .collect()
}

fn eval_owned(source: &str) -> EvalOutcome {
    eval_whnf_owned(&lower(source)).expect("source evaluates")
}

fn eval_owned_with_options(source: &str, options: TreeWalkOptions) -> EvalOutcome {
    eval_whnf_owned_with_options(&lower(source), options).expect("source evaluates")
}

fn assert_trace_output(output: &EvalTraceOutput, kind: EvalTraceKind, message: &[u8]) {
    assert_eq!(output.kind(), kind);
    assert_eq!(output.message(), message);
}

fn assert_warning_output(output: &EvalWarningOutput, message: &[u8]) {
    assert_eq!(output.message(), message);
}

fn eval_captured_stderr_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.capture_stderr();
    evaluator.eval_root().expect("source evaluates");
    evaluator.captured_stderr().to_vec()
}

fn eval_captured_stderr_error_with_options(
    source: &str,
    options: TreeWalkOptions,
) -> (TreeWalkError, Vec<u8>) {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.capture_stderr();
    let error = evaluator.eval_root().expect_err("source fails");
    let stderr = evaluator.captured_stderr().to_vec();
    (error, stderr)
}

fn eval_captured_stderr(source: &str) -> Vec<u8> {
    eval_captured_stderr_with_options(source, TreeWalkOptions::new())
}

fn assert_error_contexts(error: &TreeWalkError, expected: &[&[u8]]) {
    let actual: Vec<&[u8]> = error
        .contexts()
        .iter()
        .map(EvalErrorContext::message)
        .collect();
    assert_eq!(actual, expected);
    let rendered = error.to_string();
    for message in expected {
        let message = String::from_utf8_lossy(message);
        assert!(
            rendered.contains(message.as_ref()),
            "rendered error {rendered:?} omitted context {message:?}"
        );
    }
}

fn symbol_for(ir: &Ir, name: &[u8]) -> Symbol {
    let index = ir
        .symbols
        .symbols()
        .iter()
        .position(|symbol| symbol.as_slice() == name)
        .expect("symbol exists");
    Symbol::new(index as u32)
}

fn primop_argument(ir: &Ir, index: usize) -> (IrId, Span) {
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .get(index)
        .copied()
        .expect("primop argument exists");
    let span = ir.arena.node(argument).expect("argument exists").span;
    (argument, span)
}

fn empty_ir(root: IrId, arena: IrArena) -> Ir {
    Ir {
        root,
        arena,
        symbols: SymbolTable::new(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

fn pure_node(kind: IrKind, span: Span, data: IrData) -> IrNode {
    IrNode::new(kind, span, EffectClass::Pure, data)
}

fn manual_ir(root: IrId, nodes: Vec<IrNode>) -> Ir {
    empty_ir(root, IrArena::from_raw_parts(nodes, Vec::new()))
}

fn manual_ir_with_symbols(root: IrId, nodes: Vec<IrNode>, symbols: SymbolTable) -> Ir {
    Ir {
        root,
        arena: IrArena::from_raw_parts(nodes, Vec::new()),
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

fn manual_ir_with_symbols_and_frames(
    root: IrId,
    nodes: Vec<IrNode>,
    symbols: SymbolTable,
    frames: Vec<FrameInfo>,
) -> Ir {
    Ir {
        root,
        arena: IrArena::from_raw_parts(nodes, Vec::new()),
        symbols,
        frames: frames.into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

fn manual_ir_with_with_chains(
    root: IrId,
    nodes: Vec<IrNode>,
    symbols: SymbolTable,
    with_chains: Vec<IrWithChain>,
) -> Ir {
    Ir {
        root,
        arena: IrArena::from_raw_parts(nodes, Vec::new()),
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: with_chains.into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

fn manual_ir_with_attr_tables(
    root: IrId,
    nodes: Vec<IrNode>,
    symbols: SymbolTable,
    bindings: Vec<IrBinding>,
    shapes: Vec<IrShape>,
) -> Ir {
    Ir {
        root,
        arena: IrArena::from_raw_parts(nodes, Vec::new()),
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: bindings.into_boxed_slice(),
        shapes: shapes.into_boxed_slice(),
    }
}

fn manual_ir_with_attr_paths(
    root: IrId,
    nodes: Vec<IrNode>,
    symbols: SymbolTable,
    attr_paths: Vec<Box<[IrAttrPathSegment]>>,
) -> Ir {
    Ir {
        root,
        arena: IrArena::from_raw_parts(nodes, Vec::new()),
        symbols,
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: attr_paths.into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

fn int_binary_ir(op: BinOpKind, left: i64, right: i64) -> Ir {
    let lhs = IrId::new(0);
    let rhs = IrId::new(1);
    let root = IrId::new(2);
    manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(left)),
            pure_node(IrKind::Int, Span::new(2, 3), IrData::Int(right)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 3),
                IrData::Binary { op, lhs, rhs },
            ),
        ],
    )
}

#[test]
fn evaluates_inline_scalar_literals() {
    assert_eq!(eval("42").as_int(), Ok(42));
    assert_eq!(eval("true").as_bool(), Ok(true));
    assert_eq!(eval("false").as_bool(), Ok(false));
    assert_eq!(eval("null").as_null(), Ok(()));

    let float = eval("1.25").as_float().expect("float value");
    assert_eq!(float.to_bits(), 1.25f64.to_bits());
}

#[test]
fn evaluates_string_literals_with_owned_heap() {
    let ir = lower("\"hello\"");
    let outcome = eval_whnf_owned(&ir).expect("string evaluates");
    let value = outcome.value();

    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        outcome
            .heap()
            .get_string(value)
            .expect("string is heap-owned")
            .bytes(),
        b"hello"
    );

    let empty = eval_whnf_owned(&lower("\"\"")).expect("empty string evaluates");
    assert_eq!(
        empty
            .heap()
            .get_string(empty.value())
            .expect("empty string is heap-owned")
            .bytes(),
        b""
    );

    let escaped =
        eval_whnf_owned(&lower("\"line\\n\\\"quoted\\\"\"")).expect("escaped string evaluates");
    assert_eq!(
        escaped
            .heap()
            .get_string(escaped.value())
            .expect("escaped string is heap-owned")
            .bytes(),
        b"line\n\"quoted\""
    );
}

#[test]
fn evaluates_uri_literals_as_strings() {
    assert_eq!(
        eval_string_bytes("https://example.test/path?x=1"),
        b"https://example.test/path?x=1"
    );
    assert_eq!(
        eval_string_bytes("https://example.test/path#fragment"),
        b"https://example.test/path"
    );
    assert_eq!(
        eval_string_bytes("https://example.test + \"/more\""),
        b"https://example.test/more"
    );
    assert_eq!(
        eval("https://example.test == \"https://example.test\"").as_bool(),
        Ok(true)
    );
}

#[test]
fn unary_type_predicate_primops_classify_whnf_values() {
    assert_eq!(eval("builtins.isAttrs { a = 1; }").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isAttrs [ 1 ]").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isList [ 1 ]").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFunction (x: x)").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.isFunction builtins.length").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction (builtins.map (x: x))").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isString \"x\"").as_bool(), Ok(true));
    let ir = lower("builtins.isString \"x\"");
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
        .expect("isString argument exists");
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
            .eval_strict_unary_primop_value(
                ir.root,
                root.span,
                StrictUnaryPrimOp::IsString,
                argument,
                argument_span,
                value,
            )
            .expect("isString evaluates context-bearing strings")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isInt 1").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isInt 1.0").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isFloat 1.0").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFloat 1").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isBool false").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isNull null").as_bool(), Ok(true));
    assert_eq!(eval("isNull null").as_bool(), Ok(true));
    assert_eq!(
        eval("let isNull = x: false; in isNull null").as_bool(),
        Ok(false)
    );
    assert_eq!(eval("builtins.isPath /tmp").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isPath \"not-path\"").as_bool(), Ok(false));
}

#[test]
fn type_of_primop_returns_nix_type_names() {
    assert_eq!(eval_string_bytes("builtins.typeOf 1"), b"int");
    assert_eq!(eval_string_bytes("builtins.typeOf 1.0"), b"float");
    assert_eq!(eval_string_bytes("builtins.typeOf false"), b"bool");
    assert_eq!(eval_string_bytes("builtins.typeOf null"), b"null");
    assert_eq!(eval_string_bytes("builtins.typeOf \"x\""), b"string");
    assert_eq!(eval_string_bytes("builtins.typeOf /tmp"), b"path");
    assert_eq!(eval_string_bytes("builtins.typeOf [ 1 ]"), b"list");
    assert_eq!(eval_string_bytes("builtins.typeOf { a = 1; }"), b"set");
    assert_eq!(eval_string_bytes("builtins.typeOf (x: x)"), b"lambda");
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.length"),
        b"lambda"
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf (builtins.map (x: x))"),
        b"lambda"
    );
}

#[test]
fn builtin_lookup_uses_shared_declaration_registry() {
    let builtin_names = BUILTINS.iter().map(Builtin::name).collect::<BTreeSet<_>>();

    assert_eq!(builtin_names.len(), BUILTINS.len());
    for builtin in BUILTINS.iter().copied() {
        assert_eq!(lookup_builtin(builtin.name()), Some(builtin));
    }
}

#[test]
fn direct_builtin_arity_uses_direct_metadata_not_first_class_metadata() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"__testBuiltin").expect("symbol interns");
    let call = BuiltinCall::new(IrId::new(0), Span::new(0, 13), symbol);
    let builtin = Builtin::test_with_call_arities(
        Some(BuiltinDirect::LazyUnary {
            effect: BuiltinEffect::Pure,
        }),
        Some(3),
    );

    check_builtin_direct_arity(call, builtin, 1).expect("direct arity uses direct metadata");

    let error = check_builtin_direct_arity(call, builtin, 3)
        .expect_err("direct arity ignores first-class arity");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidPrimOpArity {
            id: call.id,
            symbol: call.symbol,
            expected: 1,
            actual: 3,
        }
    );
}

#[test]
fn builtin_surface_matches_pinned_flakes_golden_fixture() {
    let fixture = pinned_builtin_name_bytes();
    assert_eq!(fixture.len(), BUILTINS.len());
    assert!(fixture.windows(2).all(|pair| pair[0] < pair[1]));

    let registry_names = BUILTINS
        .iter()
        .map(|builtin| builtin.name().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(registry_names, fixture);

    let mut options =
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec()).expect("system valid");
    options.set_current_time(1_700_000_000).expect("time valid");

    assert_eq!(
        eval_list_string_bytes_with_options("builtins.attrNames builtins", options.clone()),
        fixture,
    );
    assert_eq!(
        eval_list_string_bytes_with_options("builtins.attrNames builtins.builtins", options),
        fixture,
    );
}

#[test]
fn version_gated_builtin_names_match_pinned_flakes_surface() {
    for name in VERSION_GATED_BUILTIN_NAMES {
        let fixture_contains = PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES.contains(name);
        let registry_contains = BUILTINS.lookup(name.as_bytes()).is_some();
        assert_eq!(
            registry_contains, fixture_contains,
            "{name} local registration should match the pinned flake-enabled fixture",
        );

        let source = format!("builtins.hasAttr {} builtins", nix_string_literal(name));
        assert_eq!(
            eval(&source).as_bool(),
            Ok(fixture_contains),
            "{name} runtime presence should match the pinned flake-enabled fixture",
        );
    }
}

#[test]
fn custom_effectful_unary_builtin_declarations_match_runtime_impls() {
    for name in [
        b"pathExists".as_slice(),
        b"readDir".as_slice(),
        b"readFile".as_slice(),
        b"readFileType".as_slice(),
        b"storePath".as_slice(),
    ] {
        assert_eq!(
            direct_builtin(name),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        let builtin = lookup_builtin(name).expect("builtin is registered");

        assert_eq!(builtin.first_class_arity(), Some(1));
        assert!(!builtin.docs().summary().is_empty());
    }
}

#[test]
fn tree_walk_options_normalize_store_dir() {
    let defaulted = TreeWalkOptions::with_store_dir(Vec::new()).expect("empty store dir defaults");
    assert_eq!(defaulted.store_dir(), b"/nix/store");

    let normalized = TreeWalkOptions::with_store_dir(b"//tmp//aos-store/./".to_vec())
        .expect("absolute store dir normalizes");
    assert_eq!(normalized.store_dir(), b"/tmp/aos-store");

    let parent_normalized = TreeWalkOptions::with_store_dir(b"/tmp/../aos-store".to_vec())
        .expect("parent components reduce");
    assert_eq!(parent_normalized.store_dir(), b"/aos-store");

    let nested_parent_normalized =
        TreeWalkOptions::with_store_dir(b"/tmp/aos-store/../other".to_vec())
            .expect("nested parent components reduce");
    assert_eq!(nested_parent_normalized.store_dir(), b"/tmp/other");

    let mut options = TreeWalkOptions::new();
    options
        .set_store_dir(b"/var//aos/store//".to_vec())
        .expect("absolute store dir sets");
    assert_eq!(options.store_dir(), b"/var/aos/store");

    assert_eq!(
        TreeWalkOptions::with_store_dir(b"relative/store".to_vec())
            .expect_err("relative store dir is rejected"),
        TreeWalkOptionsError::RelativeStoreDir
    );

    let base = TreeWalkOptions::with_search_path_base(b"//tmp//aos-search/./".to_vec())
        .expect("absolute search-path base normalizes");
    assert_eq!(base.search_path_base(), b"/tmp/aos-search");

    let mut options = TreeWalkOptions::new();
    options
        .set_search_path_base(b"/var//aos/search//".to_vec())
        .expect("absolute search-path base sets");
    assert_eq!(options.search_path_base(), b"/var/aos/search");

    assert_eq!(
        TreeWalkOptions::with_search_path_base(b"relative/search".to_vec())
            .expect_err("relative search-path base is rejected"),
        TreeWalkOptionsError::RelativeSearchPathBase
    );

    let path_base = TreeWalkOptions::with_path_literal_base(b"//tmp//aos-source/./".to_vec())
        .expect("absolute path-literal base normalizes");
    assert_eq!(
        path_base.path_literal_base(),
        Some(b"/tmp/aos-source".as_slice())
    );

    let mut options = TreeWalkOptions::new();
    assert_eq!(options.path_literal_base(), None);
    options
        .set_path_literal_base(b"/var//aos/source//".to_vec())
        .expect("absolute path-literal base sets");
    assert_eq!(
        options.path_literal_base(),
        Some(b"/var/aos/source".as_slice())
    );
    options.clear_path_literal_base();
    assert_eq!(options.path_literal_base(), None);

    assert_eq!(
        TreeWalkOptions::with_path_literal_base(b"relative/source".to_vec())
            .expect_err("relative path-literal base is rejected"),
        TreeWalkOptionsError::RelativePathLiteralBase
    );

    let home_dir = TreeWalkOptions::with_home_dir(b"//tmp//aos-home/./".to_vec())
        .expect("absolute home directory normalizes");
    assert_eq!(home_dir.home_dir(), Some(b"/tmp/aos-home".as_slice()));

    let mut options = TreeWalkOptions::new();
    assert_eq!(options.home_dir(), None);
    options
        .set_home_dir(b"/var//aos/home//".to_vec())
        .expect("absolute home directory sets");
    assert_eq!(options.home_dir(), Some(b"/var/aos/home".as_slice()));
    options.clear_home_dir();
    assert_eq!(options.home_dir(), None);

    assert_eq!(
        TreeWalkOptions::with_home_dir(b"relative/home".to_vec())
            .expect_err("relative home directory is rejected"),
        TreeWalkOptionsError::RelativeHomeDir
    );
    assert_eq!(
        TreeWalkOptions::with_home_dir(Vec::new()).expect_err("empty home directory is rejected"),
        TreeWalkOptionsError::RelativeHomeDir
    );
}

#[test]
fn to_file_uses_configured_store_dir() {
    let options = TreeWalkOptions::with_store_dir(b"/custom/store".to_vec())
        .expect("custom store dir configures");
    let path = eval_string_bytes_with_options(r#"builtins.toFile "x" "abc""#, options);

    assert!(path.starts_with(b"/custom/store/"), "{path:?}");
    assert!(path.ends_with(b"-x"), "{path:?}");
}

#[test]
fn tree_walk_options_configure_current_system() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.current_system(), None);

    let configured = TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
        .expect("currentSystem configures");
    assert_eq!(
        configured.current_system(),
        Some(b"aarch64-linux".as_slice())
    );

    let mut options = TreeWalkOptions::new();
    options
        .set_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem sets");
    assert_eq!(options.current_system(), Some(b"x86_64-linux".as_slice()));
    options.clear_current_system();
    assert_eq!(options.current_system(), None);

    assert_eq!(
        TreeWalkOptions::with_current_system(Vec::new())
            .expect_err("empty currentSystem is rejected"),
        TreeWalkOptionsError::EmptyCurrentSystem
    );
}

#[test]
fn tree_walk_options_configure_current_time() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.current_time(), None);

    let configured =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime configures");
    assert_eq!(configured.current_time(), Some(1_700_000_000));

    let mut options = TreeWalkOptions::new();
    options
        .set_current_time(1_700_000_001)
        .expect("currentTime sets");
    assert_eq!(options.current_time(), Some(1_700_000_001));
    options.clear_current_time();
    assert_eq!(options.current_time(), None);

    assert_eq!(
        TreeWalkOptions::with_current_time(-1).expect_err("negative currentTime is rejected"),
        TreeWalkOptionsError::NegativeCurrentTime
    );
}

#[test]
fn tree_walk_options_configure_trace_verbose() {
    let defaulted = TreeWalkOptions::new();
    assert!(!defaulted.trace_verbose());

    let configured = TreeWalkOptions::with_trace_verbose(true);
    assert!(configured.trace_verbose());

    let mut options = TreeWalkOptions::new();
    options.set_trace_verbose(true);
    assert!(options.trace_verbose());
    options.set_trace_verbose(false);
    assert!(!options.trace_verbose());
}

#[test]
fn tree_walk_options_configure_abort_on_warn() {
    let defaulted = TreeWalkOptions::new();
    assert!(!defaulted.abort_on_warn());

    let configured = TreeWalkOptions::with_abort_on_warn(true);
    assert!(configured.abort_on_warn());

    let mut options = TreeWalkOptions::new();
    options.set_abort_on_warn(true);
    assert!(options.abort_on_warn());
    options.set_abort_on_warn(false);
    assert!(!options.abort_on_warn());
}

#[test]
fn tree_walk_options_configure_max_call_depth() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.max_call_depth(), DEFAULT_MAX_CALL_DEPTH);

    let configured = TreeWalkOptions::with_max_call_depth(10);
    assert_eq!(configured.max_call_depth(), 10);

    let mut options = TreeWalkOptions::new();
    options.set_max_call_depth(0);
    assert_eq!(options.max_call_depth(), 0);
}

#[test]
fn tree_walk_options_configure_filesystem_access_policy() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.eval_mode(), EvalMode::Impure);
    assert!(defaulted.allowed_paths().is_empty());
    assert!(defaulted.allowed_uris().is_empty());

    let restricted = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    assert_eq!(restricted.eval_mode(), EvalMode::Restricted);

    let mut options = TreeWalkOptions::new();
    options.set_eval_mode(EvalMode::Pure);
    assert_eq!(options.eval_mode(), EvalMode::Pure);
    options
        .add_allowed_path(b"/tmp//allowed/./".to_vec())
        .expect("absolute allowed path configures");
    assert_eq!(options.allowed_paths(), &[b"/tmp/allowed".to_vec()]);
    options
        .set_allowed_paths(vec![b"/var/../tmp/other".to_vec()])
        .expect("allowed paths replace");
    assert_eq!(options.allowed_paths(), &[b"/tmp/other".to_vec()]);
    options.clear_allowed_paths();
    assert!(options.allowed_paths().is_empty());

    options
        .add_allowed_uri(b"https://cache.example/".to_vec())
        .expect("allowed URI prefix configures");
    assert_eq!(
        options.allowed_uris(),
        &[b"https://cache.example/".to_vec()]
    );
    assert!(options.uri_is_allowed(b"https://cache.example/source.tar.gz"));
    assert!(!options.uri_is_allowed(b"https://other.example/source.tar.gz"));
    options
        .set_allowed_uris(vec![b"github:".to_vec()])
        .expect("allowed URI prefixes replace");
    assert_eq!(options.allowed_uris(), &[b"github:".to_vec()]);
    options.clear_allowed_uris();
    assert!(options.allowed_uris().is_empty());

    assert_eq!(
        options
            .add_allowed_path(b"relative/path".to_vec())
            .expect_err("relative allowed paths are rejected"),
        TreeWalkOptionsError::RelativeAllowedPath
    );
    assert_eq!(
        options
            .add_allowed_path(Vec::new())
            .expect_err("empty allowed paths are rejected"),
        TreeWalkOptionsError::RelativeAllowedPath
    );
    assert_eq!(
        options
            .add_allowed_uri(Vec::new())
            .expect_err("empty allowed URI prefixes are rejected"),
        TreeWalkOptionsError::EmptyAllowedUri
    );
}

#[test]
fn tree_walk_options_configure_environment_variables() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.env_var(b"HOME"), None);

    let configured = TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/homeless".to_vec());
    assert_eq!(configured.env_var(b"HOME"), Some(b"/homeless".as_slice()));
    assert_eq!(configured.env_var(b"USER"), None);

    let mut options = TreeWalkOptions::new();
    options.set_env_var(b"USER".to_vec(), b"builder".to_vec());
    assert_eq!(options.env_var(b"USER"), Some(b"builder".as_slice()));
    options.set_env_var(b"USER".to_vec(), b"overridden".to_vec());
    assert_eq!(options.env_var(b"USER"), Some(b"overridden".as_slice()));
    options.clear_env_var(b"USER");
    assert_eq!(options.env_var(b"USER"), None);
}

#[test]
fn tree_walk_options_configure_ambient_search_path_rejection() {
    let mut options = TreeWalkOptions::new();
    assert!(!options.reject_ambient_search_path());

    options.set_reject_ambient_search_path(true);
    assert!(options.reject_ambient_search_path());

    options.set_reject_ambient_search_path(false);
    assert!(!options.reject_ambient_search_path());
}

#[test]
fn static_builtin_selects_are_first_class_functions() {
    let length = lower("builtins.length");
    assert_eq!(
        length.arena.node(length.root).expect("root exists").kind,
        IrKind::BuiltinAttr
    );
    assert_eq!(eval("builtins.length [ 1 2 ]").as_int(), Ok(2));
    assert_eq!(eval("builtins.true").as_bool(), Ok(true));
    assert_eq!(eval("builtins.false").as_bool(), Ok(false));
    assert_eq!(eval("builtins.null").as_null(), Ok(()));
    assert_eq!(eval("builtins.break 7").as_int(), Ok(7));
    assert_eq!(eval("let f = builtins.break; in f 9").as_int(), Ok(9));
    assert_eq!(eval_string_bytes("builtins.storeDir"), b"/nix/store");
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.storeDir",
            TreeWalkOptions::with_store_dir(b"/tmp/aos-store".to_vec())
                .expect("store dir is valid")
        ),
        b"/tmp/aos-store"
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.storeDir"),
        b"string"
    );
    assert_eq!(eval_string_bytes("builtins.nixVersion"), PINNED_NIX_VERSION);
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.nixVersion"),
        b"string"
    );
    assert_eq!(
        eval("builtins.langVersion").as_int(),
        Ok(PINNED_NIX_LANG_VERSION)
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.langVersion"),
        b"int"
    );
    assert!(matches!(
        eval_whnf(&lower("builtins.nixVersion null"))
            .expect_err("nixVersion is a value, not a function")
            .kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::String,
            ..
        }
    ));
    assert!(matches!(
        eval_whnf(&lower("builtins.langVersion null"))
            .expect_err("langVersion is a value, not a function")
            .kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Int,
            ..
        }
    ));
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.currentSystem",
            TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
                .expect("currentSystem is valid")
        ),
        b"aarch64-linux"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.typeOf builtins.currentSystem",
            TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
                .expect("currentSystem is valid")
        ),
        b"string"
    );
    assert_eq!(
        eval_with_options(
            "builtins.currentTime",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        )
        .as_int(),
        Ok(1_700_000_000)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.typeOf builtins.currentTime",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        ),
        b"int"
    );
    assert_eq!(
        eval_with_options(
            "builtins.currentTime == builtins.currentTime",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins ? length").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? break").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? getEnv").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? throw").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? abort").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? tryEval").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? placeholder").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? nixVersion").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? langVersion").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? currentSystem").as_bool(), Ok(false));
    assert_eq!(
        eval_with_options(
            "builtins ? currentSystem",
            TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
                .expect("currentSystem is valid")
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins ? currentTime").as_bool(), Ok(false));
    assert_eq!(
        eval_with_options(
            "builtins ? currentTime",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins ? storeDir").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? __missing").as_bool(), Ok(false));
    assert_eq!(eval("builtins ? length.foo").as_bool(), Ok(false));
    assert_eq!(
        eval("builtins.isFunction builtins.length").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.head").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.tail").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.concatLists").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.length"),
        b"lambda"
    );
    assert_eq!(
        eval("builtins.functionArgs builtins.length == {}").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = builtins.length; in f [ 1 2 3 ]").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.elemAt").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.elem").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = builtins.isFunction; in f builtins.convertHash").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.throw").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.abort").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.tryEval").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.placeholder").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isFunction builtins.all").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFunction builtins.any").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.isFunction builtins.concatMap").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.filter").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isFunction builtins.map").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.isFunction builtins.genList").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.groupBy").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.partition").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.foldl'").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.substring").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.replaceStrings").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.sort").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let x = builtins.break (1 / 0); in 42").as_int(),
        Ok(42)
    );
    assert!(matches!(
        eval_whnf(&lower("builtins.length (builtins.break [ 1 2 ])"))
            .expect_err("length sees the break result as an unforced thunk")
            .kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Thunk,
            ..
        }
    ));
    assert!(matches!(
        eval_whnf(&lower(
            "builtins.length (let f = builtins.break; in f [ 1 2 ])"
        ))
        .expect_err("first-class break preserves the returned thunk")
        .kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Thunk,
            ..
        }
    ));
    assert!(matches!(
        eval_whnf(&lower("builtins.hasAttr \"x\" (builtins.break { x = 1; })"))
            .expect_err("hasAttr sees the break result as an unforced thunk")
            .kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Thunk,
            ..
        }
    ));
    assert_eq!(eval("builtins.__missing or 42").as_int(), Ok(42));
    assert_eq!(eval("builtins.__missing.foo or 42").as_int(), Ok(42));
    assert_eq!(eval("builtins.length.foo or 42").as_int(), Ok(42));
    assert_eq!(
        eval_string_bytes("builtins.storeDir or \"fallback\""),
        b"/nix/store"
    );
    assert_eq!(
        eval_string_bytes("builtins.nixVersion or \"fallback\""),
        PINNED_NIX_VERSION
    );
    assert_eq!(
        eval("builtins.langVersion or 42").as_int(),
        Ok(PINNED_NIX_LANG_VERSION)
    );
    assert_eq!(
        eval_string_bytes("builtins.currentSystem or \"fallback\""),
        b"fallback"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.currentSystem or \"fallback\"",
            TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
                .expect("currentSystem is valid")
        ),
        b"aarch64-linux"
    );
    assert_eq!(eval("builtins.currentTime or 42").as_int(), Ok(42));
    assert_eq!(
        eval_with_options(
            "builtins.currentTime or 42",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        )
        .as_int(),
        Ok(1_700_000_000)
    );
}

#[test]
fn builtins_global_evaluates_to_registry_backed_attrset() {
    fn expected_builtin_names(include_system: bool, include_time: bool) -> Vec<Vec<u8>> {
        let mut names = BUILTINS
            .iter()
            .filter(|builtin| {
                include_system || builtin.availability() != BuiltinAvailability::ImpureCurrentSystem
            })
            .filter(|builtin| {
                include_time || builtin.availability() != BuiltinAvailability::ImpureCurrentTime
            })
            .map(|builtin| builtin.name().to_vec())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    assert_eq!(eval("builtins ? builtins").as_bool(), Ok(true));
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.builtins"),
        b"set"
    );
    assert_eq!(
        eval_string_bytes("let b = builtins; in builtins.typeOf b.builtins"),
        b"set"
    );
    assert_eq!(
        eval("let b = builtins; in builtins.isFunction b.genericClosure").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames builtins"),
        expected_builtin_names(false, false)
    );
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames builtins.builtins"),
        expected_builtin_names(false, false)
    );

    let mut options =
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec()).expect("system valid");
    options.set_current_time(1_700_000_000).expect("time valid");
    assert_eq!(
        eval_list_string_bytes_with_options("builtins.attrNames builtins", options),
        expected_builtin_names(true, true)
    );
}

#[test]
fn trace_primop_records_output_and_returns_second_argument() {
    let outcome = eval_owned(r#"builtins.trace "hello" 7"#);

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        b"hello",
    );

    let outcome = eval_owned(r#"let t = builtins.trace "first-class"; in t 9"#);

    assert_eq!(outcome.value().as_int(), Ok(9));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        b"first-class",
    );
}

#[test]
fn trace_primop_forces_message_to_whnf_but_not_nested_values() {
    let outcome = eval_owned(r#"builtins.trace [ (builtins.throw "nested") ] { a = 1 / 0; }"#);

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        "[ «thunk» ]".as_bytes(),
    );
}

#[test]
fn trace_primop_renders_unforced_literals_but_not_computed_thunks() {
    let outcome = eval_owned(r#"builtins.trace [ 1 "x" true null /tmp/foo (1 + 2) ] 1"#);

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        r#"[ 1 "x" true null /tmp/foo «thunk» ]"#.as_bytes(),
    );

    let outcome = eval_owned(r#"builtins.trace { a = /tmp/foo; b = 1; c = 1 + 2; } 1"#);

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        "{ a = /tmp/foo; b = 1; c = «thunk»; }".as_bytes(),
    );
}

#[test]
fn trace_primop_renders_recursive_cached_thunks_shallowly() {
    let outcome = eval_owned("let s = rec { a = s; }; in builtins.seq s.a (builtins.trace s 1)");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        "{ a = «repeated»; }".as_bytes(),
    );
}

#[test]
fn trace_primop_renders_whnf_values() {
    for (source, expected) in [
        (r#"builtins.trace "a\n\"b" 1"#, b"a\n\"b".as_slice()),
        ("builtins.trace 1000000.0 1", b"1e+06".as_slice()),
        (
            "builtins.trace builtins.length 1",
            "«primop length»".as_bytes(),
        ),
        ("builtins.trace (x: x) 1", "«lambda»".as_bytes()),
        ("builtins.trace { } 1", b"{ }".as_slice()),
    ] {
        let outcome = eval_owned(source);

        assert_eq!(outcome.value().as_int(), Ok(1), "{source}");
        assert_eq!(outcome.trace_output().len(), 1, "{source}");
        assert_trace_output(
            outcome.trace_output().first().expect("trace output exists"),
            EvalTraceKind::Trace,
            expected,
        );
    }
}

#[test]
fn trace_verbose_primop_respects_verbose_option() {
    let hidden = eval_owned(r#"builtins.traceVerbose (builtins.throw "hidden") 1"#);

    assert_eq!(hidden.value().as_int(), Ok(1));
    assert!(hidden.trace_output().is_empty());

    let hidden = eval_owned(r#"let t = builtins.traceVerbose (builtins.throw "hidden"); in t 1"#);

    assert_eq!(hidden.value().as_int(), Ok(1));
    assert!(hidden.trace_output().is_empty());

    let shown = eval_owned_with_options(
        r#"builtins.traceVerbose "shown" 2"#,
        TreeWalkOptions::with_trace_verbose(true),
    );

    assert_eq!(shown.value().as_int(), Ok(2));
    assert_eq!(shown.trace_output().len(), 1);
    assert_trace_output(
        shown.trace_output().first().expect("trace output exists"),
        EvalTraceKind::TraceVerbose,
        b"shown",
    );

    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.traceVerbose (builtins.throw "boom") 1"#),
        TreeWalkOptions::with_trace_verbose(true),
    )
    .expect_err("verbose trace forces its message");

    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
}

#[test]
fn tree_walk_preserves_trace_records_after_later_errors() {
    let ir = lower(r#"builtins.trace "before-error" (builtins.throw "boom")"#);
    let mut evaluator = TreeWalk::new(&ir);
    let error = evaluator.eval_root().expect_err("second argument throws");

    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
    assert_eq!(evaluator.trace_output().len(), 1);
    assert_trace_output(
        evaluator
            .trace_output()
            .first()
            .expect("trace output exists"),
        EvalTraceKind::Trace,
        b"before-error",
    );
}

#[test]
fn warn_primop_records_warning_and_returns_second_argument() {
    let outcome = eval_owned(r#"builtins.warn "hello" 7"#);

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert!(outcome.trace_output().is_empty());
    assert_eq!(outcome.warning_output().len(), 1);
    assert_warning_output(
        outcome
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"hello",
    );

    let outcome = eval_owned(r#"let w = builtins.warn "first-class"; in w 9"#);

    assert_eq!(outcome.value().as_int(), Ok(9));
    assert_eq!(outcome.warning_output().len(), 1);
    assert_warning_output(
        outcome
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"first-class",
    );

    let outcome = eval_owned(r#"builtins.warn ("a" + "b") { a = 1 / 0; }"#);

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    assert_eq!(outcome.warning_output().len(), 1);
    assert_warning_output(
        outcome
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"ab",
    );
}

#[test]
fn warn_primop_requires_string_message() {
    for source in [
        "builtins.warn 1 7",
        "builtins.warn /tmp/foo 7",
        r#"builtins.warn { __toString = self: "hook"; } 7"#,
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("warn requires a string");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::Type {
                    expected: "string",
                    ..
                }
            ),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn warn_primop_formats_multiline_stderr_like_cpp_nix() {
    fn formatted(message: &[u8]) -> Vec<u8> {
        TreeWalk::warning_stderr_bytes(IrId::new(0), Span::new(0, 0), message)
            .expect("warning output formats")
    }

    assert_eq!(formatted(b"hello"), b"evaluation warning: hello\n");
    assert_eq!(
        formatted(b"a\nb"),
        b"evaluation warning: a\n                    b\n"
    );
    assert_eq!(
        formatted(b"a\n\nb"),
        b"evaluation warning: a\n\n                    b\n"
    );
    assert_eq!(formatted(b"a\n"), b"evaluation warning: a\n");
    assert_eq!(formatted(b""), b"\n");
    assert_eq!(formatted(b"\n"), b"\n");
    assert_eq!(
        formatted(b"\nb"),
        b"evaluation warning:\n                    b\n"
    );
}

#[test]
fn warn_primop_abort_on_warn_emits_warning_then_errors() {
    let ir = lower(r#"builtins.warn "strict" 7"#);
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::with_abort_on_warn(true));
    let error = evaluator
        .eval_root()
        .expect_err("abort-on-warn fails after emitting warning");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::WarningAborted { .. }
    ));
    assert_eq!(evaluator.warning_output().len(), 1);
    assert_warning_output(
        evaluator
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"strict",
    );

    let ir = lower(r#"builtins.tryEval (builtins.warn "strict" 7)"#);
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::with_abort_on_warn(true));
    let error = evaluator
        .eval_root()
        .expect_err("tryEval does not catch abort-on-warn");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::WarningAborted { .. }
    ));
    assert_eq!(evaluator.warning_output().len(), 1);
    assert_warning_output(
        evaluator
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"strict",
    );
}

fn assert_cpp_nix_trace_and_warn_stderr_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        r#"builtins.trace "hello" 7"#,
        r#"builtins.trace "a\n\"b" 1"#,
        "builtins.trace 1.0 1",
        "builtins.trace (-0.0) 1",
        "builtins.trace 0.0001 1",
        "builtins.trace 0.00001 1",
        "builtins.trace 100000.0 1",
        "builtins.trace 1000000.0 1",
        "builtins.trace 1.23456789 1",
        "builtins.trace builtins.length 1",
        "builtins.trace { } 1",
    ] {
        let reference = cpp_nix_eval_stderr(oracle, source);
        let stderr = eval_captured_stderr(source);
        assert_eq!(stderr, reference, "trace stderr diverged for {source}");
    }

    let source = r#"builtins.traceVerbose "hidden" 7"#;
    let reference = cpp_nix_eval_stderr(oracle, source);
    let stderr = eval_captured_stderr(source);
    assert_eq!(stderr, reference, "disabled traceVerbose stderr diverged");

    let source = r#"builtins.traceVerbose "shown" 7"#;
    let reference =
        cpp_nix_eval_stderr_with_nix_options(oracle, source, &[("trace-verbose", "true")]);
    let stderr =
        eval_captured_stderr_with_options(source, TreeWalkOptions::with_trace_verbose(true));
    assert_eq!(stderr, reference, "enabled traceVerbose stderr diverged");

    for source in [
        r#"builtins.warn "hello" 7"#,
        r#"builtins.warn "a\nb" 7"#,
        r#"builtins.warn "a\n\nb" 7"#,
        r#"builtins.warn "" 7"#,
    ] {
        let reference = cpp_nix_eval_stderr(oracle, source);
        let stderr = eval_captured_stderr(source);
        assert_eq!(stderr, reference, "warning stderr diverged for {source}");
    }

    for source in [r#"builtins.warn "fatal" 7"#, r#"builtins.warn "a\nb" 7"#] {
        let reference = cpp_nix_eval_failure_stderr_with_nix_options(
            oracle,
            source,
            &[("abort-on-warn", "true")],
        );
        let (error, stderr) = eval_captured_stderr_error_with_options(
            source,
            TreeWalkOptions::with_abort_on_warn(true),
        );
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::WarningAborted { .. }),
            "abort-on-warn did not produce WarningAborted for {source}: {error:?}"
        );
        assert!(
            reference.starts_with(&stderr),
            "abort-on-warn warning stderr prefix diverged for {source}: reference={:?}, actual={:?}",
            String::from_utf8_lossy(&reference),
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            String::from_utf8_lossy(&reference)
                .contains("aborting to reveal stack trace of warning"),
            "C++ Nix abort-on-warn stderr did not include abort diagnostic for {source}: {}",
            String::from_utf8_lossy(&reference)
        );
    }
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_trace_and_warn_stderr_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_trace_and_warn_stderr_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_trace_and_warn_stderr_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix trace/warn check");
        return;
    };
    assert_cpp_nix_trace_and_warn_stderr_match_tree_walk(&oracle);
}

fn assert_cpp_nix_number_printing_matches_tree_walk(oracle: &str) {
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

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_number_printing_matches_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_number_printing_matches_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_number_printing_matches_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix number printing check");
        return;
    };
    assert_cpp_nix_number_printing_matches_tree_walk(&oracle);
}

#[test]
fn number_raw_renderer_formats_integer_and_float_values() {
    for (source, expected) in [
        ("1", b"1".as_slice()),
        ("(-2)", b"-2"),
        ("9223372036854775807", b"9223372036854775807"),
        ("(-9223372036854775807 - 1)", b"-9223372036854775808"),
        ("1.0", b"1"),
        ("1.25", b"1.25"),
        ("1.23456789", b"1.23457"),
        ("(-0.0)", b"0"),
        ("0.0001", b"0.0001"),
        ("0.00001", b"1e-05"),
        ("100000.0", b"100000"),
        ("1000000.0", b"1e+06"),
        ("((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))", b"nan"),
        ("(1.0e308 * 1.0e308)", b"inf"),
        ("(builtins.sub 0.0 (1.0e308 * 1.0e308))", b"-inf"),
    ] {
        assert_eq!(
            eval_number_raw_bytes(&lower(source)).as_deref(),
            Ok(expected),
            "{source}"
        );
    }

    let ir = lower(r#""x""#);
    let error = eval_number_raw_bytes(&ir).expect_err("raw number renderer rejects strings");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: ir.root,
            expected: "number",
            actual: ValueTag::String,
        }
    );
}

#[test]
#[ignore = "requires AOS_NIX_ORACLE to point at pinned nix-instantiate 2.24.12"]
fn pinned_cpp_nix_builtin_surface_matches_registry() {
    let oracle = cpp_nix_oracle();
    assert_pinned_cpp_nix_builtin_surface_matches_registry(&oracle);
}

#[test]
fn configured_pinned_cpp_nix_builtin_surface_matches_registry() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix surface check");
        return;
    };
    assert_pinned_cpp_nix_builtin_surface_matches_registry(&oracle);
}

#[test]
#[ignore = "requires AOS_NIX_ORACLE to point at pinned nix-instantiate 2.24.12"]
fn pinned_present_unimplemented_builtin_stubs_match_registry() {
    let oracle = cpp_nix_oracle();
    assert_pinned_present_unimplemented_builtin_stubs_match_registry(&oracle);
}

#[test]
fn configured_pinned_present_unimplemented_builtin_stubs_match_registry() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!(
            "AOS_NIX_ORACLE not set; skipping configured C++ Nix unimplemented builtin stub check"
        );
        return;
    };
    assert_pinned_present_unimplemented_builtin_stubs_match_registry(&oracle);
}

fn assert_pinned_absent_experimental_builtin_attrs_match_registry(oracle: &str) {
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

#[test]
#[ignore = "requires AOS_NIX_ORACLE to point at pinned nix-instantiate 2.24.12"]
fn pinned_absent_experimental_builtin_attrs_match_registry() {
    let oracle = cpp_nix_oracle();
    assert_pinned_absent_experimental_builtin_attrs_match_registry(&oracle);
}

#[test]
fn configured_pinned_absent_experimental_builtin_attrs_match_registry() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!(
            "AOS_NIX_ORACLE not set; skipping configured C++ Nix absent experimental builtin check"
        );
        return;
    };
    assert_pinned_absent_experimental_builtin_attrs_match_registry(&oracle);
}

#[test]
#[ignore = "requires AOS_NIX_ORACLE to point at pinned nix-instantiate 2.24.12"]
fn cpp_nix_identity_constants_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_identity_constants_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_identity_constants_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix oracle check");
        return;
    };
    assert_cpp_nix_identity_constants_match_tree_walk(&oracle);
}

fn assert_cpp_nix_control_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    let (dir, path) = temp_file_with_bytes("cpp-nix-break-path", b"abc");
    let path = path_source(&path);

    for source in [
        "builtins.break 7".to_owned(),
        "let f = builtins.break; in f 9".to_owned(),
        "let x = builtins.break (1 / 0); in 42".to_owned(),
        "builtins.seq (builtins.break (1 / 0)) 7".to_owned(),
        "builtins.deepSeq (builtins.break [ (1 / 0) ]) 7".to_owned(),
        "(builtins.break (1 + 2)) == 3".to_owned(),
        r#"builtins.break ("a" + "b") + "c""#.to_owned(),
        "let x = builtins.break [ 1 2 ]; y = builtins.seq x 0; in y + builtins.length x".to_owned(),
        "let f = builtins.break (x: x); in f 1".to_owned(),
        "builtins.isInt (builtins.break (1 + 2))".to_owned(),
        format!("builtins.isPath (builtins.break {path})"),
        format!("builtins.typeOf (builtins.break {path})"),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    for source in [
        "builtins.length (builtins.break [ 1 2 ])",
        "builtins.add (builtins.break (builtins.break (1 + 2))) 1",
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_control_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_control_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_control_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix control check");
        return;
    };
    assert_cpp_nix_control_builtins_match_tree_walk(&oracle);
}

fn assert_cpp_nix_attrset_builtin_semantics_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.attrNames { z = 1; a = 2; A = 3; _ = 4; aa = 5; }"#,
        r#"builtins.attrValues { z = "z"; a = "a"; A = "A"; _ = "_"; aa = "aa"; }"#,
        r#"builtins.getAttr "a" { a = "x"; b = 1; }"#,
        r#"let get = builtins.getAttr "a"; in get { a = "x"; }"#,
        r#"builtins.hasAttr "a" { a = 1; }"#,
        r#"builtins.hasAttr "missing" { a = 1; }"#,
        r#"builtins.removeAttrs { z = 1; a = 2; b = 3; } [ "z" "missing" "z" ]"#,
        r#"builtins.listToAttrs [ { name = "b"; value = 2; } { name = "a"; value = 1; } { name = "a"; value = 9; } ]"#,
        r#"let f = builtins.listToAttrs; in f [ { name = "a"; value = 1; } ]"#,
        r#"builtins.intersectAttrs { z = 0; a = 0; } { z = 4; a = 5; c = 6; }"#,
        r#"builtins.catAttrs "a" [ { a = 1; } { b = 2; } { a = 3; } ]"#,
        r#"builtins.functionArgs ({ b ? 1, a, ... }@args: a)"#,
        r#"let f = builtins.functionArgs; in f ({ a, b ? 1 }: a)"#,
        r#"builtins.functionArgs builtins.length"#,
        r#"builtins.mapAttrs (name: value: name) { b = 2; a = 1; }"#,
        r#"builtins.mapAttrs (name: value: value + 1) { b = 2; a = 1; }"#,
        r#"builtins.attrNames (builtins.mapAttrs (name: value: value) { z = 1; a = 2; A = 3; _ = 4; aa = 5; })"#,
        r#"builtins.attrValues (builtins.mapAttrs (name: value: name) { z = 1; a = 2; A = 3; _ = 4; aa = 5; })"#,
        r#"builtins.attrNames (builtins.mapAttrs (1 / 0) { b = 2; a = 1; })"#,
        r#"let mapAttrs = builtins.mapAttrs; mapped = mapAttrs (name: value: value) { a = 1; }; in mapped"#,
        r#"builtins.attrNames (builtins.groupBy (x: x) [ "b" "a" "b" "A" "_" "aa" ])"#,
        r#"builtins.attrValues (builtins.groupBy (x: x) [ "b" "a" "b" "A" "_" "aa" ])"#,
        r#"builtins.zipAttrsWith (name: values: values) [ { a = 1; b = 2; } { a = 3; c = 4; } { b = 5; } ]"#,
        r#"builtins.attrNames (builtins.zipAttrsWith (name: values: 1 / 0) [ { b = 2; a = 1; } { c = 3; } ])"#,
        r#"builtins.length (builtins.zipAttrsWith (name: values: values) [ { a = 1 / 0; } ]).a"#,
        r#"let zip = builtins.zipAttrsWith; zipped = zip (name: values: values) [ { a = 1; } ]; in zipped"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_attrset_builtin_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_attrset_builtin_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_attrset_builtin_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix attrset check");
        return;
    };
    assert_cpp_nix_attrset_builtin_semantics_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_type_predicates_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    let version = cpp_nix_version(&oracle);
    assert!(
        version.contains("(Nix) 2.24."),
        "expected a C++ Nix 2.24.x oracle, got {version}"
    );
    eprintln!("C++ Nix oracle: {version}");

    for source in [
        "builtins.isAttrs { a = 1; }",
        "builtins.isAttrs [ 1 ]",
        "builtins.isList [ 1 ]",
        "builtins.isFunction (x: x)",
        "builtins.isFunction builtins.length",
        "builtins.isFunction (builtins.map (x: x))",
        "builtins.isString \"x\"",
        "builtins.isInt 1",
        "builtins.isInt 1.0",
        "builtins.isFloat 1.0",
        "builtins.isFloat 1",
        "builtins.isBool false",
        "builtins.isNull null",
        "builtins.isPath /tmp",
        "builtins.isPath \"not-path\"",
        "builtins.typeOf 1",
        "builtins.typeOf 1.0",
        "builtins.typeOf false",
        "builtins.typeOf null",
        "builtins.typeOf \"x\"",
        "builtins.typeOf /tmp",
        "builtins.typeOf [ 1 ]",
        "builtins.typeOf { a = 1; }",
        "builtins.typeOf (x: x)",
        "builtins.typeOf builtins.length",
        "builtins.typeOf (builtins.map (x: x))",
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }
}

fn assert_cpp_nix_equality_semantics_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        "1 == 1",
        "1 == 2",
        "1 != 2",
        "1 == 1.0",
        "1 != 1.5",
        "9007199254740993 == 9007199254740992.0",
        "0.1 + 0.2 == 0.3",
        "1.0000000000000002 == 1.0",
        "1.0000000000000001 == 1.0",
        "true == true",
        "true != false",
        "null == null",
        "null == false",
        "1 == true",
        r#""a" == "a""#,
        r#""a" == "b""#,
        r#""a" != "b""#,
        r#""line\n" == "line\n""#,
        "[1 \"a\" null] == [1 \"a\" null]",
        "[1] != [1 2]",
        "[1 2] == [1 3]",
        r#"[1 (builtins.throw "x")] == [2 (builtins.throw "y")]"#,
        "{ b = 2; a = 1; } == { a = 1; b = 2; }",
        r#"{ a = 1; } == { a = 1; b = builtins.throw "x"; }"#,
        r#"{ a = 1; z = builtins.throw "x"; } == { a = 2; z = builtins.throw "y"; }"#,
        "{ a = { x = 1; }; } == { a = { x = 1; }; }",
        "let f = x: x; in f == f",
        "let f = x: x; in f != f",
        "let f = x: x; g = x: x; in f == g",
        "(x: x) == 1",
        "let f = x: x; in [ f ] == [ f ]",
        "[ (x: x) ] == [ (x: x) ]",
        "let v = { a = x: x; }; in [ v.a ] == [ v.a ]",
        "let v = { a = x: x; }; xs = [ v.a ]; in xs == xs",
        "let f = x: x; in { inherit f; } == { inherit f; }",
        r#"let xs = [ (builtins.throw "x") ]; in [ xs ] == [ xs ]"#,
        r#"let s = { a = builtins.throw "x"; }; in [ s ] == [ s ]"#,
        r#"{ outPath = "/a"; a = 1; } == { outPath = "/a"; a = 1; }"#,
        r#"{ outPath = "/a"; a = 1; } == { outPath = "/a"; a = 2; }"#,
        r#"let a = { outPath = "/a"; }; in a == "/a""#,
        r#"let a = { type = "derivation"; outPath = "/a"; drvPath = "/a.drv"; };
               in a == { type = "derivation"; outPath = "/a"; drvPath = "/a.drv"; }"#,
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in nan == nan",
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in nan != nan",
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in [ nan ] == [ nan ]",
        "[ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ] == [ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ]",
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in nan < nan",
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in builtins.tryEval (nan < nan)",
        "[1] == { }",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        r#"[1 (builtins.throw "x")] == [1 (builtins.throw "y")]"#,
        r#"{ z = builtins.throw "x"; a = 1; } == { a = 2; z = builtins.throw "y"; }"#,
        r#"let xs = [ (builtins.throw "x") ]; in xs == xs"#,
        r#"let s = { a = builtins.throw "x"; }; in s == s"#,
    ] {
        assert_cpp_nix_and_tree_walk_throw_message(oracle, source, "x");
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_equality_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_equality_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_equality_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix equality check");
        return;
    };
    assert_cpp_nix_equality_semantics_match_tree_walk(&oracle);
}

fn assert_cpp_nix_comparison_semantics_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        "1 < 2",
        "2 > 1",
        "2 <= 2",
        "2 >= 3",
        "1 < 1.5",
        "1.5 >= 2",
        "9007199254740993 < 9007199254740994.0",
        "builtins.lessThan 1 2",
        "let less = builtins.lessThan 1; in less 2",
        "builtins.lessThan 2 1",
        "builtins.lessThan 1 1",
        r#""a" < "b""#,
        r#""b" > "a""#,
        r#""a" <= "a""#,
        r#""a" >= "b""#,
        r#""Z" < "a""#,
        r#""a\n" < "aa""#,
        "/tmp/a < /tmp/b",
        "/tmp/b > /tmp/a",
        "/tmp/a <= /tmp/a",
        "builtins.lessThan /tmp/a /tmp/b",
        "[1 2] < [1 3]",
        "[1 3] > [1 2]",
        "[1 2] <= [1 2]",
        "[1 2] >= [1 3]",
        "[1] < [1 0]",
        "[1 0] > [1]",
        "[] < [0]",
        r#"[1 "a"] < [1 "b"]"#,
        "[[1 2]] < [[1 3]]",
        "[1 (builtins.throw \"x\")] < [2 (builtins.throw \"y\")]",
        "[2 (builtins.throw \"x\")] < [1 (builtins.throw \"y\")]",
        "let f = x: x; prefix = [ f ]; in (prefix ++ [ 1 ]) < (prefix ++ [ 2 ])",
        "let xs = [ xs ]; in xs < xs",
        "let xs = [ xs ]; in xs <= xs",
        "let s = rec { a = s; }; in [s] < [s]",
        "let s = rec { a = s; }; in [s] <= [s]",
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in nan < nan",
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in nan > nan",
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in nan <= nan",
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in nan >= nan",
        "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in [ nan 1 ] < [ nan 2 ]",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        "true < false",
        "null < null",
        "{} < {}",
        "(x: x) < (x: x)",
        r#"1 < "a""#,
        r#""a" < 1"#,
        r#"/tmp/a < "a""#,
        "[1] < true",
        "[1] < [\"a\"]",
        "false < [(1 / 0)]",
        "1 < true",
        r#""a" < true"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }

    assert_cpp_nix_and_tree_walk_throw_message(
        oracle,
        r#"[1 (builtins.throw "x")] <= [1 (builtins.throw "y")]"#,
        "y",
    );

    for (source, operator) in [
        ("1 < 2 < 3", "<"),
        ("1 <= 2 <= 3", "<="),
        ("3 > 2 > 1", ">"),
        ("3 >= 2 >= 1", ">="),
    ] {
        assert_cpp_nix_and_parser_reject_non_associative_operator(oracle, source, operator);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_comparison_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_comparison_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_comparison_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix comparison check");
        return;
    };
    assert_cpp_nix_comparison_semantics_match_tree_walk(&oracle);
}

fn assert_cpp_nix_function_semantics_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        "(x: x + 1) 2",
        "let f = x: x; in f (1 + 2)",
        "let f = x: 7; in f (1 / 0)",
        "let x = 1; f = y: x + y; in f 2",
        "let x = 1; f = y: x + y; in let x = 10; in f x",
        "let f = x: x; or = 2; in f or",
        "(x: y: x + y) 1 2",
        "((x: y: x) (1 + 2)) 0",
        "builtins.typeOf (x: x)",
        "let f = x: x; in f == f",
        "({ a, b }: a + b) { a = 1; b = 2; }",
        "({ a, b }: 1) { a = builtins.throw \"a\"; b = builtins.throw \"b\"; }",
        "({ a, ... }: a) { a = 1; b = builtins.throw \"b\"; }",
        "({ a ? 1 + 2 }: a) {}",
        "({ a ? builtins.throw \"default\" }: 7) {}",
        "({ a ? builtins.throw \"default\" }: 7) { a = builtins.throw \"provided\"; }",
        "({ a ? 1 }: a) { a = 7; }",
        "({ a, b ? a + 1 }: b) { a = 2; }",
        "({ a ? b, b }: a) { b = 2; }",
        "(args@{ a ? args.b, ... }: a) { b = 2; }",
        "(args@{ a, ... }: args.b) { a = 1; b = 2; }",
        "({ a, ... } @ args: args.b) { a = 1; b = 2; }",
        "({ a ? 1 } @ args: args ? a) {}",
        "({ a ? 1 } @ args: args ? a) { a = 2; }",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    assert_cpp_nix_and_tree_walk_reject_with_final_error(
        oracle,
        "({ a, b }: a) { a = 1; }",
        "function 'anonymous lambda' called without required argument 'b'",
        |kind| matches!(kind, TreeWalkErrorKind::MissingFormalAttribute { .. }),
    );
    assert_cpp_nix_and_tree_walk_reject_with_final_error(
        oracle,
        "({ a }: a) { a = 1; b = 2; }",
        "function 'anonymous lambda' called with unexpected argument 'b'",
        |kind| matches!(kind, TreeWalkErrorKind::UnexpectedFormalAttribute { .. }),
    );
    assert_cpp_nix_and_tree_walk_reject_with_final_error(
        oracle,
        "({ a } @ args: a) { a = 1; b = 2; }",
        "function 'anonymous lambda' called with unexpected argument 'b'",
        |kind| matches!(kind, TreeWalkErrorKind::UnexpectedFormalAttribute { .. }),
    );

    assert_cpp_nix_and_tree_walk_reject_expression(oracle, "({ a }: a) 1");
    assert_cpp_nix_and_tree_walk_reject_expression(oracle, "builtins.toString (x: x)");
    assert_cpp_nix_and_tree_walk_reject_expression(oracle, r#""${x: x}""#);

    assert_cpp_nix_and_tree_walk_throw_message(
        oracle,
        "({ a }: 1) (builtins.throw \"arg\")",
        "arg",
    );
    assert_cpp_nix_and_tree_walk_throw_message(
        oracle,
        "({ a ? builtins.throw \"default\" }: a) {}",
        "default",
    );
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_function_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_function_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_function_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix function check");
        return;
    };
    assert_cpp_nix_function_semantics_match_tree_walk(&oracle);
}

fn assert_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        "(rec { a = 1; b = a + 1; }).b",
        "(rec { a = b; b = 1; }).a",
        "(rec { a = builtins.throw \"a\"; }).b or 2",
        "rec { a = b; b = a; } ? a",
        "let a = b; b = 1; in a",
        "let a = b; b = c; c = 3; in a",
        "let fix = f: let x = f x; in x; in (fix (self: { a = 1; b = self.a + 1; })).b",
        "let fix = f: let x = f x; in x; in (fix (self: { a = 1; nested = { b = self.a + 1; }; })).nested.b",
        "let even = n: if n == 0 then true else odd (n - 1); odd = n: if n == 0 then false else even (n - 1); in even 10",
        "let even = n: if n == 0 then true else odd (n - 1); odd = n: if n == 0 then false else even (n - 1); in odd 9",
        "let x = { a = 1; b = x; }; in x.b.a",
        "let xs = [ 1 xs ]; in builtins.elemAt (builtins.elemAt xs 1) 0",
        "let fix = f: let x = f x; in x; in (fix (self: { package = { name = \"a\"; dep = self.package.name; }; })).package.dep",
        "let f = n: if n == 0 then 0 else f (n - 1); in f 100",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    assert_cpp_nix_json_matches_tree_walk_with_nix_options(
        oracle,
        "(x: x) 1",
        &[("max-call-depth", "0")],
        TreeWalkOptions::with_max_call_depth(0),
    );
    assert_cpp_nix_json_matches_tree_walk_with_nix_options(
        oracle,
        "(x: (y: y) 2) 1",
        &[("max-call-depth", "1")],
        TreeWalkOptions::with_max_call_depth(1),
    );
    assert_cpp_nix_json_matches_tree_walk_with_nix_options(
        oracle,
        "builtins.add 1 2",
        &[("max-call-depth", "0")],
        TreeWalkOptions::with_max_call_depth(0),
    );
    assert_cpp_nix_json_matches_tree_walk_with_nix_options(
        oracle,
        "builtins.map (x: x) [ 1 ]",
        &[("max-call-depth", "0")],
        TreeWalkOptions::with_max_call_depth(0),
    );
    assert_cpp_nix_json_matches_tree_walk_with_nix_options(
        oracle,
        "builtins.genList (x: x) 1",
        &[("max-call-depth", "0")],
        TreeWalkOptions::with_max_call_depth(0),
    );

    for source in [
        "let x = x; in x",
        "let a = b; b = a; in a",
        "(rec { a = a; }).a",
        "(rec { a = b; b = a; }).a",
    ] {
        assert_cpp_nix_and_tree_walk_reject_with_final_error(
            oracle,
            source,
            "infinite recursion encountered",
            |kind| {
                matches!(
                    kind,
                    TreeWalkErrorKind::Force {
                        source: ForceError::InfiniteRecursion,
                        ..
                    }
                )
            },
        );
    }

    for source in [
        "(x: builtins.add 1 2) 0",
        "(x: (y: (z: z) 3) 2) 1",
        "builtins.all (x: true) [ 1 ]",
        "builtins.add ((x: x) 1) 2",
        "let add = builtins.add; in add ((x: x) 1) 2",
        "builtins.seq ((x: x) 1) 2",
        "builtins.map ((x: x) (y: y)) [ 1 ]",
        "builtins.trace ((x: x) \"m\") 1",
    ] {
        assert_cpp_nix_and_tree_walk_reject_with_final_error_and_nix_options(
            oracle,
            source,
            &[("max-call-depth", "0")],
            TreeWalkOptions::with_max_call_depth(0),
            "stack overflow; max-call-depth exceeded",
            |kind| matches!(kind, TreeWalkErrorKind::MaxCallDepthExceeded { .. }),
        );
    }

    assert_cpp_nix_and_tree_walk_reject_with_final_error_and_nix_options(
        oracle,
        "(x: (y: (z: z) 3) 2) 1",
        &[("max-call-depth", "1")],
        TreeWalkOptions::with_max_call_depth(1),
        "stack overflow; max-call-depth exceeded",
        |kind| matches!(kind, TreeWalkErrorKind::MaxCallDepthExceeded { .. }),
    );

    assert_cpp_nix_and_tree_walk_reject_with_final_error_and_nix_options(
        oracle,
        "let f = n: if n == 0 then 0 else f (n - 1); in f 20",
        &[("max-call-depth", "10")],
        TreeWalkOptions::with_max_call_depth(10),
        "stack overflow; max-call-depth exceeded",
        |kind| matches!(kind, TreeWalkErrorKind::MaxCallDepthExceeded { .. }),
    );
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix recursion check");
        return;
    };
    assert_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk(&oracle);
}

fn assert_cpp_nix_numeric_and_ordering_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        "builtins.add 1 2",
        "let add = builtins.add 1; in add 2",
        "builtins.sub 5 8",
        "builtins.mul 2 3",
        "builtins.div 7 2",
        "builtins.div 7 (-2)",
        "builtins.add 1 2.5",
        "builtins.sub 1 2.5",
        "builtins.mul 2 0.5",
        "builtins.div 7 2.0",
        "builtins.add 9223372036854775807 1",
        "builtins.sub (-9223372036854775807 - 1) 1",
        "builtins.mul 9223372036854775807 2",
        "builtins.bitAnd 6 3",
        "builtins.bitOr 4 1",
        "builtins.bitXor 6 3",
        "builtins.bitXor (-1) 1",
        "let xor = builtins.bitXor 6; in xor 3",
        "builtins.ceil 1",
        "builtins.ceil 1.2",
        "builtins.ceil (-1.2)",
        "builtins.ceil 9223372036854775808.0",
        "builtins.floor 1",
        "builtins.floor 1.8",
        "builtins.floor (-1.2)",
        "builtins.floor 9223372036854775808.0",
        "9223372036854775807",
        "0 + (-9223372036854775807 - 1)",
        "1 + 2",
        "5 - 8",
        "2 * 3",
        "7 / 2",
        "7 / (-2)",
        "(-7) / 2",
        "1 + 2.5",
        "1.5 + 2",
        "5 - 1.5",
        "5.5 - 2",
        "2 * 0.5",
        "2.5 * 2",
        "7 / 2.0",
        "7.0 / 2",
        "builtins.typeOf (7 / 2)",
        "builtins.typeOf (7 / 2.0)",
        "9223372036854775807 + 1",
        "(-9223372036854775807 - 1) - 1",
        "9223372036854775807 * 2",
        "let x = -9223372036854775807 - 1; in -x",
        "let x = 1; in -x",
        "let x = 1.5; in -x",
        "builtins.lessThan 1 2",
        "let less = builtins.lessThan 1; in less 2",
        "builtins.lessThan 2 1",
        "builtins.lessThan 1 1",
        "builtins.lessThan 1 1.5",
        "builtins.lessThan \"a\" \"b\"",
        "builtins.lessThan [ 1 2 ] [ 1 3 ]",
        "builtins.lessThan [ 1 (1 / 0) ] [ 2 (1 / 0) ]",
        "builtins.toString 1.25",
        "builtins.toString (-0.0)",
        "builtins.toString (builtins.add 1 2.5)",
        "builtins.toString (builtins.div 7 2.0)",
        "builtins.toString (0.1 + 0.2)",
        "builtins.toString (1.0 / 10.0)",
        "builtins.toString (5.5 - 2.2)",
        "builtins.toString (0.1 * 0.2)",
        "builtins.toString ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))",
        "builtins.toString (1.0e308 * 1.0e308)",
        "builtins.toString (builtins.sub 0.0 (1.0e308 * 1.0e308))",
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }

    for source in ["1 / 0", "1.0 / 0.0", "1.0 / -0.0"] {
        assert_cpp_nix_and_tree_walk_reject_with_final_error(
            &oracle,
            source,
            "division by zero",
            |kind| matches!(kind, TreeWalkErrorKind::DivisionByZero { .. }),
        );
    }

    for source in [
        "builtins.tryEval (1 / 0)",
        "builtins.tryEval (1.0 / 0.0)",
        "builtins.tryEval (1.0 / -0.0)",
    ] {
        assert_cpp_nix_and_tree_walk_reject_with_final_error(
            &oracle,
            source,
            "division by zero",
            |kind| matches!(kind, TreeWalkErrorKind::DivisionByZero { .. }),
        );
    }

    for source in [
        "(-9223372036854775807 - 1) / (-1)",
        "builtins.tryEval ((-9223372036854775807 - 1) / (-1))",
    ] {
        assert_cpp_nix_and_tree_walk_reject_with_final_error(
            &oracle,
            source,
            "overflow in integer division",
            |kind| {
                matches!(
                    kind,
                    TreeWalkErrorKind::ArithmeticOverflow {
                        op: ArithmeticOp::Div,
                        ..
                    }
                )
            },
        );
    }

    for source in ["let x = true; in -x"] {
        assert_cpp_nix_and_tree_walk_reject_expression(&oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_numeric_and_ordering_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_numeric_and_ordering_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_numeric_and_ordering_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix numeric check");
        return;
    };
    assert_cpp_nix_numeric_and_ordering_builtins_match_tree_walk(&oracle);
}

fn assert_cpp_nix_language_operators_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    let dir = unique_temp_dir("cpp-nix-language-operators");
    let base = dir.join("base");
    fs::create_dir(&base).expect("base directory creates");
    let suffix = dir.join("suffix.txt");
    fs::write(&suffix, b"abc").expect("suffix file writes");
    let base = path_source(&base);
    let missing = path_source(&dir.join("missing.txt"));
    let suffix = path_source(&suffix);

    for source in [
            "1 + 2".to_owned(),
            "1.5 + 2.0".to_owned(),
            "1 + 2.5".to_owned(),
            "1.5 + 2".to_owned(),
            r#""a" + "b""#.to_owned(),
            r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
               in builtins.getContext
                 (withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a"
                  + withCtx "b" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b")"#
                .to_owned(),
            format!("builtins.typeOf ({base} + \"/child\")"),
            format!("builtins.toString ({base} + \"/child\")"),
            format!("builtins.toString ({base} + {suffix})"),
            format!(r#""prefix-" + {suffix}"#),
            "({ a = 1; } // { b = 2; }).a".to_owned(),
            "({ a = 1; } // { a = 2; }).a".to_owned(),
            "({ a = { x = 1; }; } // { a = { y = 2; }; }).a".to_owned(),
            "builtins.attrNames ({ a = 1 / 0; } // { b = 2; })".to_owned(),
            "let xs = [ { a = 1; } ]; ys = [ { b = 2; } ]; in ((builtins.elemAt xs 0) // (builtins.elemAt ys 0)).b".to_owned(),
            "[ 1 ] ++ [ 2 ]".to_owned(),
            "builtins.length ([ (1 / 0) ] ++ [ 2 ])".to_owned(),
            r#"{ __toString = self: "left"; } + "right""#.to_owned(),
            r#"{ outPath = "left"; } + { outPath = "right"; }"#.to_owned(),
            format!("{{ __toString = self: {suffix}; }} + {suffix}"),
            format!("builtins.getContext ({{ __toString = self: {suffix}; }} + {suffix})"),
        ] {
            assert_cpp_nix_json_matches_tree_walk(oracle, &source);
        }

    for source in [
        "1 + \"a\"".to_owned(),
        "\"a\" + 1".to_owned(),
        "true + false".to_owned(),
        "null + null".to_owned(),
        "[ 1 ] + [ 2 ]".to_owned(),
        "({ a = 1; } + { b = 2; })".to_owned(),
        "(x: x) + (x: x)".to_owned(),
        format!(
            r#"{base} + (builtins.appendContext "/child" {{
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = {{ path = true; }};
                }})"#
        ),
        "({} // (1 / 0))".to_owned(),
        "((1 / 0) // {})".to_owned(),
        "(builtins.break { a = 1; }) // { b = 2; }".to_owned(),
        "{ a = 1; } // (builtins.break { b = 2; })".to_owned(),
        format!(r#""prefix-" + {missing}"#),
        "1 ++ []".to_owned(),
        "[] ++ 1".to_owned(),
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, &source);
    }

    let (matrix_dir, operands) = add_operator_matrix_operands("cpp-nix-add-matrix");
    for left in &operands {
        for right in &operands {
            let source = add_operator_matrix_source(left, right);
            if add_operator_matrix_cell_is_legal(left.kind, right.kind) {
                assert_cpp_nix_json_matches_tree_walk(oracle, &source);
            } else {
                assert_cpp_nix_and_tree_walk_reject_expression(oracle, &source);
            }
        }
    }
    fs::remove_dir_all(matrix_dir).expect("matrix temp directory removes");

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_language_operators_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_language_operators_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_language_operators_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix operator check");
        return;
    };
    assert_cpp_nix_language_operators_match_tree_walk(&oracle);
}

fn assert_cpp_nix_sort_and_less_than_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        "builtins.lessThan 1 1.5",
        "builtins.lessThan [ 1 ] [ 1 0 ]",
        "builtins.lessThan [ 1 [ 2 ] ] [ 1 [ 3 ] ]",
        "builtins.lessThan [ 1 2.0 ] [ 1 3 ]",
        "builtins.lessThan [ 1 3 ] [ 1 2 ]",
        "builtins.lessThan [ 1 2 ] [ 1 2 ]",
        "builtins.lessThan [ 1 (1 / 0) ] [ 2 (1 / 0) ]",
        "builtins.sort builtins.lessThan [ 3 1 2 1 ]",
        "let sort = builtins.sort builtins.lessThan; in sort [ 3 1 2 ]",
        "builtins.sort (a: b: builtins.lessThan b a) [ 3 1 2 ]",
        "builtins.map (x: x.name) (builtins.sort (a: b: a.key < b.key) [ { key = 1; name = \"a\"; } { key = 1; name = \"b\"; } { key = 0; name = \"c\"; } ])",
        "builtins.map (x: x.name) (builtins.sort (a: b: false) [ { name = \"a\"; } { name = \"b\"; } { name = \"c\"; } ])",
        "builtins.map (x: x.name) (builtins.sort (a: b: false) (builtins.genList (i: { name = builtins.toString i; }) 129))",
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }

    for source in [
        "builtins.lessThan 1 \"1\"",
        "builtins.lessThan true false",
        "builtins.lessThan [ 1 true ] [ 1 false ]",
        "builtins.lessThan [ 1 \"x\" ] [ 1 2 ]",
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(&oracle, source);
    }

    assert_cpp_nix_and_tree_walk_throw_message(
        oracle,
        "builtins.sort (a: b:
              if a == 2 && b == 1 then builtins.throw \"wrong-order\"
              else if a == 2 && b == 3 then builtins.throw \"2<3\"
              else a < b)
            [ 3 1 2 ]",
        "2<3",
    );
    assert_cpp_nix_and_tree_walk_throw_message(
        oracle,
        "builtins.sort (a: b:
              if a == 1 && b == 66 then builtins.throw \"top-merge\"
              else a < b)
            (builtins.genList (i: 129 - i) 129)",
        "top-merge",
    );
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_sort_and_less_than_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_sort_and_less_than_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_sort_and_less_than_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix sort check");
        return;
    };
    assert_cpp_nix_sort_and_less_than_builtins_match_tree_walk(&oracle);
}

fn assert_cpp_nix_laziness_and_evaluation_semantics_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        "builtins.isAttrs { x = builtins.throw \"unforced\"; }",
        "builtins.length [ (builtins.throw \"unforced\") ]",
        "(x: 1) (builtins.throw \"unforced\")",
        "let x = builtins.throw \"unforced\"; in 1",
        "{ a = builtins.throw \"unforced\"; b = 2; }.b",
        "let x = builtins.abort \"unforced\"; in 1",
        "(x: 1) (builtins.abort \"unforced\")",
        "builtins.length [ (builtins.abort \"unforced\") ]",
        "{ a = builtins.abort \"unforced\"; } ? a",
        "builtins.seq { x = 1 / 0; } 2",
        "builtins.seq [ (1 / 0) ] 2",
        "builtins.length (builtins.seq 1 [ (1 / 0) ])",
        "let seq = builtins.seq 1; in seq 2",
        "builtins.deepSeq [ 1 [ 2 ] ] 3",
        "builtins.deepSeq { a = { b = 1; }; } 3",
        "builtins.deepSeq (x: x) 3",
        "let x = { a = x; }; in builtins.deepSeq x 3",
        "let x = [ x ]; in builtins.deepSeq x 3",
        "let deepSeq = builtins.deepSeq [ 1 ]; in deepSeq 2",
        "(builtins.tryEval (builtins.throw \"boom\")).success",
        "(builtins.tryEval (assert false; 1)).success",
        "(builtins.tryEval 7).value",
        "(builtins.tryEval { x = builtins.throw \"boom\"; }).success",
        "builtins.isAttrs (builtins.tryEval { x = builtins.throw \"boom\"; }).value",
        "(builtins.tryEval [ (builtins.throw \"boom\") ]).success",
        "builtins.length (builtins.tryEval [ (builtins.throw \"boom\") ]).value",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        "let x = builtins.trace \"let\" 1; in x + x",
        "(x: x + x) (builtins.trace \"arg\" 1)",
        "let xs = [ (builtins.trace \"list\" 1) ]; in (builtins.elemAt xs 0) + (builtins.elemAt xs 0)",
        "let set = { x = builtins.trace \"attr\" 1; }; in set.x + set.x",
        "let x = builtins.trace \"retry\" (builtins.throw \"boom\"); a = builtins.tryEval x; b = builtins.tryEval x; in if a.success == false && b.success == false then 1 else 0",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
        let reference = cpp_nix_eval_stderr(oracle, source);
        let stderr = eval_captured_stderr(source);
        assert_eq!(stderr, reference, "trace stderr diverged for {source}");
    }

    for source in [
        "builtins.tryEval (builtins.abort \"boom\")",
        "builtins.tryEval (1 + true)",
        "builtins.tryEval ({ }).missing",
        "builtins.tryEval (builtins.elemAt [] 0)",
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }

    for (source, expected_message) in [
        (
            "builtins.seq (builtins.throw \"first\") (builtins.throw \"second\")",
            "first",
        ),
        ("builtins.seq 1 (builtins.throw \"second\")", "second"),
        (
            "builtins.deepSeq [ (builtins.throw \"first\") (builtins.throw \"second\") ] 1",
            "first",
        ),
        (
            "builtins.deepSeq { z = builtins.throw \"z\"; a = builtins.throw \"a\"; } 1",
            "z",
        ),
        (
            "builtins.deepSeq [ 1 ] (builtins.throw \"second\")",
            "second",
        ),
        (
            "builtins.add (builtins.throw \"left\") (builtins.throw \"right\")",
            "left",
        ),
        (
            "builtins.deepSeq { x = builtins.throw \"nested\"; } 1",
            "nested",
        ),
    ] {
        assert_cpp_nix_and_tree_walk_throw_message(oracle, source, expected_message);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_laziness_and_evaluation_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_laziness_and_evaluation_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_laziness_and_evaluation_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix laziness check");
        return;
    };
    assert_cpp_nix_laziness_and_evaluation_semantics_match_tree_walk(&oracle);
}

fn assert_cpp_nix_let_with_scoping_semantics_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        "let a = 1; b = a + 1; in b",
        "let a = b; b = 1; in a",
        "let a = 1; in let b = a + 1; in b",
        "let x = 1 / 0; in 7",
        r#"let ${"x"} = 1; in x"#,
        r#"let ${"a"}.b = 1; in a.b"#,
        "let x = 1; inherited = let inherit x; in x; in let x = 2; in inherited",
        "let src = { x = 1; y = 2; }; inherit (src) x y; in x + y",
        "let inherit (src) x; src = { x = 5; }; in x",
        "let inherit ({}) x; in 42",
        "with { a = 1; }; a",
        "with { f = x: x + 1; }; f 2",
        "with (1 / 0); 7",
        "with { a = 1 / 0; }; 7",
        "with { a = 1; }; with { a = 2; }; a",
        "let a = 3; in with { a = 1; }; a",
        "with { a = 1; }; let a = 3; in a",
        "(x: with { x = 1; }; x) 3",
        "with { true = 1; }; true",
        "with { false = 1; }; false",
        "with { null = 1; }; null",
        "builtins.isAttrs (with { builtins = 1; }; builtins)",
        "with { currentTime = 123; }; currentTime",
        r#"with { storeDir = "with"; }; storeDir"#,
        "with { langVersion = 9; }; langVersion",
        r#"with { nixVersion = "with"; }; nixVersion"#,
        "with { length = xs: 7; }; length [ 1 ]",
        "with { concatMap = f: xs: 7; }; concatMap (x: [ x ]) [ 1 ]",
        "with { map = f: xs: 7; }; map (x: x) [ 1 ]",
        r#"with { toString = x: "with"; }; toString 1"#,
        "with { baseNameOf = x: \"with\"; }; baseNameOf /a/b",
        r#"let f = derivationStrict; d = f {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }; in builtins.hasAttr "out" d"#,
        r#"let f = builtins.derivationStrict; d = f {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }; in builtins.hasAttr "drvPath" d"#,
        r#"with { derivationStrict = x: x; }; let f = derivationStrict; d = f {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }; in builtins.hasAttr "out" d"#,
        "with {}; true",
        "with {}; false",
        "with {}; null",
        "let x = 1; f = y: with { a = x + y; }; a; in let x = 10; in f x",
        "let x = 1; scope = { a = x; }; f = y: with scope; a + y; in f 2",
        "let f = with { a = 1; }; x: a + x; in f 2",
        "(with { a = 1 + 2; }; { b = a; }).b",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        r#"let inherit (builtins.trace "source" { x = 1; }) x; in 42"#,
        r#"let inherit (builtins.trace "source" { x = 1; y = 2; }) x y; in x + y"#,
        r#"with (builtins.trace "scope" { a = 1; }); 7"#,
        r#"with (builtins.trace "scope" { a = 1; }); a"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
        let reference = cpp_nix_eval_stderr(oracle, source);
        let stderr = eval_captured_stderr(source);
        assert_eq!(stderr, reference, "trace stderr diverged for {source}");
    }

    for source in [
        r#"let name = "a"; ${name} = 1; in a"#,
        r#"let ${"x" + "y"} = 1; in 1"#,
        r#"let ${"a${"b"}"} = 1; in 1"#,
        "let a = 1; a = 2; in a",
        "let inherit x; x = 1; in x",
        "let inherit (src) x; x = 1; in x",
    ] {
        assert_cpp_nix_parse_and_aos_frontend_reject_expression(oracle, source);
    }

    for source in ["with 1; missing", "with {}; missing"] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }

    assert_cpp_nix_and_tree_walk_reject_expression(
        oracle,
        "with { derivationStrict = x: x; }; let f = derivationStrict; in f 1",
    );
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_let_with_scoping_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_let_with_scoping_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_let_with_scoping_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix let/with check");
        return;
    };
    assert_cpp_nix_let_with_scoping_semantics_match_tree_walk(&oracle);
}

fn assert_cpp_nix_control_flow_and_error_semantics_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        "if true then 1 else 2",
        "if false then 1 else 2",
        "if true then 7 else (builtins.throw \"else\")",
        "if false then (builtins.throw \"then\") else 9",
        "assert true; 5",
        "assert (builtins.isInt 1); 6",
        "let x = builtins.throw \"latent\"; in 1",
        "let x = builtins.abort \"latent\"; in 1",
        "{ a = builtins.throw \"latent\"; b = 2; }.b",
        "builtins.length [ (builtins.throw \"latent\") ]",
        "(builtins.tryEval (builtins.throw \"boom\")).success",
        "(builtins.tryEval (assert false; 1)).success",
        "(builtins.tryEval 7).success",
        "(builtins.tryEval 7).value",
        "(builtins.tryEval { x = builtins.throw \"boom\"; }).success",
        "builtins.isAttrs (builtins.tryEval { x = builtins.throw \"boom\"; }).value",
        "(builtins.tryEval [ (builtins.throw \"boom\") ]).success",
        "builtins.length (builtins.tryEval [ (builtins.throw \"boom\") ]).value",
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        "if 1 then 2 else 3",
        "assert 1; 2",
        "assert false; 2",
        "builtins.tryEval (builtins.abort \"boom\")",
        "builtins.tryEval (1 + true)",
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }

    for (source, expected_message) in [
        ("builtins.throw \"boom\"", "boom"),
        ("let f = builtins.throw; in f \"boom\"", "boom"),
    ] {
        assert_cpp_nix_and_tree_walk_throw_message(oracle, source, expected_message);
    }

    assert_cpp_nix_and_tree_walk_reject_with_final_error(
        oracle,
        "assert false; builtins.abort \"body\"",
        "assertion 'false' failed",
        |kind| matches!(kind, TreeWalkErrorKind::AssertionFailed { .. }),
    );

    assert_cpp_nix_parse_and_aos_frontend_reject_expression(oracle, "if true then 1");
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_control_flow_and_error_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_control_flow_and_error_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_control_flow_and_error_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix control/error check");
        return;
    };
    assert_cpp_nix_control_flow_and_error_semantics_match_tree_walk(&oracle);
}

fn assert_cpp_nix_import_semantics_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    let root =
        fs::canonicalize(unique_temp_dir("cpp-nix-import")).expect("temp directory canonicalizes");
    let subdir = root.join("sub");
    let dir_import = root.join("dir");
    let empty_dir = root.join("empty-dir");
    fs::create_dir(&subdir).expect("sub directory creates");
    fs::create_dir(&dir_import).expect("import directory creates");
    fs::create_dir(&empty_dir).expect("empty import directory creates");
    fs::write(subdir.join("dep.nix"), b"2").expect("dep writes");
    fs::write(subdir.join("inc.nix"), b"3").expect("inc writes");
    fs::write(subdir.join("data.txt"), b"data").expect("data writes");
    fs::write(subdir.join("rec.nix"), b"rec { x = 4; y = x; }").expect("rec writes");
    fs::write(
        subdir.join("child.nix"),
        br#"{
              a = 1;
              nested = import ./dep.nix;
              f = x: x + import ./inc.nix;
              formal = { a ? 1, b }: a + b;
              rel = ./data.txt;
            }"#,
    )
    .expect("child writes");
    fs::write(dir_import.join("default.nix"), b"5").expect("default writes");
    fs::write(root.join("fresh.nix"), b"secret").expect("fresh writes");
    fs::write(root.join("traced.nix"), br#"builtins.trace "once" 9"#).expect("traced writes");
    fs::write(root.join("scoped-value.nix"), b"x").expect("scoped value writes");
    fs::write(root.join("scoped-shadow.nix"), b"builtins.add 1 2").expect("scoped shadow writes");
    fs::write(root.join("scoped-lambda.nix"), b"y: secret + y").expect("scoped lambda writes");
    fs::write(root.join("scoped-importer.nix"), b"import ./fresh.nix")
        .expect("scoped importer writes");
    fs::write(root.join("scoped-true.nix"), b"true").expect("scoped true writes");
    fs::write(root.join("scoped-false.nix"), b"false").expect("scoped false writes");
    fs::write(root.join("scoped-null.nix"), b"null").expect("scoped null writes");
    fs::write(
        root.join("scoped-trace.nix"),
        br#"builtins.trace "scoped" 1"#,
    )
    .expect("scoped trace writes");
    std::os::unix::fs::symlink(root.join("traced.nix"), root.join("traced-link.nix"))
        .expect("trace symlink creates");
    let traced_dir = root.join("traced-dir");
    fs::create_dir(&traced_dir).expect("traced dir creates");
    fs::write(
        traced_dir.join("default.nix"),
        br#"builtins.trace "dir-once" 8"#,
    )
    .expect("traced default writes");

    let child = path_source(&subdir.join("child.nix"));
    let dir = path_source(&dir_import);
    let empty_dir = path_source(&empty_dir);
    for source in [
        format!("(import {child}).a"),
        format!("(import {child}).nested"),
        format!("(import {child}).f 4"),
        format!("builtins.baseNameOf ((import {child}).rel)"),
        format!("import {dir}"),
        format!("let f = import; in builtins.isAttrs (f {child})"),
        format!(
            "builtins.scopedImport {{ x = 7; }} {path}",
            path = path_source(&root.join("scoped-value.nix"))
        ),
        format!(
            "builtins.scopedImport {{ builtins = {{ add = a: b: 10; }}; }} {path}",
            path = path_source(&root.join("scoped-shadow.nix"))
        ),
        format!(
            "(builtins.scopedImport {{ secret = 5; }} {path}) 2",
            path = path_source(&root.join("scoped-lambda.nix"))
        ),
        format!(
            "builtins.scopedImport {{ import = path: 42; }} {path}",
            path = path_source(&root.join("scoped-importer.nix"))
        ),
        format!(
            "builtins.scopedImport {{ true = 1; }} {path}",
            path = path_source(&root.join("scoped-true.nix"))
        ),
        format!(
            "builtins.scopedImport {{ false = 2; }} {path}",
            path = path_source(&root.join("scoped-false.nix"))
        ),
        format!(
            "builtins.scopedImport {{ null = 3; }} {path}",
            path = path_source(&root.join("scoped-null.nix"))
        ),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    let fresh = path_source(&root.join("fresh.nix"));
    assert_cpp_nix_and_tree_walk_reject_expression(
        oracle,
        &format!("with {{ secret = 42; }}; import {fresh}"),
    );
    assert_cpp_nix_and_tree_walk_reject_expression(oracle, &format!("import {empty_dir}"));
    assert_cpp_nix_and_tree_walk_reject_expression(
        oracle,
        &format!(
            "builtins.scopedImport {{ secret = 9; }} {path}",
            path = path_source(&root.join("scoped-importer.nix"))
        ),
    );

    for source in [
        format!(
            "builtins.deepSeq [ (import {path}) (import {path}) ] 0",
            path = path_source(&root.join("traced.nix"))
        ),
        format!(
            "builtins.deepSeq [ (import {path}) (import {link}) ] 0",
            path = path_source(&root.join("traced.nix")),
            link = path_source(&root.join("traced-link.nix"))
        ),
        format!(
            "builtins.deepSeq [ (import {dir}) (import {default}) ] 0",
            dir = path_source(&traced_dir),
            default = path_source(&traced_dir.join("default.nix"))
        ),
        format!(
            "builtins.deepSeq [ (builtins.scopedImport {{ }} {path}) (builtins.scopedImport {{ }} {path}) ] 0",
            path = path_source(&root.join("scoped-trace.nix"))
        ),
    ] {
        let reference = cpp_nix_eval_stderr(oracle, &source);
        let stderr = eval_captured_stderr(&source);
        assert_eq!(
            stderr, reference,
            "import cache stderr diverged for {source}"
        );
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_import_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_import_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_import_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix import check");
        return;
    };
    assert_cpp_nix_import_semantics_match_tree_walk(&oracle);
}

fn assert_cpp_nix_string_context_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.getContext (builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
            })"#,
        r#"builtins.getContext (builtins.appendContext "x" {
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = {
                    path = true;
                    allOutputs = true;
                    outputs = [ "out" "dev" "" "out" ];
                };
            })"#,
        r#"builtins.hasContext (builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
            })"#,
        r#"builtins.getContext (builtins.appendContext
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                })
                {
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other" = { path = true; };
                    "/nix/store/cccccccccccccccccccccccccccccccc-empty" = {
                        path = false;
                        allOutputs = false;
                        outputs = [];
                    };
                })"#,
        r#"builtins.getContext (builtins.appendContext
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { outputs = [ "out" ]; };
                })
                {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = {
                        path = true;
                        allOutputs = true;
                        outputs = [ "dev" ];
                    };
                })"#,
        r#"builtins.getContext (builtins.unsafeDiscardStringContext
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                }))"#,
        r#"builtins.getContext (builtins.unsafeDiscardOutputDependency
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { allOutputs = true; };
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-out.drv" = { outputs = [ "out" ]; };
                    "/nix/store/cccccccccccccccccccccccccccccccc-src" = { path = true; };
                }))"#,
        r#"builtins.getContext (builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { path = true; };
                }))"#,
        r#"builtins.getContext (builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { allOutputs = true; };
                }))"#,
        r#"let append = builtins.appendContext "x"; in
               builtins.getContext (append {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
               })"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        "builtins.appendContext 1 {}",
        r#"builtins.appendContext { outPath = "abc"; } {}"#,
        r#"builtins.appendContext "x" 1"#,
        r#"builtins.appendContext "x" { "not-a-store-path" = { path = true; }; }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = 1;
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = 1; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-." = { path = true; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-.." = { path = true; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { allOutputs = true; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { outputs = [ "out" ]; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = { outputs = [ 1 ]; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = {
                    outputs = [
                      (builtins.appendContext "out" {
                        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                      })
                    ];
                };
            }"#,
        r#"builtins.addDrvOutputDependencies "x""#,
        r#"builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                })"#,
        r#"builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { outputs = [ "out" ]; };
                })"#,
        r#"builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a.drv" = { path = true; };
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b.drv" = { path = true; };
                })"#,
        r#"builtins.unsafeDiscardOutputDependency 1"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_string_context_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_string_context_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_string_context_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix string context check");
        return;
    };
    assert_cpp_nix_string_context_builtins_match_tree_walk(&oracle);
}

fn assert_cpp_nix_string_coercion_contexts_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 b = withCtx "b" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
               in builtins.getContext (builtins.toString [ a 1 b ])"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 b = withCtx "b" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
               in builtins.getContext "${a}${b}""#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 b = withCtx "b" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
               in builtins.getContext (a + b)"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 b = withCtx "b" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
                 sep = withCtx ":" "/nix/store/cccccccccccccccccccccccccccccccc-sep";
               in builtins.getContext (builtins.concatStringsSep sep [ a b ])"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 sep = withCtx ":" "/nix/store/cccccccccccccccccccccccccccccccc-sep";
               in {
                 single = builtins.getContext (builtins.concatStringsSep sep [ a ]);
                 empty = builtins.getContext (builtins.concatStringsSep sep []);
               }"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 source = withCtx "x" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
                 used = withCtx "X" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-used";
                 unused = withCtx "Z" "/nix/store/cccccccccccccccccccccccccccccccc-unused";
                 pattern = withCtx "x" "/nix/store/dddddddddddddddddddddddddddddddd-pattern";
               in {
                 used = builtins.getContext
                   (builtins.replaceStrings [ "x" "z" ] [ used unused ] source);
                 unused = builtins.getContext
                   (builtins.replaceStrings [ "y" ] [ used ] source);
                 patternContext = builtins.getContext
                   (builtins.replaceStrings [ pattern ] [ used ] source);
               }"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 hook = withCtx "hook" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hook";
                 out = withCtx "out" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-out";
               in {
                 toStringHook = builtins.getContext
                   (builtins.toString { __toString = self: hook; });
                 toStringOut = builtins.getContext
                   (builtins.toString { outPath = out; });
                 interpolationHook = builtins.getContext
                   "${{ __toString = self: hook; }}";
                 interpolationOut = builtins.getContext
                   "${{ outPath = out; }}";
               }"#,
        r#"let
                 strict = derivationStrict {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
                 drv = {
                   type = "derivation";
                   name = "x";
                   drvPath = strict.drvPath;
                   outPath = strict.out;
                 };
               in builtins.getContext (builtins.toString drv)"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_string_coercion_contexts_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_string_coercion_contexts_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_string_coercion_contexts_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix coercion check");
        return;
    };
    assert_cpp_nix_string_coercion_contexts_match_tree_walk(&oracle);
}

fn assert_cpp_nix_derivation_wrapper_matches_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        r#"let
                 d = derivation {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in {
                 allLen = builtins.length d.all;
                 allOutputNames = builtins.map (x: x.outputName) d.all;
                 attrNames = builtins.attrNames d;
                 drvAttrs = builtins.attrNames d.drvAttrs;
                 drvPath = d.drvPath;
                 functionArgs = builtins.functionArgs derivation;
                 isFunction = builtins.isFunction builtins.derivation;
                 kind = d.type;
                 outNames = builtins.attrNames d.out;
                 outputName = d.outputName;
                 pathOut = d.outPath;
                 rendered = "${d}";
                 renderedContext = builtins.getContext "${d}";
                 type = builtins.typeOf derivation;
               }"#,
        r#"let
                 d = builtins.derivation {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                   outputs = [ "out" "dev" ];
                 };
               in {
                 allLen = builtins.length d.all;
                 allOutputNames = builtins.map (x: x.outputName) d.all;
                 devNested = d.dev.out.dev.dev.outPath;
                 devOutPath = d.dev.outPath;
                 drvAttrs = builtins.attrNames d.drvAttrs;
                 names = builtins.attrNames d;
                 outNested = d.out.dev.out.outPath;
                 pathOut = d.outPath;
                 outputs = d.outputs;
               }"#,
        r#"let
                 d = derivation {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                   outputs = [ "dev" ];
                 };
               in {
                 allLen = builtins.length d.all;
                 hasDev = builtins.hasAttr "dev" d;
                 hasOut = builtins.hasAttr "out" d;
                 names = builtins.attrNames d;
                 outputName = d.outputName;
                 pathOut = d.outPath;
               }"#,
        r#"let
                 f = builtins.derivation;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        r#"derivation {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = "out dev";
               }"#,
        r#"derivation {
                 name = "x";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }.drvPath"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_derivation_wrapper_matches_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_derivation_wrapper_matches_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_derivation_wrapper_matches_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix derivation wrapper check");
        return;
    };
    assert_cpp_nix_derivation_wrapper_matches_tree_walk(&oracle);
}

fn assert_cpp_nix_to_string_builtin_matches_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    let (dir, path) = temp_file_with_bytes("cpp-nix-to-string-path", b"abc");
    let path = path_source(&path);

    for source in [
        r#"builtins.toString "x""#.to_owned(),
        "builtins.toString 1".to_owned(),
        "builtins.toString (-2)".to_owned(),
        "builtins.toString 9223372036854775807".to_owned(),
        "builtins.toString (-9223372036854775807 - 1)".to_owned(),
        "builtins.toString 1.0".to_owned(),
        "builtins.toString 1.25".to_owned(),
        "builtins.toString 1.23456789".to_owned(),
        "builtins.toString (-0.0)".to_owned(),
        "builtins.toString 0.00001".to_owned(),
        "builtins.toString 0.0000001".to_owned(),
        "builtins.toString 1000000.0".to_owned(),
        "builtins.toString ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))".to_owned(),
        "builtins.toString (1.0e308 * 1.0e308)".to_owned(),
        "builtins.toString (builtins.sub 0.0 (1.0e308 * 1.0e308))".to_owned(),
        "builtins.toString true".to_owned(),
        "builtins.toString false".to_owned(),
        "builtins.toString null".to_owned(),
        format!("builtins.toString {path}"),
        "builtins.toString [ 1 \"x\" true false null ]".to_owned(),
        "builtins.toString [ \"x\" [] \"y\" ]".to_owned(),
        "builtins.toString [ [ \"a\" \"b\" ] [ \"c\" \"\" ] [ \"\" \"d\" ] ]".to_owned(),
        "builtins.toString { __toString = self: 1; outPath = 1 / 0; }".to_owned(),
        r#"builtins.toString { __toString = self: [ "a" "b" ]; }"#.to_owned(),
        r#"builtins.toString { outPath = [ "a" "b" ]; }"#.to_owned(),
        r#"let f = builtins.toString; in f [ "a" "b" ]"#.to_owned(),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    for source in [
        "builtins.toString [ \"a\" (1 / 0) ]",
        "builtins.toString (x: x)",
        r#"builtins.toString { __toString = "bad"; outPath = "fallback"; }"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_to_string_builtin_matches_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_to_string_builtin_matches_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_to_string_builtin_matches_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix toString check");
        return;
    };
    assert_cpp_nix_to_string_builtin_matches_tree_walk(&oracle);
}

fn assert_cpp_nix_string_path_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.substring 1 3 "abcdef""#,
        r#"builtins.substring 1 2 { outPath = "abcd"; }"#,
        r#"let slice = builtins.substring 1; take2 = slice 2; in take2 "abcd""#,
        r#"builtins.stringLength "a\n""#,
        r#"builtins.stringLength { __toString = self: self.name; name = "custom"; }"#,
        r#"builtins.replaceStrings [ "a" "bc" ] [ "x" "Y" ] "abcabc""#,
        r#"builtins.replaceStrings [ "" ] [ "x" ] "ab""#,
        r#"builtins.replaceStrings [ "a" "ab" ] [ "X" "Y" ] "ababa""#,
        r#"builtins.replaceStrings [ "ab" "a" ] [ "Y" "X" ] "ababa""#,
        r#"let replace = builtins.replaceStrings [ "a" ]; swap = replace [ "b" ]; in swap "a""#,
        r#"builtins.concatStringsSep ":" [ "a" { outPath = "b"; } { __toString = self: "c"; } ]"#,
        r#"let join = builtins.concatStringsSep ","; in join [ "a" "b" ]"#,
        r#"builtins.match "a(.)c" "abc""#,
        r#"builtins.match "a(.)" "abc""#,
        r#"builtins.match "abc" "abc""#,
        r#"builtins.match "a|aa" "aa""#,
        r#"builtins.match "(a|aa)" "aa""#,
        r#"builtins.match "(a)?b" "b""#,
        r#"builtins.match "(a*)" """#,
        r#"builtins.match "a{2,3}" "aaa""#,
        r#"let m = builtins.match "a(.)c"; in m "abc""#,
        r#"builtins.split "-" "a-b-c""#,
        r#"builtins.split "(-)" "a-b-c""#,
        r#"builtins.split "(a)?b" "b-ab""#,
        r#"builtins.split "a*" "baac""#,
        r#"builtins.split "(a*)" "baac""#,
        r#"builtins.split "a?" "bc""#,
        r#"builtins.split "^" "abc""#,
        r#"builtins.split "$" "abc""#,
        r#"builtins.split "^|$" "abc""#,
        r#"builtins.split "^|$" "a""#,
        r#"builtins.split "a*$" "baac""#,
        r#"builtins.length (builtins.split "." "éx")"#,
        r#"builtins.stringLength (builtins.elemAt (builtins.elemAt (builtins.split "(.)" "éx") 1) 0)"#,
        r#"let split = builtins.split "-"; in split "a-b""#,
        r#"builtins.splitVersion "1.0pre2""#,
        r#"builtins.splitVersion "foo-1.2_bar""#,
        r#"builtins.splitVersion "1+2~pre""#,
        r#"builtins.compareVersions "1.0pre2" "1.0pre10""#,
        r#"builtins.compareVersions "1a" "1.0""#,
        r#"builtins.compareVersions "1.0" "1.0.0""#,
        r#"let cmp = builtins.compareVersions "1.2"; in cmp "1.10""#,
        r#"builtins.parseDrvName "foo-1.2""#,
        r#"builtins.parseDrvName "foo--1""#,
        r#"builtins.parseDrvName "foo-.1""#,
        r#"builtins.parseDrvName "foo-_1""#,
        r#"builtins.parseDrvName "foo-A-1""#,
        r#"builtins.parseDrvName "foo-""#,
        r#"builtins.parseDrvName "-1""#,
        r#"builtins.baseNameOf "/a/b/""#,
        r#"builtins.dirOf "/a/b/""#,
        r#"builtins.baseNameOf "a//""#,
        r#"builtins.dirOf "a//""#,
        r#"builtins.baseNameOf "//a""#,
        r#"builtins.dirOf "//a""#,
        r#"builtins.dirOf { __toString = self: "/a/b"; }"#,
        r#"builtins.toPath "/tmp/../var/./tmp//""#,
        r#"let toPath = builtins.toPath; in toPath "/tmp/foo//bar""#,
        r#"builtins.typeOf (builtins.toPath "/tmp")"#,
        r#"builtins.toPath { __toString = self: "/tmp/from-to-string"; }"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }

    for source in [
        r#"builtins.match "" """#,
        r#"builtins.match "[" "x""#,
        r#"builtins.match "()" """#,
        r#"builtins.match "(?:a)" "a""#,
        r#"builtins.match "\\d" "1""#,
        r#"builtins.match "a|" "a""#,
        r#"builtins.match "(|a)" "a""#,
        r#"builtins.match "\\x61" "a""#,
        r#"builtins.match "\\n" "n""#,
        r#"builtins.match "a*?" "aaa""#,
        r#"builtins.match "a{1,2}?" "aa""#,
        r#"builtins.split "" "abc""#,
        r#"builtins.split "[" "x""#,
        r#"builtins.split "()" """#,
        r#"builtins.split "(?:a)" "a""#,
        r#"builtins.split "\\d" "1""#,
        r#"builtins.split "a|" "a""#,
        r#"builtins.split "(|a)" "a""#,
        r#"builtins.split "\\x61" "a""#,
        r#"builtins.split "\\n" "n""#,
        r#"builtins.split "a*?" "aaa""#,
        r#"builtins.split "a{1,2}?" "aa""#,
        r#"builtins.parseDrvName (builtins.appendContext "foo-1" { "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; }; })"#,
        r#"builtins.toPath "relative/path""#,
        r#"builtins.toPath 1"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(&oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_string_path_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_string_path_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_string_path_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix string/path check");
        return;
    };
    assert_cpp_nix_string_path_builtins_match_tree_walk(&oracle);
}

fn assert_cpp_nix_filesystem_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    let root = fs::canonicalize(unique_temp_dir("filesystem-builtins"))
        .expect("temp directory canonicalizes");
    let regular = root.join("regular.txt");
    let nested = root.join("nested");
    let link = root.join("link");
    let link_dir = root.join("link-dir");
    let dangling = root.join("dangling");
    fs::write(&regular, b"hello\n").expect("regular file writes");
    fs::create_dir(&nested).expect("nested directory creates");
    std::os::unix::fs::symlink(&regular, &link).expect("file symlink creates");
    std::os::unix::fs::symlink(&nested, &link_dir).expect("directory symlink creates");
    std::os::unix::fs::symlink(root.join("missing-target"), &dangling)
        .expect("dangling symlink creates");

    let root_source = nix_string_literal(&path_source(&root));
    let regular_path = path_source(&regular);
    let regular_source = nix_string_literal(&regular_path);
    let nested_source = nix_string_literal(&path_source(&nested));
    let link_source = nix_string_literal(&path_source(&link));
    let link_dir_path = path_source(&link_dir);
    let link_dir_source = nix_string_literal(&link_dir_path);
    let dangling_path = path_source(&dangling);
    let dangling_source = nix_string_literal(&dangling_path);
    let missing_source = nix_string_literal(&path_source(&root.join("missing")));

    for source in [
        format!("builtins.readFile {regular_source}"),
        format!("builtins.readFile {regular_path}"),
        format!(r#"let f = builtins.readFile; in f {link_source}"#),
        format!("builtins.hasContext (builtins.readFile {regular_source})"),
        format!("builtins.readDir {root_source}"),
        format!("builtins.attrNames (builtins.readDir {root_source})"),
        format!("builtins.readFileType {regular_source}"),
        format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{regular_path}/."))
        ),
        format!("builtins.readFileType {nested_source}"),
        format!("builtins.readFileType {link_source}"),
        format!("builtins.readFileType {link_dir_source}"),
        format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{link_dir_path}/"))
        ),
        format!("builtins.readFileType {dangling_source}"),
        format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{dangling_path}/."))
        ),
        format!("builtins.pathExists {regular_source}"),
        format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{regular_path}/."))
        ),
        format!("builtins.pathExists {nested_source}"),
        format!("builtins.pathExists {link_dir_source}"),
        format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{link_dir_path}/"))
        ),
        format!("builtins.pathExists {dangling_source}"),
        format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{dangling_path}/"))
        ),
        format!("builtins.pathExists {missing_source}"),
        format!(
            "builtins.pathExists {{ outPath = {}; }}",
            nix_string_literal(&format!("{regular_path}/"))
        ),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_filesystem_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_filesystem_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_filesystem_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix filesystem check");
        return;
    };
    assert_cpp_nix_filesystem_builtins_match_tree_walk(&oracle);
}

#[test]
fn filesystem_builtins_report_unsupported_ifd_without_realizer() {
    let root =
        fs::canonicalize(unique_temp_dir("ifd-unsupported")).expect("temp dir canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let file_path = output_path.join("data.txt");
    let source = format!(
        "builtins.readFile (builtins.appendContext {file} {{ {drv} = {{ outputs = [ \"out\" ]; }}; }})",
        file = nix_string_literal(&path_source(&file_path)),
        drv = nix_string_literal(&path_source(&drv_path)),
    );
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");

    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("IFD requires a realizer");
    let TreeWalkErrorKind::UnsupportedImportFromDerivation { op, detail, .. } = error.kind() else {
        panic!("unexpected error kind: {error:?}");
    };
    assert_eq!(op, "readFile");
    assert_eq!(detail.path(), file_path.as_os_str().as_bytes());
    assert_eq!(detail.drv_path(), drv_path.as_os_str().as_bytes());
    assert_eq!(detail.output_name(), Some(b"out".as_slice()));
    assert_eq!(detail.context_kind(), ContextKind::SingleOutput);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn filesystem_builtins_realize_ifd_context_before_reading_paths() {
    let root =
        fs::canonicalize(unique_temp_dir("ifd-realizer")).expect("temp directory canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let data_path = output_path.join("data.txt");
    let import_path = output_path.join("imported.nix");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_realizer = Arc::clone(&requests);
    let drv_path_for_realizer = drv_path.as_os_str().as_bytes().to_vec();
    let output_path_for_realizer = output_path.clone();
    let data_path_for_realizer = data_path.clone();
    let import_path_for_realizer = import_path.clone();
    let realizer = IfdRealizer::new(move |request| {
        if request.drv_path() != drv_path_for_realizer.as_slice() {
            return Err(IfdRealizationError::new("unexpected derivation path"));
        }
        if request.output_name() != Some(b"out".as_slice()) {
            return Err(IfdRealizationError::new("unexpected output name"));
        }
        requests_for_realizer
            .lock()
            .expect("request log lock")
            .push((
                request.path().to_vec(),
                request.op(),
                request.context_kind(),
            ));
        fs::create_dir_all(&output_path_for_realizer)
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        fs::write(&data_path_for_realizer, b"hello")
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        fs::write(&import_path_for_realizer, b"41")
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        Ok(())
    });
    let source = format!(
        r#"let
                 ctx = {{ {drv} = {{ outputs = [ "out" ]; }}; }};
                 data = builtins.appendContext {data} ctx;
                 dir = builtins.appendContext {output} ctx;
                 imported = builtins.appendContext {imported} ctx;
               in builtins.readFile data == "hello"
                  && builtins.elem "data.txt" (builtins.attrNames (builtins.readDir dir))
                  && builtins.pathExists data
                  && builtins.readFileType data == "regular"
                  && builtins.readFile data == "hello"
                  && import imported == 41"#,
        drv = nix_string_literal(&path_source(&drv_path)),
        data = nix_string_literal(&path_source(&data_path)),
        output = nix_string_literal(&path_source(&output_path)),
        imported = nix_string_literal(&path_source(&import_path)),
    );
    let ir = lower(&source);
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.set_ifd_realizer(realizer);
    let value = evaluator
        .eval_root()
        .expect("IFD-backed filesystem reads evaluate");
    assert_eq!(value.as_bool().expect("result is bool"), true);

    let requests = requests.lock().expect("request log lock");
    assert!(requests.iter().any(|(_, op, _)| *op == "readFile"));
    assert!(requests.iter().any(|(_, op, _)| *op == "readDir"));
    assert!(requests.iter().any(|(_, op, _)| *op == "pathExists"));
    assert!(requests.iter().any(|(_, op, _)| *op == "readFileType"));
    assert!(requests.iter().any(|(_, op, _)| *op == "import"));
    assert_eq!(
        requests
            .iter()
            .filter(|(_, op, _)| *op == "readFile")
            .count(),
        2
    );
    assert!(
        requests
            .iter()
            .all(|(_, _, kind)| *kind == ContextKind::SingleOutput)
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn denied_ifd_path_does_not_call_realizer() {
    let root = fs::canonicalize(unique_temp_dir("ifd-denied")).expect("temp dir canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let file_path = output_path.join("data.txt");
    let source = format!(
        "builtins.readFile (builtins.appendContext {file} {{ {drv} = {{ outputs = [ \"out\" ]; }}; }})",
        file = nix_string_literal(&path_source(&file_path)),
        drv = nix_string_literal(&path_source(&drv_path)),
    );
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");
    options.set_eval_mode(EvalMode::Restricted);
    let calls = Arc::new(AtomicU64::new(0));
    let calls_for_realizer = Arc::clone(&calls);
    let realizer = IfdRealizer::new(move |_| {
        calls_for_realizer.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let ir = lower(&source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.set_ifd_realizer(realizer);

    let error = evaluator
        .eval_root()
        .expect_err("restricted mode rejects before IFD realization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied { .. }
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn mixed_opaque_and_derivation_context_rejects_before_ifd_realizer() {
    let root = fs::canonicalize(unique_temp_dir("ifd-mixed")).expect("temp dir canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let opaque_path = store.join("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-source");
    let file_path = output_path.join("data.txt");
    let source = format!(
        "builtins.readFile (builtins.appendContext {file} {{ {drv} = {{ outputs = [ \"out\" ]; }}; {opaque} = {{ path = true; }}; }})",
        file = nix_string_literal(&path_source(&file_path)),
        drv = nix_string_literal(&path_source(&drv_path)),
        opaque = nix_string_literal(&path_source(&opaque_path)),
    );
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");
    let calls = Arc::new(AtomicU64::new(0));
    let calls_for_realizer = Arc::clone(&calls);
    let realizer = IfdRealizer::new(move |_| {
        calls_for_realizer.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let ir = lower(&source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.set_ifd_realizer(realizer);

    let error = evaluator
        .eval_root()
        .expect_err("opaque context rejects before IFD realization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "readFile", .. }
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn scoped_import_ifd_error_reports_scoped_import_op() {
    let root = fs::canonicalize(unique_temp_dir("ifd-scoped")).expect("temp dir canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let import_path = output_path.join("imported.nix");
    let source = format!(
        "builtins.scopedImport {{ }} (builtins.appendContext {file} {{ {drv} = {{ outputs = [ \"out\" ]; }}; }})",
        file = nix_string_literal(&path_source(&import_path)),
        drv = nix_string_literal(&path_source(&drv_path)),
    );
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");

    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("scopedImport IFD requires a realizer");
    let TreeWalkErrorKind::UnsupportedImportFromDerivation { op, detail, .. } = error.kind() else {
        panic!("unexpected error kind: {error:?}");
    };
    assert_eq!(op, "scopedImport");
    assert_eq!(detail.path(), import_path.as_os_str().as_bytes());
    assert_eq!(detail.drv_path(), drv_path.as_os_str().as_bytes());
    assert_eq!(detail.output_name(), Some(b"out".as_slice()));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn import_evaluates_files_directories_and_escaping_values_in_one_heap() {
    let root =
        fs::canonicalize(unique_temp_dir("import-basic")).expect("temp directory canonicalizes");
    let subdir = root.join("sub");
    let dir_import = root.join("dir");
    let empty_dir = root.join("empty-dir");
    fs::create_dir(&subdir).expect("sub directory creates");
    fs::create_dir(&dir_import).expect("import directory creates");
    fs::create_dir(&empty_dir).expect("empty import directory creates");
    fs::write(subdir.join("dep.nix"), b"2").expect("dep writes");
    fs::write(subdir.join("inc.nix"), b"3").expect("inc writes");
    fs::write(subdir.join("data.txt"), b"data").expect("data writes");
    fs::write(subdir.join("rec.nix"), b"rec { x = 4; y = x; }").expect("rec writes");
    fs::write(
        subdir.join("child.nix"),
        br#"{
              a = 1;
              nested = import ./dep.nix;
              f = x: x + import ./inc.nix;
              formal = { a ? 1, b }: a + b;
              rel = ./data.txt;
            }"#,
    )
    .expect("child writes");
    fs::write(dir_import.join("default.nix"), b"5").expect("default writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");

    assert_eq!(
        eval_with_options("(import ./sub/child.nix).a", options.clone())
            .as_int()
            .expect("imported attr is int"),
        1
    );
    assert_eq!(
        eval_with_options("(import ./sub/child.nix).nested", options.clone())
            .as_int()
            .expect("imported nested value is int"),
        2
    );
    assert_eq!(
        eval_with_options("(import ./sub/child.nix).f 4", options.clone())
            .as_int()
            .expect("imported function result is int"),
        7
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.baseNameOf ((import ./sub/child.nix).rel)",
            options.clone(),
        ),
        b"data.txt"
    );
    assert_eq!(
        eval_with_options("(import ./sub/rec.nix).y == 4", options.clone())
            .as_bool()
            .expect("imported recursive attr equality is bool"),
        true
    );
    assert_eq!(
        eval_with_options(
            r#"let args = builtins.functionArgs (import ./sub/child.nix).formal;
                   in args.a && !(args.b)"#,
            options.clone(),
        )
        .as_bool()
        .expect("imported functionArgs result is bool"),
        true
    );
    let xml = eval_string_bytes_with_options(
        "builtins.toXML (import ./sub/child.nix).formal",
        options.clone(),
    );
    assert!(
        xml.windows(b"attrspat".len())
            .any(|window| window == b"attrspat"),
        "imported formal-set lambda XML includes attrspat"
    );
    let traced_path = eval_whnf_owned_with_options(
        &lower("builtins.trace (import ./sub/child.nix).rel 0"),
        options.clone(),
    )
    .expect("imported path trace evaluates");
    let expected_path = subdir.join("data.txt").as_os_str().as_bytes().to_vec();
    assert_eq!(traced_path.trace_output().len(), 1);
    assert_trace_output(
        traced_path
            .trace_output()
            .first()
            .expect("path trace output exists"),
        EvalTraceKind::Trace,
        &expected_path,
    );
    assert_eq!(
        eval_with_options("import ./dir", options.clone())
            .as_int()
            .expect("directory import is int"),
        5
    );
    let missing_default =
        eval_whnf_owned_with_options(&lower("import ./empty-dir"), options.clone())
            .expect_err("directory import without default.nix rejects");
    assert!(matches!(
        missing_default.kind(),
        TreeWalkErrorKind::FileRead { .. }
    ));
    let first_class =
        eval_whnf_owned_with_options(&lower("let f = import; in f ./sub/child.nix"), options)
            .expect("first-class import evaluates");
    assert_eq!(first_class.value().tag(), ValueTag::Attrs);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn import_uses_fresh_scope_and_shared_result_cache() {
    let root = fs::canonicalize(unique_temp_dir("import-scope-cache"))
        .expect("temp directory canonicalizes");
    fs::write(root.join("fresh.nix"), b"secret").expect("fresh writes");
    fs::write(root.join("traced.nix"), br#"builtins.trace "once" 9"#).expect("traced writes");
    std::os::unix::fs::symlink(root.join("traced.nix"), root.join("traced-link.nix"))
        .expect("trace symlink creates");
    let traced_dir = root.join("traced-dir");
    fs::create_dir(&traced_dir).expect("traced dir creates");
    fs::write(
        traced_dir.join("default.nix"),
        br#"builtins.trace "dir-once" 8"#,
    )
    .expect("traced default writes");
    fs::write(root.join("self.nix"), b"import ./self.nix").expect("self writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");

    let fresh_error = eval_whnf_owned_with_options(
        &lower("with { secret = 42; }; import ./fresh.nix"),
        options.clone(),
    )
    .expect_err("imported file does not inherit caller with-scope");
    assert!(matches!(
        fresh_error.kind(),
        TreeWalkErrorKind::ImportScope { .. } | TreeWalkErrorKind::UnresolvedWithVar { .. }
    ));
    let fresh_let_error = eval_whnf_owned_with_options(
        &lower("let secret = 42; in import ./fresh.nix"),
        options.clone(),
    )
    .expect_err("imported file does not inherit caller let-scope");
    assert!(matches!(
        fresh_let_error.kind(),
        TreeWalkErrorKind::ImportScope { .. } | TreeWalkErrorKind::UnresolvedWithVar { .. }
    ));

    let traced = eval_whnf_owned_with_options(
        &lower("builtins.deepSeq [ (import ./traced.nix) (import ./traced.nix) ] 0"),
        options.clone(),
    )
    .expect("cached imports evaluate");
    assert_eq!(traced.value().as_int().expect("trace result is int"), 0);
    assert_eq!(traced.trace_output().len(), 1);
    assert_trace_output(
        traced.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        b"once",
    );

    let symlinked = eval_whnf_owned_with_options(
        &lower("builtins.deepSeq [ (import ./traced.nix) (import ./traced-link.nix) ] 0"),
        options.clone(),
    )
    .expect("canonicalized imports share cache");
    assert_eq!(symlinked.value().as_int().expect("trace result is int"), 0);
    assert_eq!(symlinked.trace_output().len(), 1);
    assert_trace_output(
        symlinked
            .trace_output()
            .first()
            .expect("trace output exists"),
        EvalTraceKind::Trace,
        b"once",
    );

    let default_nix = eval_whnf_owned_with_options(
        &lower("builtins.deepSeq [ (import ./traced-dir) (import ./traced-dir/default.nix) ] 0"),
        options.clone(),
    )
    .expect("directory and default.nix imports share cache");
    assert_eq!(
        default_nix.value().as_int().expect("trace result is int"),
        0
    );
    assert_eq!(default_nix.trace_output().len(), 1);
    assert_trace_output(
        default_nix
            .trace_output()
            .first()
            .expect("trace output exists"),
        EvalTraceKind::Trace,
        b"dir-once",
    );

    let cycle = eval_whnf_owned_with_options(&lower("import ./self.nix"), options)
        .expect_err("recursive import is rejected");
    assert!(matches!(
        cycle.kind(),
        TreeWalkErrorKind::RecursiveImport { .. }
    ));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_uses_configured_parse_cache() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(root.join("dep.nix"), b"{ zOnly = 41; }").expect("dep writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    let ir = lower(r#"builtins.concatStringsSep "," (builtins.attrNames (import ./dep.nix))"#);

    let mut first = TreeWalk::with_options(&ir, options.clone());
    let value = first.eval_root().expect("first import evaluates");
    let string = first
        .heap()
        .get_string(value)
        .expect("attrNames result concatenates to string");
    assert_eq!(string.bytes(), b"zOnly");
    assert_eq!(first.import_parse_cache_stats(), (0, 1));
    assert!(
        fs::read_dir(&cache_root)
            .expect("cache directory exists")
            .next()
            .is_some(),
        "first import should write a durable parse-cache entry"
    );

    let mut second = TreeWalk::with_options(&ir, options);
    let value = second.eval_root().expect("second import evaluates");
    let string = second
        .heap()
        .get_string(value)
        .expect("cached attrNames result concatenates to string");
    assert_eq!(string.bytes(), b"zOnly");
    assert_eq!(second.import_parse_cache_stats(), (1, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cached_import_remaps_formal_and_inherit_symbols() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-symbols"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(
        root.join("dep.nix"),
        br#"let
                 hidden = 7;
                 f = args@{ a ? hidden, ... }: a;
               in { inherit hidden f; }"#,
    )
    .expect("dep writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    let ir = lower(
        r#"let imported = import ./dep.nix;
               in (builtins.getAttr "f" imported) {} + builtins.getAttr "hidden" imported"#,
    );

    let mut first = TreeWalk::with_options(&ir, options.clone());
    assert_eq!(
        first
            .eval_root()
            .expect("first import evaluates")
            .as_int()
            .expect("first result is int"),
        14
    );
    assert_eq!(first.import_parse_cache_stats(), (0, 1));

    let mut second = TreeWalk::with_options(&ir, options);
    assert_eq!(
        second
            .eval_root()
            .expect("cached import evaluates")
            .as_int()
            .expect("cached result is int"),
        14
    );
    assert_eq!(second.import_parse_cache_stats(), (1, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cached_import_remaps_lowered_builtin_symbols() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-builtins"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(
        root.join("dep.nix"),
        br#"let f = builtins.length; in builtins.add (f [ 1 2 3 ]) 4"#,
    )
    .expect("dep writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    let ir = lower("import ./dep.nix");

    let mut first = TreeWalk::with_options(&ir, options.clone());
    assert_eq!(
        first
            .eval_root()
            .expect("first import evaluates")
            .as_int()
            .expect("first result is int"),
        7
    );
    assert_eq!(first.import_parse_cache_stats(), (0, 1));

    let mut second = TreeWalk::with_options(&ir, options);
    assert_eq!(
        second
            .eval_root()
            .expect("cached import evaluates")
            .as_int()
            .expect("cached result is int"),
        7
    );
    assert_eq!(second.import_parse_cache_stats(), (1, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cached_import_remaps_with_var_symbols() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-with-var"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(root.join("dep.nix"), br#"with { x = 41; }; x + 1"#).expect("dep writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    let ir = lower("import ./dep.nix");

    let mut first = TreeWalk::with_options(&ir, options.clone());
    assert_eq!(
        first
            .eval_root()
            .expect("first import evaluates")
            .as_int()
            .expect("first result is int"),
        42
    );
    assert_eq!(first.import_parse_cache_stats(), (0, 1));

    let mut second = TreeWalk::with_options(&ir, options);
    assert_eq!(
        second
            .eval_root()
            .expect("cached import evaluates")
            .as_int()
            .expect("cached result is int"),
        42
    );
    assert_eq!(second.import_parse_cache_stats(), (1, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cached_imports_keep_module_relative_path_bases() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-bases"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir(&first_dir).expect("first dir creates");
    fs::create_dir(&second_dir).expect("second dir creates");
    fs::write(first_dir.join("dep.nix"), b"./data.txt").expect("first dep writes");
    fs::write(second_dir.join("dep.nix"), b"./data.txt").expect("second dep writes");
    fs::write(first_dir.join("data.txt"), b"first").expect("first data writes");
    fs::write(second_dir.join("data.txt"), b"second").expect("second data writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    let ir = lower(
        r#"builtins.toString (import ./first/dep.nix)
               + "|"
               + builtins.toString (import ./second/dep.nix)"#,
    );
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator.eval_root().expect("imports evaluate");
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("result is a string");
    let expected = format!(
        "{}|{}",
        first_dir.join("data.txt").display(),
        second_dir.join("data.txt").display()
    );
    assert_eq!(string.bytes(), expected.as_bytes());
    assert_eq!(evaluator.import_parse_cache_stats(), (1, 1));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cache_does_not_capture_scoped_or_text_store_imports() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-bypass"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(root.join("scoped.nix"), b"secret").expect("scoped import writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);

    let scoped_ir = lower("builtins.scopedImport { secret = 9; } ./scoped.nix");
    let mut scoped = TreeWalk::with_options(&scoped_ir, options.clone());
    assert_eq!(
        scoped
            .eval_root()
            .expect("scoped import evaluates")
            .as_int()
            .expect("scoped result is int"),
        9
    );
    assert_eq!(scoped.import_parse_cache_stats(), (0, 0));

    let text_store_ir = lower(r#"let p = builtins.toFile "generated.nix" "3"; in import p"#);
    let mut text_store = TreeWalk::with_options(&text_store_ir, options);
    assert_eq!(
        text_store
            .eval_root()
            .expect("text-store import evaluates")
            .as_int()
            .expect("text-store result is int"),
        3
    );
    assert_eq!(text_store.import_parse_cache_stats(), (0, 0));
    assert!(
        !cache_root.exists(),
        "bypassed imports should not create parse-cache artifacts"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn scoped_import_injects_globals_and_bypasses_result_cache() {
    let root =
        fs::canonicalize(unique_temp_dir("scoped-import")).expect("temp directory canonicalizes");
    let dir_import = root.join("dir");
    fs::create_dir(&dir_import).expect("import directory creates");
    fs::write(root.join("value.nix"), b"x").expect("value writes");
    fs::write(root.join("shadow-builtins.nix"), b"builtins.add 1 2")
        .expect("shadow builtins writes");
    fs::write(root.join("lambda.nix"), b"y: secret + y").expect("lambda writes");
    fs::write(root.join("shadow-import.nix"), b"import ./nested.nix")
        .expect("shadow import writes");
    fs::write(root.join("nested.nix"), b"secret").expect("nested writes");
    fs::write(root.join("true.nix"), b"true").expect("true writes");
    fs::write(root.join("false.nix"), b"false").expect("false writes");
    fs::write(root.join("null.nix"), b"null").expect("null writes");
    fs::write(root.join("trace.nix"), br#"builtins.trace "scoped" 1"#).expect("trace writes");
    fs::write(dir_import.join("default.nix"), b"x").expect("default writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");

    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { x = 7; } ./value.nix",
            options.clone()
        )
        .as_int()
        .expect("scoped global is int"),
        7
    );
    assert_eq!(
        eval_with_options("builtins.scopedImport { x = 8; } ./dir", options.clone())
            .as_int()
            .expect("scoped directory import is int"),
        8
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { builtins = { add = a: b: 10; }; } ./shadow-builtins.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped builtins shadow is int"),
        10
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { import = path: 42; } ./shadow-import.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped import shadow is int"),
        42
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { true = 1; false = 2; null = 3; } ./true.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped true shadow is int"),
        1
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { true = 1; false = 2; null = 3; } ./false.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped false shadow is int"),
        2
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { true = 1; false = 2; null = 3; } ./null.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped null shadow is int"),
        3
    );
    assert_eq!(
        eval_with_options(
            "(builtins.scopedImport { secret = 5; } ./lambda.nix) 2",
            options.clone(),
        )
        .as_int()
        .expect("escaped lambda sees scoped globals"),
        7
    );
    assert_eq!(
        eval_with_options(
            "let f = builtins.scopedImport { x = 11; }; in f ./value.nix",
            options.clone(),
        )
        .as_int()
        .expect("partially applied scopedImport evaluates"),
        11
    );

    let traced = eval_whnf_owned_with_options(
        &lower(
            "builtins.deepSeq [
                  (builtins.scopedImport {} ./trace.nix)
                  (builtins.scopedImport {} ./trace.nix)
                ] 0",
        ),
        options.clone(),
    )
    .expect("scoped imports evaluate");
    assert_eq!(traced.value().as_int().expect("trace result is int"), 0);
    assert_eq!(traced.trace_output().len(), 2);
    for trace in traced.trace_output() {
        assert_trace_output(trace, EvalTraceKind::Trace, b"scoped");
    }

    let plain_inner = eval_whnf_owned_with_options(
        &lower("builtins.scopedImport { secret = 9; } ./shadow-import.nix"),
        options,
    )
    .expect_err("plain import inside scopedImport does not inherit scoped globals");
    assert!(matches!(
        plain_inner.kind(),
        TreeWalkErrorKind::ImportScope { .. } | TreeWalkErrorKind::UnresolvedWithVar { .. }
    ));

    fs::remove_dir_all(root).expect("temp directory removes");
}

fn search_path_options(prefix: &[u8], path: &Path) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::new();
    options
        .add_nix_path_entry(prefix.to_vec(), path.as_os_str().as_bytes().to_vec())
        .expect("search path entry configures");
    options
}

fn relative_search_path_options(base: &Path, prefix: &[u8], path: &[u8]) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::with_search_path_base(base.as_os_str().as_bytes().to_vec())
        .expect("search-path base is absolute");
    options
        .add_nix_path_entry(prefix.to_vec(), path.to_vec())
        .expect("relative search path entry configures");
    options
}

fn search_path_fixture() -> (PathBuf, PathBuf, PathBuf) {
    let root = unique_temp_dir("find-file");
    let nixpkgs = root.join("nixpkgs");
    let subdir = nixpkgs.join("subdir");
    fs::create_dir_all(&subdir).expect("search path fixture creates");
    fs::write(nixpkgs.join("default.nix"), b"{ }").expect("default file writes");
    (root, nixpkgs, subdir)
}

fn resolved_search_path_entry(prefix: &[u8], path: &Path) -> ResolvedSearchPathEntry {
    ResolvedSearchPathEntry {
        prefix: prefix.to_vec(),
        path: path.as_os_str().as_bytes().to_vec(),
    }
}

fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn path_value_bytes(evaluator: &TreeWalk, value: Value) -> Vec<u8> {
    evaluator
        .heap()
        .get_path(value)
        .expect("value is a heap-owned path")
        .bytes()
        .to_vec()
}

fn assert_search_path_not_found(error: TreeWalkError, expected_lookup: &[u8]) {
    assert!(
        matches!(
            error.kind(),
            TreeWalkErrorKind::SearchPathNotFound { lookup, .. }
                if lookup == expected_lookup
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn nix_path_value_reflects_configured_search_path() {
    let (root, nixpkgs, _subdir) = search_path_fixture();
    let options = search_path_options(b"nixpkgs", &nixpkgs);

    let actual = eval_string_bytes_with_options("builtins.toJSON builtins.nixPath", options);
    let expected = format!(
        r#"[{{"path":{},"prefix":"nixpkgs"}}]"#,
        nix_string_literal(&path_source(&nixpkgs))
    );
    assert_eq!(actual, expected.into_bytes());

    let options = relative_search_path_options(&root, b"nixpkgs", b"nixpkgs/./");
    let actual = eval_string_bytes_with_options("builtins.toJSON builtins.nixPath", options);
    assert_eq!(
        actual,
        br#"[{"path":"nixpkgs/./","prefix":"nixpkgs"}]"#.to_vec()
    );
}

#[test]
fn find_file_and_search_path_return_path_values() {
    let (root, nixpkgs, subdir) = search_path_fixture();
    let prefixed = search_path_options(b"nixpkgs", &nixpkgs);
    let bare = search_path_options(b"", &root);
    let expected = path_source(&subdir);

    for (source, options) in [
        (
            r#"let p = builtins.findFile builtins.nixPath "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
            prefixed.clone(),
        ),
        (
            r#"let f = builtins.findFile; g = f builtins.nixPath; p = g "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
            prefixed.clone(),
        ),
        (
            r#"let p = <nixpkgs/subdir>; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
            prefixed,
        ),
        (
            r#"let p = builtins.findFile builtins.nixPath "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
            bare,
        ),
    ] {
        let actual = eval_json_bytes_with_options(source, options);
        let expected_json = format!(r#"["path",{}]"#, nix_string_literal(&expected));
        assert_eq!(
            actual,
            expected_json.into_bytes(),
            "source diverged: {source}"
        );
    }
}

#[test]
fn find_file_accepts_missing_prefix_and_relative_entries() {
    let (root, nixpkgs, subdir) = search_path_fixture();
    let expected = path_source(&subdir);

    for (source, options) in [
            (
                format!(
                    r#"let p = builtins.findFile [ {{ path = {}; }} ] "subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
                    nix_string_literal(&path_source(&nixpkgs))
                ),
                TreeWalkOptions::new(),
            ),
            (
                r#"let p = builtins.findFile [ { path = "nixpkgs"; prefix = "nixpkgs"; } ] "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#.to_owned(),
                TreeWalkOptions::with_search_path_base(root.as_os_str().as_bytes().to_vec())
                    .expect("search-path base is absolute"),
            ),
            (
                r#"let p = builtins.findFile [ { path = "nixpkgs"; } ] "subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#.to_owned(),
                TreeWalkOptions::with_search_path_base(root.as_os_str().as_bytes().to_vec())
                    .expect("search-path base is absolute"),
            ),
            (
                r#"let p = <nixpkgs/subdir>; in [ (builtins.typeOf p) (builtins.toString p) ]"#.to_owned(),
                relative_search_path_options(&root, b"nixpkgs", b"nixpkgs"),
            ),
        ] {
            let actual = eval_json_bytes_with_options(&source, options);
            let expected_json = format!(r#"["path",{}]"#, nix_string_literal(&expected));
            assert_eq!(
                actual,
                expected_json.into_bytes(),
                "source diverged: {source}"
            );
        }
}

#[test]
fn search_path_lookup_uses_configured_order_and_fallback() {
    let root = unique_temp_dir("search-path-order");
    let first = root.join("first");
    let second = root.join("second");
    let empty = root.join("empty");
    let first_subdir = first.join("subdir");
    let second_subdir = second.join("subdir");
    fs::create_dir_all(&first_subdir).expect("first search path hit creates");
    fs::create_dir_all(&second_subdir).expect("second search path hit creates");
    fs::create_dir(&empty).expect("empty search path entry creates");

    let mut ordered = TreeWalkOptions::new();
    ordered
        .add_nix_path_entry(b"nixpkgs".to_vec(), path_bytes(&first))
        .expect("first search-path entry configures");
    ordered
        .add_nix_path_entry(b"nixpkgs".to_vec(), path_bytes(&second))
        .expect("second search-path entry configures");
    assert_eq!(
        eval_string_bytes_with_options("builtins.toString <nixpkgs>", ordered.clone()),
        path_bytes(&first)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            r#"builtins.toString (builtins.findFile builtins.nixPath "nixpkgs")"#,
            ordered.clone()
        ),
        path_bytes(&first)
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.toString <nixpkgs/subdir>", ordered.clone()),
        path_bytes(&first_subdir)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            r#"builtins.toString (builtins.findFile builtins.nixPath "nixpkgs/subdir")"#,
            ordered
        ),
        path_bytes(&first_subdir)
    );

    let mut fallback = TreeWalkOptions::new();
    fallback
        .add_nix_path_entry(b"nixpkgs".to_vec(), path_bytes(&empty))
        .expect("empty search-path entry configures");
    fallback
        .add_nix_path_entry(b"nixpkgs".to_vec(), path_bytes(&second))
        .expect("fallback search-path entry configures");
    assert_eq!(
        eval_string_bytes_with_options("builtins.toString <nixpkgs>", fallback.clone()),
        path_bytes(&empty)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            r#"builtins.toString (builtins.findFile builtins.nixPath "nixpkgs")"#,
            fallback.clone()
        ),
        path_bytes(&empty)
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.toString <nixpkgs/subdir>", fallback.clone()),
        path_bytes(&second_subdir)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            r#"builtins.toString (builtins.findFile builtins.nixPath "nixpkgs/subdir")"#,
            fallback
        ),
        path_bytes(&second_subdir)
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn find_file_reports_exhausted_search_path() {
    let (_root, nixpkgs, _subdir) = search_path_fixture();
    let options = search_path_options(b"nixpkgs", &nixpkgs);
    let ir = lower(r#"builtins.findFile builtins.nixPath "nixpkgs/missing""#);
    let error = eval_whnf_owned_with_options(&ir, options)
        .expect_err("missing search-path lookup is rejected");

    assert_search_path_not_found(error, b"nixpkgs/missing");
}

#[test]
fn pure_eval_hides_configured_search_path_from_nix_path_and_angle_lookup() {
    let (_root, nixpkgs, subdir) = search_path_fixture();
    let mut hidden_options = search_path_options(b"nixpkgs", &nixpkgs);
    hidden_options
        .add_allowed_path(path_bytes(&nixpkgs))
        .expect("search path configures as allowed");
    hidden_options.set_eval_mode(EvalMode::Pure);

    assert_eq!(
        eval_string_bytes_with_options("builtins.toJSON builtins.nixPath", hidden_options.clone()),
        b"[]".to_vec()
    );

    let search_path = lower(r#"<nixpkgs/subdir>"#);
    let error = eval_whnf_owned_with_options(&search_path, hidden_options)
        .expect_err("pure eval hides configured angle-bracket search paths");
    assert_search_path_not_found(error, b"nixpkgs/subdir");

    let explicit_options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
    let explicit = format!(
        r#"builtins.toString (builtins.findFile [ {{ path = {}; prefix = "nixpkgs"; }} ] "nixpkgs/subdir")"#,
        nix_string_literal(&path_source(&nixpkgs))
    );
    assert_eq!(
        eval_string_bytes_with_options(&explicit, explicit_options.clone()),
        path_bytes(&subdir)
    );

    let default_nix = nixpkgs.join("default.nix");
    let default_nix_bytes = path_bytes(&default_nix);
    let read = format!(
        r#"builtins.readFile (builtins.findFile [ {{ path = {}; prefix = "nixpkgs"; }} ] "nixpkgs/default.nix")"#,
        nix_string_literal(&path_source(&nixpkgs))
    );
    let error = eval_whnf_owned_with_options(&lower(&read), explicit_options)
        .expect_err("pure eval still denies later filesystem reads");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied { path, mode: EvalMode::Pure, .. }
            if path.as_slice() == default_nix_bytes.as_slice()
    ));
}

#[test]
fn find_file_caches_successful_lookup_results() {
    let (_root, nixpkgs, subdir) = search_path_fixture();
    let ir = lower("0");
    let mut evaluator = TreeWalk::new(&ir);
    let entries = vec![resolved_search_path_entry(b"nixpkgs", &nixpkgs)];
    let lookup = b"nixpkgs/subdir";
    let span = Span::new(0, 0);

    let first = evaluator
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect("initial search-path lookup finds existing directory");
    assert_eq!(path_value_bytes(&evaluator, first), path_bytes(&subdir));

    fs::remove_dir(&subdir).expect("fixture subdir removes");

    let cached = evaluator
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect("cached search-path hit survives filesystem mutation");
    assert_eq!(path_value_bytes(&evaluator, cached), path_bytes(&subdir));

    let mut fresh = TreeWalk::new(&ir);
    let error = fresh
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect_err("fresh evaluator observes removed directory");
    assert_search_path_not_found(error, lookup);
}

#[test]
fn find_file_caches_exhausted_lookup_results() {
    let (_root, nixpkgs, _subdir) = search_path_fixture();
    let ir = lower("0");
    let mut evaluator = TreeWalk::new(&ir);
    let entries = vec![resolved_search_path_entry(b"nixpkgs", &nixpkgs)];
    let lookup = b"nixpkgs/later";
    let later = nixpkgs.join("later");
    let span = Span::new(0, 0);

    let first = evaluator
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect_err("initial missing search-path lookup is rejected");
    assert_search_path_not_found(first, lookup);

    fs::create_dir(&later).expect("late fixture directory creates");

    let cached = evaluator
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect_err("cached search-path miss survives filesystem mutation");
    assert_search_path_not_found(cached, lookup);

    let mut fresh = TreeWalk::new(&ir);
    let found = fresh
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect("fresh evaluator observes late directory");
    assert_eq!(path_value_bytes(&fresh, found), path_bytes(&later));
}

fn assert_cpp_nix_find_file_and_search_path_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    let (root, nixpkgs, subdir) = search_path_fixture();
    let nixpkgs_source = nix_string_literal(&path_source(&nixpkgs));
    let root_source = nix_string_literal(&path_source(&root));
    let expected = path_source(&subdir);

    for source in [
        format!(
            r#"let p = builtins.findFile [ {{ path = {nixpkgs_source}; prefix = "nixpkgs"; }} ] "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#
        ),
        format!(
            r#"let p = builtins.findFile [ {{ path = {nixpkgs_source}; }} ] "subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#
        ),
        format!(
            r#"let p = builtins.findFile [ {{ path = {root_source}; prefix = ""; }} ] "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#
        ),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    let nix_path = format!("nixpkgs={}", path_source(&nixpkgs));
    let options = search_path_options(b"nixpkgs", &nixpkgs);
    for source in [
        r#"builtins.head builtins.nixPath"#,
        r#"let p = builtins.findFile builtins.nixPath "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
        r#"let p = <nixpkgs/subdir>; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk_with_options_and_env(
            oracle,
            source,
            options.clone(),
            &[("NIX_PATH", &nix_path)],
        );
    }

    let actual = eval_string_bytes_with_options(
        r#"builtins.toString <nixpkgs/subdir>"#,
        search_path_options(b"nixpkgs", &nixpkgs),
    );
    assert_eq!(actual, expected.into_bytes());
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_find_file_and_search_path_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_find_file_and_search_path_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_find_file_and_search_path_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix findFile check");
        return;
    };
    assert_cpp_nix_find_file_and_search_path_match_tree_walk(&oracle);
}

fn assert_cpp_nix_json_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.fromJSON ''{"b":1,"a":[true,false,null,"x"],"c":{"n":2.5}}''"#,
        r#"builtins.attrNames (builtins.fromJSON ''{"b":1,"a":2}'')"#,
        r#"(builtins.fromJSON ''{"a":1,"a":2}'').a"#,
        r#"builtins.fromJSON ''"é"''"#,
        r#"builtins.fromJSON "9223372036854775808""#,
        r#"builtins.fromJSON "18446744073709551615""#,
        r#"builtins.typeOf (builtins.fromJSON "-9223372036854775809")"#,
        r#"builtins.hasContext (builtins.fromJSON ''"x"'')"#,
        r#"let f = builtins.fromJSON; in f "{}""#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }

    for source in [
        "null",
        "true",
        "false",
        "42",
        r#""é""#,
        r#""\t\r\n\\\"""#,
        r#"builtins.fromJSON "\"\\b\"""#,
        r#"builtins.fromJSON "\"\\f\"""#,
        r#"builtins.fromJSON "\"\\u0001\"""#,
        r#"builtins.fromJSON "\"\\u001f\"""#,
        r#"{ b = 1; a = [ true false null "x" ]; }"#,
        r#"{ "10" = 10; "2" = 2; A = 1; a = 2; }"#,
        "1.0",
        "1.50",
        "(-0.0)",
        "0.000001",
        "100000000000000000000.0",
        "((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))",
        "(1.0e308 * 1.0e308)",
        r#"{ __toString = self: "hook"; outPath = "out"; }"#,
        r#"{ __toString = self: { outPath = "nested"; }; }"#,
        r#"{ outPath = [ "a" "b" ]; }"#,
        r#"{ outPath = "out"; a = 1; }"#,
        "{}",
    ] {
        assert_cpp_nix_to_json_matches_tree_walk(&oracle, source);
    }

    for source in [
        r#"builtins.fromJSON "01""#,
        "builtins.fromJSON 1",
        "builtins.toJSON [ (x: x) ]",
        "builtins.toJSON [ 1 (1 / 0) ]",
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(&oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_json_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_json_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_json_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix JSON check");
        return;
    };
    assert_cpp_nix_json_builtins_match_tree_walk(&oracle);
}

fn assert_cpp_nix_xml_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"{ a = 1; b = [ true false null "x<y&\"z" ]; }"#,
        r#""a
<&>\"b""#,
        r#"[ 1.25 (-0.0) 0.000001 1000000.0 100000000000000000000.0 1.23456789 1234567.0 ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) (1.0e308 * 1.0e308) (builtins.sub 0.0 (1.0e308 * 1.0e308)) ]"#,
        "x: x",
        "{ a, b ? 1, ... }: a",
        "args@{ a, ... }: a",
        "builtins.length",
        r#"{ type = "derivation"; drvPath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv"; outPath = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x"; name = "x"; }"#,
        r#"{ type = "derivation"; drvPath = 1; outPath = 2; }"#,
        r#"[
                (builtins.appendContext "direct" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-direct" = { path = true; };
                })
            ]"#,
    ] {
        assert_cpp_nix_to_xml_matches_tree_walk(oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_xml_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_xml_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_xml_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix XML check");
        return;
    };
    assert_cpp_nix_xml_builtins_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_from_toml_builtin_matches_tree_walk() {
    let oracle = cpp_nix_oracle();
    let version = cpp_nix_version(&oracle);
    assert!(
        version.contains("(Nix) 2.24."),
        "expected a C++ Nix 2.24.x oracle, got {version}"
    );
    eprintln!("C++ Nix oracle: {version}");

    for source in [
        r#"builtins.fromTOML """#,
        r#"builtins.fromTOML ''
                a = 1
                b = 1.5
                c = true
                d = "x"
                e = [1, "x", true, [2]]

                [owner]
                name = "Tom"
            ''"#,
        r#"builtins.fromTOML ''
                [[fruit]]
                name = "apple"
                [[fruit]]
                name = "banana"
            ''"#,
        r#"builtins.fromTOML ''
                positive = 9223372036854775808
                negative = -9223372036854775809
                hex = 0x8000000000000000
                octal = 0o1000000000000000000000
                binary_min = 0b1000000000000000000000000000000000000000000000000000000000000000
                binary_minus_one = 0b1111111111111111111111111111111111111111111111111111111111111111
                binary_wrapped = 0b10000000000000000000000000000000000000000000000000000000000000000
            ''"#,
        r#"builtins.fromTOML ''
                [9223372036854775808]
                value = "key"
            ''"#,
        r#"builtins.fromTOML ''
                "a.b" = 1
                a.b = 2
            ''"#,
        r#"builtins.fromTOML ''
                pos_inf = inf
                neg_inf = -inf
                nan = nan
            ''"#,
        r#"builtins.fromTOML ''
                positive = 1e999
                positive_signed = +1e999
                negative = -1e999
                fraction = 1.0e999
            ''"#,
        r#"let f = builtins.fromTOML; in f "a = 1""#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }

    for source in [
        r#"builtins.fromTOML "a = null""#,
        r#"builtins.fromTOML "a = 1979-05-27T07:32:00Z""#,
        r#"builtins.fromTOML "a = 1979-05-27""#,
        r#"builtins.fromTOML "a = 07:32:00""#,
        r#"builtins.fromTOML "a = 09223372036854775808""#,
        r#"builtins.fromTOML "a = -09223372036854775809""#,
        r#"builtins.fromTOML "a = 0_9223372036854775808""#,
        r#"builtins.fromTOML "a = +0x8000000000000000""#,
        r#"builtins.fromTOML "a = 01e999""#,
        r#"builtins.fromTOML "a = 1_e999""#,
        r#"builtins.fromTOML "a = +01e999""#,
        "builtins.fromTOML \"a = 1\na = 2\"",
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(&oracle, source);
    }
}

fn assert_cpp_nix_hash_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.hashString "md5" "abc""#,
        r#"builtins.hashString "sha1" "abc""#,
        r#"builtins.hashString "sha256" "abc""#,
        r#"builtins.hashString "sha512" "abc""#,
        r#"let h = builtins.hashString "sha256"; in h "abc""#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "base64"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "nix32"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "base32"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = "sha256"; toHashFormat = "sri"; }"#,
        r#"builtins.convertHash { hash = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"; hashAlgo = "sha256"; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = "sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"; toHashFormat = "base16"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "md5" "abc"; hashAlgo = "md5"; toHashFormat = "nix32"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha1" "abc"; hashAlgo = "sha1"; toHashFormat = "base64"; }"#,
        r#"builtins.convertHash { hash = builtins.hashString "sha512" "abc"; hashAlgo = "sha512"; toHashFormat = "nix32"; }"#,
        r#"let convert = builtins.convertHash; in convert { hash = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="; hashAlgo = "sha256"; toHashFormat = "base16"; }"#,
        r#"builtins.placeholder "out""#,
        r#"builtins.placeholder "dev""#,
        r#"let placeholder = builtins.placeholder; in placeholder "out""#,
        r#"builtins.stringLength (builtins.placeholder "out")"#,
        r#"let p = builtins.toFile "foo" "bar"; in { path = p; ctx = builtins.getContext p; }"#,
        r#"let p = builtins.toFile "foo" "bar"; nested = builtins.toFile "baz" p; in { nested = nested; nestedCtx = builtins.getContext nested; }"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    let (dir, path) = temp_file_with_bytes("cpp-nix-hash-file", b"abc");
    let path = path_source(&path);
    for source in [
        format!(r#"builtins.hashFile "md5" {path}"#),
        format!(r#"builtins.hashFile "sha1" {path}"#),
        format!(r#"builtins.hashFile "sha256" {path}"#),
        format!(
            r#"builtins.hashFile "sha512" {}"#,
            nix_string_literal(&path)
        ),
        format!(
            r#"builtins.hashFile "sha256" {{ outPath = {}; }}"#,
            nix_string_literal(&path)
        ),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    let recursive_digest = "11a71b4754d812f4aea20161c533bdaa112ac5c853013e65d3aa9640b5735230";
    let flat_digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let file_url = nix_string_literal(&format!("file://{path}"));
    for source in [
        format!("builtins.path {{ path = {path}; }}"),
        format!("builtins.path {{ path = {}; }}", nix_string_literal(&path)),
        format!("builtins.path {{ path = {path}; name = \"renamed\"; }}"),
        format!("let p = builtins.path; in p {{ path = {path}; name = \"renamed\"; }}"),
        format!("builtins.path {{ path = {path}; recursive = false; }}"),
        format!("builtins.path {{ path = {path}; sha256 = \"{recursive_digest}\"; }}"),
        format!(
            "builtins.path {{ path = {path}; recursive = false; sha256 = \"{flat_digest}\"; }}"
        ),
        format!(
            "builtins.path {{ path = {path}; recursive = false; filter = path: type: builtins.throw \"called\"; }}"
        ),
        format!("builtins.fetchurl {file_url}"),
        format!("builtins.fetchurl {{ url = {file_url}; sha256 = \"{flat_digest}\"; }}"),
        format!(
            "let fetchurl = builtins.fetchurl; in fetchurl {{ url = {file_url}; sha256 = \"{flat_digest}\"; name = \"renamed\"; }}"
        ),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("oracle tree directory creates");
    fs::write(tree.join("a"), b"one").expect("oracle included file writes");
    fs::write(tree.join("b"), b"two").expect("oracle excluded file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.hasContext path == false && builtins.baseNameOf path == "a""#;
    for source in [
        format!("builtins.filterSource ({keep}) {tree}"),
        format!("builtins.path {{ path = {tree}; filter = ({keep}); }}"),
        format!("let filterSource = builtins.filterSource; in filterSource ({keep}) {tree}"),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }
    fs::remove_dir_all(dir).expect("temp directory removes");

    for source in [
        r#"builtins.hashString "sha384" "abc""#,
        r#"builtins.convertHash { hash = builtins.hashString "sha256" "abc"; hashAlgo = null; toHashFormat = "base16"; }"#,
        r#"builtins.placeholder 1"#,
        r#"builtins.placeholder (builtins.appendContext "out" { "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; }; })"#,
        r#"builtins.toFile "bad/name" "x""#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_json(oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_hash_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_hash_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_hash_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix hash check");
        return;
    };
    assert_cpp_nix_hash_builtins_match_tree_walk(&oracle);
}

fn assert_cpp_nix_flake_ref_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.parseFlakeRef "github:NixOS/nixpkgs?%64ir=lib""#,
        r#"builtins.parseFlakeRef "file+https://example.com/blob.txt?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D""#,
        r#"builtins.parseFlakeRef "https://example.com/source.tar.gz?revCount=bad&lastModified=nope&foo=bar""#,
        r#"builtins.flakeRefToString {
                narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
                owner = "NixOS";
                repo = "nixpkgs";
                rev = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                type = "github";
            }"#,
        r#"builtins.flakeRefToString {
                rev = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                type = "git";
                url = "https://example.com/repo";
            }"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        r#"builtins.flakeRefToString {
                type = "git";
                url = "https://example.com/repo";
                rev = "bad";
            }"#,
        r#"builtins.flakeRefToString {
                type = "tarball";
                url = "https://example.com/source.tar.gz";
                narHash = "not-a-hash";
            }"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_json(oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_flake_ref_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_flake_ref_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_flake_ref_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix flake-ref check");
        return;
    };
    assert_cpp_nix_flake_ref_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_restricted_unresolved_forge_fetch_tree_access_matches_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix fetchTree access check");
        return;
    };
    assert_pinned_cpp_nix_oracle(&oracle);

    for (source, expected_uri) in [
        (
            r#"builtins.fetchTree "github:NixOS/nixpkgs/main""#,
            "github:NixOS/nixpkgs/main",
        ),
        (
            r#"builtins.fetchTree "github:NixOS/nixpkgs/main?dir=lib""#,
            "github:NixOS/nixpkgs/main",
        ),
        (
            r#"builtins.fetchTree "github:NixOS/nixpkgs/main?dir=lib&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D""#,
            "github:NixOS/nixpkgs/main?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D",
        ),
        (
            r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = ""; }"#,
            "github:NixOS/nixpkgs/",
        ),
        (
            r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "bad?ref"; }"#,
            "github:NixOS/nixpkgs/bad%3Fref",
        ),
        (
            r#"builtins.fetchTree { type = "github"; owner = ""; repo = "nixpkgs"; }"#,
            "github:/nixpkgs",
        ),
        (
            r#"builtins.fetchTree { type = "gitlab"; owner = "group"; repo = "project/private"; }"#,
            "gitlab:group/project/private",
        ),
        (
            r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; host = "bad host"; }"#,
            "github:NixOS/nixpkgs",
        ),
    ] {
        let stderr = cpp_nix_eval_failure_stderr_with_nix_options(
            &oracle,
            source,
            &[
                (
                    "experimental-features",
                    PINNED_BUILTIN_SURFACE_EXPERIMENTAL_FEATURES,
                ),
                ("restrict-eval", "true"),
                ("allowed-uris", ""),
            ],
        );
        assert!(
            String::from_utf8_lossy(&stderr)
                .contains(&format!("access to URI '{expected_uri}' is forbidden")),
            "{}",
            String::from_utf8_lossy(&stderr)
        );

        let error = eval_whnf_owned_with_options(
            &lower(source),
            TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
        )
        .expect_err("restricted unresolved forge fetchTree denies the canonical URI");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::FetchTreeAccessDenied {
                input,
                mode: EvalMode::Restricted,
                ..
            } if input == expected_uri.as_bytes()
        ));
    }
}

#[test]
fn parse_flake_ref_parses_github_example() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.toJSON (builtins.parseFlakeRef "github:NixOS/nixpkgs/23.05?dir=lib")"#
        ),
        br#"{"dir":"lib","owner":"NixOS","ref":"23.05","repo":"nixpkgs","type":"github"}"#,
    );
}

#[test]
fn parse_flake_ref_supports_first_class_indirect_refs() {
    assert_eq!(
        eval_string_bytes(
            r#"let parse = builtins.parseFlakeRef; in builtins.toJSON (parse "nixpkgs/unstable")"#
        ),
        br#"{"id":"nixpkgs","ref":"unstable","type":"indirect"}"#,
    );
}

#[test]
fn parse_flake_ref_preserves_git_url_dir_query() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.toJSON (builtins.parseFlakeRef "git+https://example.com/repo.git?ref=main&dir=lib")"#
        ),
        br#"{"dir":"lib","ref":"main","type":"git","url":"https://example.com/repo.git?dir=lib"}"#,
    );
}

#[test]
fn parse_flake_ref_decodes_query_values_but_not_names() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.toJSON (builtins.parseFlakeRef "github:NixOS/nixpkgs?%64ir=lib")"#
        ),
        br#"{"owner":"NixOS","repo":"nixpkgs","type":"github"}"#,
    );
}

#[test]
fn parse_flake_ref_supports_file_curl_refs() {
    assert_eq!(
            eval_string_bytes(
                r#"builtins.toJSON (builtins.parseFlakeRef "file+https://example.com/blob.txt?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D")"#
            ),
            br#"{"narHash":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","type":"file","url":"https://example.com/blob.txt"}"#,
        );
}

#[test]
fn parse_flake_ref_drops_invalid_curl_numeric_metadata() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.toJSON (builtins.parseFlakeRef "https://example.com/source.tar.gz?revCount=bad&lastModified=nope&foo=bar")"#
        ),
        br#"{"type":"tarball","url":"https://example.com/source.tar.gz?foo=bar"}"#,
    );
}

#[test]
fn flake_ref_to_string_renders_github_example() {
    assert_eq!(
        eval_string_bytes(
            r#"let render = builtins.flakeRefToString; in render {
                    dir = "lib";
                    owner = "NixOS";
                    ref = "23.05";
                    repo = "nixpkgs";
                    type = "github";
                }"#
        ),
        b"github:NixOS/nixpkgs/23.05?dir=lib",
    );
}

#[test]
fn flake_ref_to_string_canonicalizes_hash_attrs() {
    assert_eq!(
            eval_string_bytes(
                r#"builtins.flakeRefToString {
                    narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
                    owner = "NixOS";
                    repo = "nixpkgs";
                    rev = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                    type = "github";
                }"#
            ),
            b"github:NixOS/nixpkgs/0000000000000000000000000000000000000000?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D",
        );

    assert_eq!(
        eval_string_bytes(
            r#"builtins.flakeRefToString {
                    rev = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
        ),
        b"git+https://example.com/repo?rev=0000000000000000000000000000000000000000",
    );
}

#[test]
fn flake_ref_to_string_renders_git_public_keys_like_cpp_nix() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.flakeRefToString {
                    publicKey = "abc";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
        ),
        b"git+https://example.com/repo?keytype=ssh-ed25519&publicKey=abc",
    );

    assert_eq!(
        eval_string_bytes(
            r#"builtins.flakeRefToString {
                    publicKeys = "[{\"key\":\"abc\",\"type\":\"ssh-ed25519\"}]";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
        ),
        b"git+https://example.com/repo?keytype=ssh-ed25519&publicKey=abc",
    );

    assert_eq!(
            eval_string_bytes(
                r#"builtins.flakeRefToString {
                    publicKey = "def";
                    publicKeys = "[{\"key\":\"abc\",\"type\":\"ssh-ed25519\"}]";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
            ),
            b"git+https://example.com/repo?publicKeys=%5B%7B%22key%22:%22abc%22%2C%22type%22:%22ssh-ed25519%22%7D%2C%7B%22key%22:%22def%22%2C%22type%22:%22ssh-ed25519%22%7D%5D",
        );

    assert_eq!(
        eval_string_bytes(
            r#"builtins.flakeRefToString {
                    publicKey = "abc";
                    publicKeys = "[]";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
        ),
        b"git+https://example.com/repo?keytype=ssh-ed25519&publicKey=abc",
    );
}

#[test]
fn flake_ref_to_string_renders_path_query_attrs() {
    assert_eq!(
            eval_string_bytes(
                r#"builtins.flakeRefToString {
                    type = "path";
                    path = "/tmp/source";
                    revCount = 5;
                    lastModified = 7;
                    rev = "abcdef";
                    narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                }"#
            ),
            b"path:/tmp/source?lastModified=7&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&rev=abcdef&revCount=5",
        );
}

#[test]
fn flake_ref_to_string_inserts_dir_without_overwriting_url_dir() {
    assert_eq!(
            eval_string_bytes(
                r#"builtins.flakeRefToString {
                    dir = "other";
                    narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                    type = "tarball";
                    url = "https://example.com/source.tar.gz?dir=lib";
                }"#
            ),
            b"https://example.com/source.tar.gz?dir=lib&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D",
        );
}

#[test]
fn flake_ref_to_string_rejects_unsupported_attrs_and_value_types() {
    let unsupported = eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "github";
                owner = "NixOS";
                repo = "nixpkgs";
                bogus = "x";
            }"#,
    ))
    .expect_err("unsupported flake-ref attrs are rejected");
    assert!(matches!(
        unsupported.kind(),
        TreeWalkErrorKind::UnsupportedFlakeRefAttr { attr, .. } if attr.as_slice() == b"bogus"
    ));

    let bad_type = eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "github";
                owner = null;
                repo = "nixpkgs";
            }"#,
    ))
    .expect_err("flake-ref attrs accept only strings, ints, and bools");
    assert!(matches!(
        bad_type.kind(),
        TreeWalkErrorKind::FlakeRefAttrType { attr, actual: ValueTag::Null, .. }
            if attr.as_slice() == b"owner"
    ));

    let thunk = eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "path";
                path = "/tmp/source";
                revCount = 1 + 1;
            }"#,
    ))
    .expect_err("computed flake-ref attrs are not forced");
    assert!(matches!(
        thunk.kind(),
        TreeWalkErrorKind::FlakeRefAttrType { attr, actual: ValueTag::Thunk, .. }
            if attr.as_slice() == b"revCount"
    ));

    eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "git";
                url = "https://example.com/repo";
                rev = "bad";
            }"#,
    ))
    .expect_err("invalid rendered git rev is rejected");

    eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "tarball";
                url = "https://example.com/source.tar.gz";
                narHash = "not-a-hash";
            }"#,
    ))
    .expect_err("invalid rendered narHash is rejected");

    eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "git";
                url = "https://example.com/repo";
                publicKeys = "not-json";
            }"#,
    ))
    .expect_err("invalid rendered publicKeys JSON is rejected");
}

#[test]
fn present_unimplemented_builtin_stubs_select_as_lambdas() {
    for name in PRESENT_UNIMPLEMENTED_BUILTIN_STUBS {
        let selected = format!("builtins.{name} or 42");

        assert_eq!(
            eval_string_bytes(&format!("builtins.typeOf ({selected})")),
            b"lambda",
            "{name} should select the builtin stub, not the default",
        );
        assert_eq!(
            eval_list_string_bytes(&format!(
                "builtins.attrNames (builtins.functionArgs ({selected}))"
            )),
            Vec::<Vec<u8>>::new(),
            "{name} should expose primop-style empty functionArgs",
        );
    }
}

#[test]
fn present_unimplemented_builtin_stubs_error_when_called() {
    for (source, name) in [(
        r#"builtins.fetchMercurial "https://example.invalid/repo""#,
        b"fetchMercurial".as_slice(),
    )] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("unimplemented builtin stub errors");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedPrimOp {
                id: ir.root,
                symbol: symbol_for(&ir, name),
            }
        );
    }
}

#[test]
fn get_flake_preflights_argument_before_fetching() {
    let error =
        eval_whnf_owned(&lower("builtins.getFlake 1")).expect_err("getFlake requires string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"let get = builtins.getFlake; in get (builtins.throw "flake")"#,
    ))
    .expect_err("first-class getFlake forces its argument");
    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));

    let error = eval_whnf_owned(&lower(
        r#"builtins.getFlake (builtins.toFile "flake-ref" "nixpkgs")"#,
    ))
    .expect_err("getFlake rejects context-bearing strings");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "getFlake", .. }
    ));

    let error = eval_whnf_owned(&lower(r#"builtins.getFlake "unknown+scheme://example""#))
        .expect_err("getFlake validates flake-reference syntax");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FlakeRef { .. }));

    let error = eval_whnf_owned(&lower(r#"let get = builtins.getFlake; in get "nixpkgs""#))
        .expect_err("indirect getFlake refs are not resolved yet");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTree { message, .. }
            if message == "unsupported fetchTree string flake reference type"
    ));
}

#[test]
fn get_flake_evaluates_local_inputless_flakes() {
    let root = unique_temp_dir("get-flake-local");
    fs::write(
        root.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 42;
                foo = "foo";
                fromSelfFoo = self.foo;
                fromSelfOutPath = self.outPath;
                narHash = "output-nar-hash";
                nested.value = "ok";
                outPath = "output-out-path";
                sourceInfo = "output-source-info";
              };
            }
            "#,
    )
    .expect("flake.nix writes");
    let store_dir = unique_temp_dir("get-flake-local-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let flake_ref = nix_string_literal(&path_source(&root));

    let source = format!(
        r#"
                let f = builtins.getFlake {flake_ref};
                in {{
                  answer = f.answer;
                  flakeType = f._type;
                  fromSelfFoo = f.fromSelfFoo;
                  inputs = builtins.attrNames f.inputs;
                  nested = f.nested.value;
                  outputNarHash = f.outputs.narHash;
                  outputNames = builtins.attrNames f.outputs;
                  outputOutPath = f.outputs.outPath;
                  outputSourceInfo = f.outputs.sourceInfo;
                  topNames = builtins.attrNames f;
                  flakeOutPath = f.outPath;
                  flakeNarHash = f.narHash;
                  selfOutPath = f.fromSelfOutPath;
                  sourceOutPath = f.sourceInfo.outPath;
                }}
                "#
    );
    let json = eval_json_bytes_with_options(&source, options);
    let value: serde_json::Value = serde_json::from_slice(&json).expect("flake JSON parses");

    assert_eq!(value["answer"], 42);
    assert_eq!(value["flakeType"], "flake");
    assert_eq!(value["fromSelfFoo"], "foo");
    assert_eq!(value["inputs"], serde_json::json!([]));
    assert_eq!(value["nested"], "ok");
    assert_eq!(value["outputNarHash"], "output-nar-hash");
    assert_eq!(value["outputOutPath"], "output-out-path");
    assert_eq!(value["outputSourceInfo"], "output-source-info");
    assert_eq!(
        value["outputNames"],
        serde_json::json!([
            "answer",
            "foo",
            "fromSelfFoo",
            "fromSelfOutPath",
            "narHash",
            "nested",
            "outPath",
            "sourceInfo"
        ])
    );
    assert_eq!(
        value["topNames"],
        serde_json::json!([
            "_type",
            "answer",
            "foo",
            "fromSelfFoo",
            "fromSelfOutPath",
            "inputs",
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "nested",
            "outPath",
            "outputs",
            "sourceInfo"
        ])
    );
    let out_path = value["flakeOutPath"]
        .as_str()
        .expect("flakeOutPath is a string");
    assert!(out_path.starts_with(path_source(&store_dir).as_str()));
    assert_eq!(value["selfOutPath"], out_path);
    assert_eq!(value["sourceOutPath"], out_path);
    assert!(
        value["flakeNarHash"]
            .as_str()
            .expect("flakeNarHash is a string")
            .starts_with("sha256-")
    );

    fs::remove_dir_all(root).expect("flake temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn get_flake_obeys_fetch_tree_locking_and_rejects_declared_inputs() {
    let root = unique_temp_dir("get-flake-locked");
    fs::write(
        root.join("flake.nix"),
        br#"
            {
              inputs.nixpkgs.url = "github:NixOS/nixpkgs";
              outputs = { self }: { answer = 42; };
            }
            "#,
    )
    .expect("flake.nix writes");
    let store_dir = unique_temp_dir("get-flake-locked-store");
    let flake_ref = nix_string_literal(&format!("path:{}", path_source(&root)));
    let pure_error = eval_whnf_owned_with_options(
        &lower(&format!("builtins.getFlake {flake_ref}")),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure getFlake path refs require a narHash");
    assert!(matches!(
        pure_error.kind(),
        TreeWalkErrorKind::FetchTreeLockedInputRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    let input_error = eval_whnf_owned_with_options(
        &lower(&format!(
            "builtins.attrNames (builtins.getFlake {flake_ref}).inputs"
        )),
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures"),
    )
    .expect_err("declared inputs are not resolved yet");
    assert!(matches!(
        input_error.kind(),
        TreeWalkErrorKind::Thrown { .. }
    ));

    fs::remove_dir_all(root).expect("flake temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_mercurial_stub_preflights_default_mode_arguments() {
    let error = eval_whnf_owned(&lower("builtins.fetchMercurial null"))
        .expect_err("fetchMercurial rejects invalid argument type before fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "set or string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            r#"let fetch = builtins.fetchMercurial; in fetch { url = "https://example.invalid/repo"; bogus = 1; }"#,
        ))
        .expect_err("first-class fetchMercurial rejects unsupported attrs before fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchMercurialAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; name = null; }"#,
    ))
    .expect_err("fetchMercurial validates name before fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.fetchMercurial (builtins.toFile "repo-url" "https://example.invalid/repo")"#,
    ))
    .expect_err("fetchMercurial rejects context-bearing URL strings");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "fetchMercurial",
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; rev = builtins.toFile "rev" "abcdef"; }"#,
        ))
        .expect_err("fetchMercurial rejects context-bearing revision strings");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "fetchMercurial",
            ..
        }
    ));
}

#[test]
fn fetch_mercurial_stub_preflights_pure_mode_pinning() {
    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchMercurial "https://example.invalid/repo""#),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure fetchMercurial rejects unpinned input before fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchMercurialRevRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    let ir = lower(
        r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; rev = "abcdef"; }"#,
    );
    let error = eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure))
        .expect_err("pinned fetchMercurial remains a fallback boundary");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedPrimOp {
            id: ir.root,
            symbol: symbol_for(&ir, b"fetchMercurial"),
        }
    );

    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; bogus = 1; }"#),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure fetchMercurial rejects unsupported attrs before pinning fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchMercurialAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; name = null; }"#),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure fetchMercurial validates name before pinning");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned_with_options(
            &lower(
                r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; rev = "abcdef"; name = builtins.throw "name"; }"#,
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Pure),
        )
        .expect_err("pure fetchMercurial forces name before fallback");
    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
}

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

#[test]
fn concat_lists_primop_flattens_spines_without_forcing_elements() {
    assert_eq!(
        eval_list_ints("builtins.concatLists [ [ 1 ] [] [ 2 3 ] ]"),
        vec![1, 2, 3]
    );
    assert_eq!(eval_list_ints("builtins.concatLists []"), Vec::<i64>::new());
    assert_eq!(
        eval_list_ints("let f = builtins.concatLists; in f [ [ 1 ] [] [ 2 3 ] ]"),
        vec![1, 2, 3]
    );

    let ir = lower("builtins.concatLists [ [ true (1 / 0) ] [] ]");
    let outcome = eval_whnf_owned(&ir).expect("concatLists evaluates");
    let heap = outcome.heap();
    let list = heap
        .get_list(outcome.value())
        .expect("concatLists result is a list");

    assert_eq!(list.len(), 2);
    assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));
    let lazy_division = list.get(1).expect("second");
    assert_eq!(lazy_division.tag(), ValueTag::Thunk);
    let thunk = heap
        .get_thunk(lazy_division)
        .expect("inner list element remains lazy");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );

    let ir = lower("let f = builtins.concatLists; in f [ [ true (1 / 0) ] [] ]");
    let outcome = eval_whnf_owned(&ir).expect("first-class concatLists evaluates");
    let heap = outcome.heap();
    let list = heap
        .get_list(outcome.value())
        .expect("concatLists result is a list");

    assert_eq!(list.len(), 2);
    assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));
    assert_eq!(list.get(1).expect("second").tag(), ValueTag::Thunk);
}

#[test]
fn concat_lists_primop_type_checks_outer_and_inner_lists() {
    let ir = lower("builtins.concatLists 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("concatLists requires an outer list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.concatLists [ [ 1 ] 2 [ 3 ] ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("concatLists requires inner lists");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.concatLists (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];

    let error = eval_whnf_owned(&ir).expect_err("outer list is forced first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: argument }
    );

    let ir = lower("builtins.concatLists [ [ 1 ] (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("inner lists are forced in order");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn head_primop_returns_first_element_without_forcing_list_elements() {
    let ir = lower("builtins.head [ (1 / 0) true ]");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_primop(ir.root, &root)
        .expect("head primop evaluates");
    assert_eq!(value.tag(), ValueTag::Thunk);
    let thunk = evaluator
        .heap
        .get_thunk(value)
        .expect("head result remains a heap-owned thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );

    assert_eq!(eval("builtins.head [ true (1 / 0) ]").as_bool(), Ok(true));
    assert_eq!(
        eval("let f = builtins.head; in f [ true (1 / 0) ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_string_bytes("let builtins = { head = x: \"local\"; }; in builtins.head [ 1 ]"),
        b"local"
    );
}

#[test]
fn head_primop_rejects_empty_lists() {
    let ir = lower("builtins.head []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("head requires a non-empty list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::EmptyListPrimOp {
            id: argument,
            op: "head"
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn head_primop_type_checks_argument() {
    let ir = lower("builtins.head 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("head requires a list");

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
fn elem_at_primop_returns_indexed_element_without_forcing_other_elements() {
    assert_eq!(
        eval("builtins.elemAt [ true (1 / 0) false ] 0").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = builtins.elemAt; in f [ 1 2 ] 1").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let xs = [ 1 2 ]; n = 1; in builtins.elemAt xs n").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let builtins = { elemAt = xs: n: 42; }; in builtins.elemAt [ true ] 0").as_int(),
        Ok(42)
    );

    let ir = lower("builtins.elemAt [ true (1 / 0) false ] 1");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_primop(ir.root, &root)
        .expect("elemAt primop evaluates");
    assert_eq!(value.tag(), ValueTag::Thunk);
    let thunk = evaluator
        .heap
        .get_thunk(value)
        .expect("selected element remains a heap-owned thunk");
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
fn elem_at_primop_type_checks_arguments_in_order() {
    let ir = lower("builtins.elemAt 1 true");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let index = args[1];
    let index_span = ir.arena.node(index).expect("index argument exists").span;

    let error = eval_whnf(&ir).expect_err("elemAt checks the index before the list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: index,
            expected: "int",
            actual: ValueTag::Bool
        }
    );
    assert_eq!(error.span(), index_span);

    let ir = lower("builtins.elemAt (1 / 0) true");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let index = args[1];
    let index_span = ir.arena.node(index).expect("index argument exists").span;

    let error = eval_whnf(&ir).expect_err("elemAt checks index type before forcing list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: index,
            expected: "int",
            actual: ValueTag::Bool
        }
    );
    assert_eq!(error.span(), index_span);

    let ir = lower("builtins.elemAt 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let index = args[1];
    let index_span = ir.arena.node(index).expect("index argument exists").span;

    let error = eval_whnf(&ir).expect_err("elemAt forces the index before checking the list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: index }
    );
    assert_eq!(error.span(), index_span);

    let error = eval_whnf_owned(&lower(
        "let f = builtins.elemAt; in f (builtins.throw \"list\") (builtins.throw \"index\")",
    ))
    .expect_err("first-class elemAt forces the index before the list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"index");

    let ir = lower("builtins.elemAt [] true");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let index = args[1];
    let index_span = ir.arena.node(index).expect("index argument exists").span;

    let error = eval_whnf(&ir).expect_err("elemAt requires an integer index");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: index,
            expected: "int",
            actual: ValueTag::Bool
        }
    );
    assert_eq!(error.span(), index_span);
}

#[test]
fn elem_at_primop_rejects_out_of_range_indexes() {
    for (source, expected_index) in [
        ("builtins.elemAt [ true ] 1", 1),
        ("builtins.elemAt [ true ] (-1)", -1),
    ] {
        let ir = lower(source);
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt requires an in-range index");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::ListIndexOutOfBounds {
                id: index,
                index: expected_index,
                len: 1
            }
        );
        assert_eq!(error.span(), index_span);
    }
}

#[test]
fn elem_primop_scans_list_with_structural_equality() {
    assert_eq!(eval("builtins.elem 2 [ 1 2 (1 / 0) ]").as_bool(), Ok(true));
    assert_eq!(eval("builtins.elem 3 [ 1 2 ]").as_bool(), Ok(false));
    assert_eq!(
        eval("let f = builtins.elem; in f 2 [ 1 2 (1 / 0) ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = builtins.elem; in f 3 [ 1 2 ]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("builtins.elem { a = 1; } [ { a = 1; } { a = 1 / 0; } ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = x: x; in builtins.elem f [ f ]").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.elem (x: x) [ (x: x) ]").as_bool(), Ok(false));
    assert_eq!(
        eval("let v = { a = x: x; }; in builtins.elem v.a [ v.a ]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("let xs = [ xs ]; in builtins.elem xs xs").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let xs = [ xs ]; f = builtins.elem; in f xs xs").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let s = rec { a = s; }; in builtins.elem s [ s ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let xs = [ (1 / 0) ]; in builtins.elem xs [ xs ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in builtins.elem nan [ nan ]")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
            eval(
                "builtins.elem ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) [ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ]"
            )
            .as_bool(),
            Ok(false)
        );
    assert_eq!(eval("builtins.elem (1 / 0) []").as_bool(), Ok(false));
    assert_eq!(
        eval("let builtins = { elem = value: list: false; }; in builtins.elem 1 [ 1 ]").as_bool(),
        Ok(false)
    );
}

#[test]
fn elem_primop_type_checks_list_before_candidate() {
    let ir = lower("builtins.elem (1 / 0) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf(&ir).expect_err("elem checks list type before candidate");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.elem 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf(&ir).expect_err("elem forces the list before the candidate");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
    assert_eq!(error.span(), list_span);

    let error = eval_whnf_owned(&lower("let f = builtins.elem; in f (1 / 0) 1"))
        .expect_err("first-class elem checks list before candidate");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("let f = builtins.elem; in f 1 (1 / 0)"))
        .expect_err("first-class elem forces list before candidate");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("builtins.elem 2 [ 1 (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("elem scans until match or error");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("let x = 1 / 0; in builtins.elem x [ x ]");
    let error = eval_whnf_owned(&ir).expect_err("elem forces shared throwing candidates");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("let s = { x = 1 / 0; }; v = { a = s; }; in builtins.elem v.a [ v.a ]");
    let error = eval_whnf_owned(&ir).expect_err("elem does not hide selected attrset errors");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn all_and_any_primops_short_circuit_over_lazy_elements() {
    assert_eq!(
        eval("builtins.all (x: x < 3) [ 1 2 3 ]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("builtins.all (x: x < 4) [ 1 2 3 ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.any (x: x == 2) [ 1 2 (1 / 0) ]").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.any (x: false) []").as_bool(), Ok(false));
    assert_eq!(eval("builtins.all (x: true) []").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.all (x: false) [ (1 / 0) ]").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("builtins.any (x: true) [ (1 / 0) ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.all builtins.isInt [ 1 2 ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.any builtins.isString [ 1 \"x\" ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let a = builtins.all; in a (x: x) [ true ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let a = builtins.any; in a (x: x) [ false true ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let p = x: x; xs = [ true ]; in builtins.all p xs").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let builtins = { all = pred: list: false; }; in builtins.all (x: true) []").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval("let builtins = { any = pred: list: true; }; in builtins.any (x: false) []").as_bool(),
        Ok(true)
    );
}

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

#[test]
fn map_primop_checks_list_before_function_for_nonempty_lists() {
    assert_eq!(eval("builtins.length (builtins.map 1 [])").as_int(), Ok(0));
    assert_eq!(
        eval("builtins.length (builtins.map (builtins.throw \"function\") [])").as_int(),
        Ok(0)
    );

    let ir = lower("builtins.map (builtins.throw \"function\") 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("map checks list before function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.map (x: x) (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("map forces list argument");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.map 1 [ 2 ]");
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

    let error = eval_whnf_owned(&ir).expect_err("map requires a function on nonempty lists");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);
}

#[test]
fn filter_primop_selects_without_forcing_returned_elements() {
    assert_eq!(
        eval("builtins.length (builtins.filter (x: x < 3) [ 1 2 3 ])").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.filter (x: x < 3) [ 1 2 3 ]) 0").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.filter (x: x < 3) [ 1 2 3 ]) 1").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.length (builtins.filter (x: false) [ (1 / 0) ])").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("builtins.length (builtins.filter (x: true) [ (1 / 0) ])").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.length (builtins.filter builtins.isInt [ 1 \"x\" 2 ])").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (let f = builtins.filter; in f builtins.isInt [ 1 \"x\" 2 ]) 1")
            .as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let p = x: x; xs = [ true ]; in builtins.length (builtins.filter p xs)").as_int(),
        Ok(1)
    );
    assert_eq!(
            eval("let builtins = { filter = pred: list: [ 42 ]; }; in builtins.filter (x: false) [] == [ 42 ]")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn filter_primop_checks_list_before_predicate() {
    assert_eq!(
        eval("builtins.length (builtins.filter (1 / 0) [])").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("builtins.length (builtins.filter 1 [])").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("let xs = []; in builtins.length (builtins.filter (builtins.throw \"predicate\") xs)")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("let f = builtins.filter; in builtins.length (f (builtins.throw \"predicate\") [])")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("let f = builtins.filter; in builtins.length (f 1 [])").as_int(),
        Ok(0)
    );

    let error = eval_whnf_owned(&lower(
        "let f = builtins.filter; in f (builtins.throw \"predicate\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class filter checks list before predicate");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"list");

    let ir = lower("builtins.filter (1 / 0) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("filter checks list before predicate");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.filter (x: true) (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("filter forces list argument");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
    assert_eq!(error.span(), list_span);
}

#[test]
fn filter_primop_checks_predicate_and_result_for_nonempty_lists() {
    let ir = lower("builtins.filter 1 [ 1 ]");
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

    let error = eval_whnf_owned(&ir).expect_err("filter requires predicate on nonempty lists");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: predicate,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), predicate_span);

    let ir = lower("builtins.filter (x: 1) [ \"a\" ]");
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

    let error = eval_whnf_owned(&ir).expect_err("filter requires bool predicate result");

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

#[test]
fn partition_primop_splits_forced_elements_into_right_and_wrong() {
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames (builtins.partition (x: true) [])"),
        vec![b"right".to_vec(), b"wrong".to_vec()]
    );
    assert_eq!(
        eval("builtins.length (builtins.partition (x: x < 3) [ 1 2 3 ]).right").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.partition (x: x < 3) [ 1 2 3 ]).right 0").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.partition (x: x < 3) [ 1 2 3 ]).right 1").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.length (builtins.partition (x: x < 3) [ 1 2 3 ]).wrong").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.partition (x: x < 3) [ 1 2 3 ]).wrong 0").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("builtins.length (builtins.partition (x: true) [ { a = 1 / 0; } ]).right").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.length (builtins.partition builtins.isInt [ 1 \"x\" 2 ]).right").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval(
            "builtins.length (let f = builtins.partition; in f builtins.isInt [ 1 \"x\" 2 ]).wrong"
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let p = x: true; xs = []; in builtins.length (builtins.partition p xs).right")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
            eval("let builtins = { partition = pred: list: { right = [ 42 ]; wrong = []; }; }; in builtins.partition (x: false) [] == { right = [ 42 ]; wrong = []; }")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn partition_primop_checks_predicate_before_list() {
    let ir = lower("builtins.partition (1 / 0) []");
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

    let error = eval_whnf_owned(&ir).expect_err("partition forces predicate before list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: predicate }
    );
    assert_eq!(error.span(), predicate_span);

    let ir = lower("builtins.partition 1 []");
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

    let error = eval_whnf_owned(&ir).expect_err("partition requires predicate first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: predicate,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), predicate_span);

    let ir = lower(
        "let f = builtins.partition; in f (builtins.throw \"predicate\") (builtins.throw \"list\")",
    );

    let error =
        eval_whnf_owned(&ir).expect_err("first-class partition forces predicate before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"predicate");

    let ir = lower("builtins.partition (x: true) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("partition checks list after predicate");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);
}

#[test]
fn partition_primop_forces_elements_before_predicate_application() {
    let ir = lower("builtins.partition (x: true) [ (1 / 0) ]");

    let error = eval_whnf_owned(&ir).expect_err("partition forces elements");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("builtins.partition (x: 1) [ \"a\" ]");
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

    let error = eval_whnf_owned(&ir).expect_err("partition requires bool predicate result");

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

#[test]
fn foldl_strict_primop_folds_left_and_forces_accumulator() {
    assert_eq!(
        eval("builtins.foldl' (acc: x: acc + x) 0 [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval("builtins.foldl' builtins.add 0 [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval("let f = builtins.foldl'; in f (acc: x: acc + x) 0 [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval("let f = builtins.foldl'; in f builtins.add 0 [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.foldl' (acc: x: acc ++ [ x ]) [] [ 1 2 3 ]) 0").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.foldl' (acc: x: acc ++ [ x ]) [] [ 1 2 3 ]) 2").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("builtins.foldl' (acc: x: acc) 0 [ (1 / 0) ]").as_int(),
        Ok(0)
    );

    let ir = lower("builtins.foldl' (acc: x: x) 0 [ (1 / 0) ]");
    let error = eval_whnf(&ir).expect_err("foldl' forces each accumulator result");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let outcome = eval_whnf_owned(&lower("builtins.foldl' (acc: x: { a = 1 / 0; }) 0 [ 1 ]"))
        .expect("foldl' forces accumulator to WHNF only");
    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
}

#[test]
fn foldl_strict_primop_checks_operator_then_list_then_initial() {
    let ir = lower("builtins.foldl' (1 / 0) 0 []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let op = args[0];
    let op_span = ir.arena.node(op).expect("operator argument exists").span;

    let error = eval_whnf(&ir).expect_err("foldl' forces operator first");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: op });
    assert_eq!(error.span(), op_span);

    let ir = lower("builtins.foldl' 1 0 []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let op = args[0];
    let op_span = ir.arena.node(op).expect("operator argument exists").span;

    let error = eval_whnf(&ir).expect_err("foldl' requires an operator function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: op,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), op_span);

    let ir = lower("builtins.foldl' (acc: x: acc) (1 / 0) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[2];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf(&ir).expect_err("foldl' checks list before initial value");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.foldl' (acc: x: acc) (1 / 0) []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let initial = args[1];
    let initial_span = ir
        .arena
        .node(initial)
        .expect("initial argument exists")
        .span;

    let error = eval_whnf(&ir).expect_err("foldl' forces initial value after list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: initial }
    );
    assert_eq!(error.span(), initial_span);

    let error = eval_whnf_owned(&lower("let f = builtins.foldl'; in f (1 / 0) 0 []"))
        .expect_err("first-class foldl' forces operator first");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower("let f = builtins.foldl'; in f 1 0 []"))
        .expect_err("first-class foldl' requires an operator function");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "let f = builtins.foldl'; in f (acc: x: acc) (1 / 0) 1",
    ))
    .expect_err("first-class foldl' checks list before initial value");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "let f = builtins.foldl'; in f (acc: x: acc) (1 / 0) []",
    ))
    .expect_err("first-class foldl' forces initial after list");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn foldl_strict_primop_checks_curried_operator_results() {
    let ir = lower("builtins.foldl' (acc: 1) 0 [ 1 ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let op = args[0];
    let op_span = ir.arena.node(op).expect("operator argument exists").span;

    let error = eval_whnf(&ir).expect_err("foldl' requires curried binary operator");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: op,
            expected: "lambda",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), op_span);

    assert_eq!(
            eval("let builtins = { foldl' = op: initial: list: 42; }; in builtins.foldl' (acc: x: acc) 0 []")
                .as_int(),
            Ok(42)
        );
}

#[test]
fn sort_primop_orders_stably_with_comparator() {
    assert_eq!(
        eval_list_ints("builtins.sort builtins.lessThan [ 3 1 2 1 ]"),
        vec![1, 1, 2, 3]
    );
    assert_eq!(
        eval_list_ints("builtins.sort (a: b: builtins.lessThan b a) [ 3 1 2 ]"),
        vec![3, 2, 1]
    );
    assert_eq!(
        eval_list_ints("let sort = builtins.sort builtins.lessThan; in sort [ 3 1 2 ]"),
        vec![1, 2, 3]
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.concatStringsSep \",\" (builtins.map (x: x.name) (builtins.sort (a: b: a.key < b.key) [ { key = 1; name = \"a\"; } { key = 1; name = \"b\"; } { key = 0; name = \"c\"; } ]))"
        ),
        b"c,a,b"
    );
    assert_eq!(
            eval("let builtins = { sort = comparator: list: [ 42 ]; }; in builtins.sort (a: b: false) [] == [ 42 ]")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn sort_primop_checks_comparator_list_and_result_types() {
    assert_eq!(
        eval_list_ints("builtins.sort (1 / 0) []"),
        Vec::<i64>::new()
    );
    assert_eq!(eval_list_ints("builtins.sort 1 []"), Vec::<i64>::new());
    assert_eq!(
        eval_list_ints("let sort = builtins.sort 1; in sort []"),
        Vec::<i64>::new()
    );

    let ir = lower("builtins.sort (1 / 0) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;
    let error = eval_whnf_owned(&ir).expect_err("sort checks the list before comparator");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.sort 1 [ 1 ]");
    let error = eval_whnf_owned(&ir).expect_err("sort requires a comparator function");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("let sort = builtins.sort; in sort 1 []");
    let result = eval_whnf_owned(&ir).expect("first-class sort skips comparator for empty list");
    let list = result
        .heap()
        .get_list(result.value())
        .expect("result is a list");
    assert!(list.is_empty());

    let ir = lower(
        "let sort = builtins.sort; in sort (builtins.throw \"comparator\") (builtins.throw \"list\")",
    );
    let error = eval_whnf_owned(&ir).expect_err("first-class sort forces list before comparator");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"list");

    let ir = lower("builtins.sort (a: b: false) 1");
    let error = eval_whnf_owned(&ir).expect_err("sort requires a list");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.sort (a: b: 1) [ 1 2 ]");
    let error = eval_whnf_owned(&ir).expect_err("sort comparator must return bool");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.sort (a: b: false) [ (1 / 0) true ]");
    let error = eval_whnf_owned(&ir).expect_err("sort forces elements before comparison");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("builtins.sort 1 [ (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("sort validates comparator before elements");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.sort builtins.lessThan [ 1 (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("sort forces elements");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn sort_primop_matches_libcxx_small_range_comparator_order() {
    let ir = lower(
        "builtins.sort (a: b:
              if a == 2 && b == 1 then builtins.throw \"wrong-order\"
              else if a == 2 && b == 3 then builtins.throw \"2<3\"
              else a < b)
            [ 3 1 2 ]",
    );
    let error = eval_whnf_owned(&ir).expect_err("sort reaches the libc++ second comparison first");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"2<3");
}

#[test]
fn sort_primop_matches_libcxx_large_range_merge_order() {
    // libc++ insertion-sorts pointer-like values up to 128 elements; 129
    // elements reaches the recursive stable-sort merge path. C++ Nix
    // 2.24 observes this top-level merge comparison for the descending fixture.
    let ir = lower(
        "builtins.sort (a: b:
              if a == 1 && b == 66 then builtins.throw \"top-merge\"
              else a < b)
            (builtins.genList (i: 129 - i) 129)",
    );
    let error = eval_whnf_owned(&ir).expect_err("sort reaches the libc++ large-range merge path");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"top-merge");
}

#[test]
fn less_than_primop_uses_language_comparison_semantics() {
    assert_eq!(eval("builtins.lessThan 1 2").as_bool(), Ok(true));
    assert_eq!(eval("builtins.lessThan 2 1").as_bool(), Ok(false));
    assert_eq!(eval("builtins.lessThan 1 1").as_bool(), Ok(false));
    assert_eq!(eval("builtins.lessThan 1 1.5").as_bool(), Ok(true));
    assert_eq!(eval("builtins.lessThan \"a\" \"b\"").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.lessThan [ 1 2 ] [ 1 3 ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.lessThan [ 1 (1 / 0) ] [ 2 (1 / 0) ]").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let builtins = { lessThan = left: right: false; }; in builtins.lessThan 1 2")
            .as_bool(),
        Ok(false)
    );
}

#[test]
fn less_than_primop_forces_operands_before_type_checks() {
    let ir = lower("builtins.lessThan true (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let rhs = args[1];
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&ir).expect_err("lessThan forces rhs before type check");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);

    let ir = lower("builtins.lessThan true false");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let lhs = args[0];
    let lhs_span = ir.arena.node(lhs).expect("lhs exists").span;

    let error = eval_whnf(&ir).expect_err("lessThan rejects incomparable lhs");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: lhs,
            expected: "number, string, path, or list",
            actual: ValueTag::Bool
        }
    );
    assert_eq!(error.span(), lhs_span);

    let ir = lower("builtins.lessThan 1 true");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let rhs = args[1];
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&ir).expect_err("lessThan checks rhs against lhs type");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "number",
            actual: ValueTag::Bool
        }
    );
    assert_eq!(error.span(), rhs_span);

    let ir = lower("builtins.lessThan [ 1 (1 / 0) ] [ 1 2 ]");
    let error = eval_whnf_owned(&ir).expect_err("equal list prefix forces next element");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn arithmetic_primops_use_numeric_semantics() {
    assert_eq!(eval("builtins.add 1 2").as_int(), Ok(3));
    assert_eq!(eval("builtins.sub 5 8").as_int(), Ok(-3));
    assert_eq!(eval("builtins.mul 2 3").as_int(), Ok(6));
    assert_eq!(eval("builtins.div 7 2").as_int(), Ok(3));
    assert_eq!(eval("builtins.div 7 (-2)").as_int(), Ok(-3));
    assert_eq!(eval("builtins.add 1 2.5").as_float(), Ok(3.5));
    assert_eq!(eval("builtins.sub 1 2.5").as_float(), Ok(-1.5));
    assert_eq!(eval("builtins.mul 2 0.5").as_float(), Ok(1.0));
    assert_eq!(eval("builtins.div 7 2.0").as_float(), Ok(3.5));
    assert_eq!(
        eval("builtins.add 9223372036854775807 1").as_int(),
        Ok(i64::MIN)
    );
    assert_eq!(
        eval("builtins.sub (-9223372036854775807 - 1) 1").as_int(),
        Ok(i64::MAX)
    );
    assert_eq!(eval("builtins.mul 9223372036854775807 2").as_int(), Ok(-2));
}

#[test]
fn arithmetic_primops_are_strict_and_numeric_only() {
    let ir = lower("builtins.add \"a\" (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let rhs = args[1];
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&ir).expect_err("rhs evaluation error wins before type check");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);

    let ir = lower("builtins.add \"a\" \"b\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let lhs = args[0];
    let lhs_span = ir.arena.node(lhs).expect("lhs exists").span;

    let error = eval_whnf_owned(&ir).expect_err("strings are invalid for builtins.add");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: lhs,
            expected: "number",
            actual: ValueTag::String,
        }
    );
    assert_eq!(error.span(), lhs_span);

    let ir = lower("builtins.sub true (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let rhs = args[1];
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&ir).expect_err("sub forces rhs before lhs type check");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);

    let div_zero = lower("builtins.div 1 0");
    let error = eval_whnf(&div_zero).expect_err("integer division by zero is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: div_zero.root }
    );

    let div_overflow = lower("builtins.div (-9223372036854775807 - 1) (-1)");
    let error = eval_whnf(&div_overflow).expect_err("integer division overflow is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::ArithmeticOverflow {
            id: div_overflow.root,
            op: ArithmeticOp::Div,
        }
    );
}

#[test]
fn bitwise_primops_apply_signed_integer_ops() {
    assert_eq!(eval("builtins.bitAnd 6 3").as_int(), Ok(2));
    assert_eq!(eval("builtins.bitOr 4 1").as_int(), Ok(5));
    assert_eq!(eval("builtins.bitXor 6 3").as_int(), Ok(5));
    assert_eq!(eval("builtins.bitXor (-1) 1").as_int(), Ok(-2));
    assert_eq!(
        eval("let builtins = { bitAnd = left: right: 42; }; in builtins.bitAnd 6 3").as_int(),
        Ok(42)
    );
}

#[test]
fn bitwise_primops_type_check_arguments_left_to_right() {
    let ir = lower("builtins.bitAnd true (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let lhs = args[0];
    let lhs_span = ir.arena.node(lhs).expect("lhs exists").span;

    let error = eval_whnf(&ir).expect_err("bitAnd checks lhs before rhs");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: lhs,
            expected: "int",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), lhs_span);

    let ir = lower("builtins.bitAnd 1 true");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let rhs = args[1];
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&ir).expect_err("bitAnd checks rhs after valid lhs");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "int",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), rhs_span);

    let ir = lower("builtins.bitAnd 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let rhs = args[1];
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf(&ir).expect_err("bitAnd forces rhs after valid lhs");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn get_attr_primop_returns_attr_without_forcing_selected_value() {
    assert_eq!(
        eval("builtins.getAttr \"a\" { a = 1; b = 1 / 0; }").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let builtins = { getAttr = name: set: 42; }; in builtins.getAttr \"a\" {}").as_int(),
        Ok(42)
    );

    let ir = lower("builtins.getAttr \"a\" { a = 1 / 0; }");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_primop(ir.root, &root)
        .expect("getAttr primop evaluates");
    assert_eq!(value.tag(), ValueTag::Thunk);
    let thunk = evaluator
        .heap
        .get_thunk(value)
        .expect("selected attr remains a heap-owned thunk");
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
fn get_attr_primop_reports_missing_attrs() {
    let ir = lower("builtins.getAttr \"missing\" { a = 1; }");
    let root = ir.arena.node(ir.root).expect("root exists");

    let error = eval_whnf(&ir).expect_err("getAttr requires the attribute to exist");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected a missing attribute error");
    };
    assert_eq!(id, ir.root);
    assert_eq!(ir.symbols.resolve(symbol), Some(b"missing".as_slice()));
    assert_eq!(error.span(), root.span);
}

#[test]
fn get_attr_primop_type_checks_arguments_in_order() {
    let ir = lower("builtins.getAttr 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let name = args[0];
    let name_span = ir.arena.node(name).expect("name argument exists").span;

    let error = eval_whnf(&ir).expect_err("getAttr checks the name before the attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: name,
            expected: "string",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), name_span);

    let ir = lower("builtins.getAttr \"a\" 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let attrs = args[1];
    let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

    let error = eval_whnf(&ir).expect_err("getAttr requires an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: attrs,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), attrs_span);
}

#[test]
fn unsafe_get_attr_pos_reports_static_binding_positions() {
    let source = r#"builtins.toJSON (
  let p = builtins.unsafeGetAttrPos "a" { a = 1; };
  in [ p.file p.line p.column ]
)"#;
    let column = source.find("a = 1").expect("binding exists") + 1;
    let expected = format!(r#"["/source.nix",1,{}]"#, column);

    assert_eq!(
        eval_string_bytes_with_source(b"/source.nix", source),
        expected.as_bytes()
    );
}

#[test]
fn unsafe_get_attr_pos_reports_dynamic_binding_positions() {
    let source = r#"builtins.toJSON (
  let p = builtins.unsafeGetAttrPos "a" { ${"a"} = 1; };
  in [ p.column ]
)"#;
    let column = source.find(r#"${"a"}"#).expect("dynamic binding exists") + 1;
    let expected = format!("[{}]", column);

    assert_eq!(
        eval_string_bytes_with_source(b"/source.nix", source),
        expected.as_bytes()
    );

    let null_source = r#"builtins.unsafeGetAttrPos "a" { ${null} = 1; } == null"#;
    assert_eq!(
        eval_owned_with_source(b"/source.nix", null_source)
            .value()
            .as_bool(),
        Ok(true)
    );
}

#[test]
fn unsafe_get_attr_pos_without_source_or_missing_attr_returns_null() {
    assert_eq!(
        eval(r#"builtins.unsafeGetAttrPos "a" { a = 1; } == null"#).as_bool(),
        Ok(true)
    );

    let source = r#"builtins.unsafeGetAttrPos "b" { a = 1; } == null"#;
    assert_eq!(
        eval_owned_with_source(b"/source.nix", source)
            .value()
            .as_bool(),
        Ok(true)
    );
}

#[test]
fn unsafe_get_attr_pos_preserves_update_winner_positions() {
    let source = r#"builtins.toJSON (
  let
    base = { a = 1; };
    merged = base // { b = 2; };
    pa = builtins.unsafeGetAttrPos "a" merged;
    pb = builtins.unsafeGetAttrPos "b" merged;
  in [ pa.column pb.column ]
)"#;
    let a_column = source.find("a = 1").expect("a binding exists") + 1;
    let b_column = source.find("b = 2").expect("b binding exists") + 1;
    let expected = format!("[{},{}]", a_column, b_column);

    assert_eq!(
        eval_string_bytes_with_source(b"/source.nix", source),
        expected.as_bytes()
    );
}

#[test]
fn unsafe_get_attr_pos_clears_computed_map_attrs_positions() {
    let source = r#"builtins.unsafeGetAttrPos "a" (builtins.mapAttrs (name: value: value) { a = 1; }) == null"#;

    assert_eq!(
        eval_owned_with_source(b"/source.nix", source)
            .value()
            .as_bool(),
        Ok(true)
    );
}

#[test]
fn unsafe_get_attr_pos_tracks_list_to_attrs_name_binding() {
    let source = r#"builtins.toJSON (
  let
    attrs = builtins.listToAttrs [ { name = "a"; value = 1; } ];
    p = builtins.unsafeGetAttrPos "a" attrs;
  in [ p.column ]
)"#;
    let name_column = source.find("name =").expect("name binding exists") + 1;
    let expected = format!("[{}]", name_column);

    assert_eq!(
        eval_string_bytes_with_source(b"/source.nix", source),
        expected.as_bytes()
    );
}

#[test]
fn unsafe_get_attr_pos_supports_first_class_application() {
    let source = r#"builtins.toJSON (
  let
    f = builtins.unsafeGetAttrPos;
    p = f "a" { a = 1; };
  in [ p.file p.column ]
)"#;
    let column = source.find("a = 1").expect("binding exists") + 1;
    let expected = format!(r#"["/source.nix",{}]"#, column);

    assert_eq!(
        eval_string_bytes_with_source(b"/source.nix", source),
        expected.as_bytes()
    );
}

#[test]
fn unsafe_get_attr_pos_reports_imported_file_path() {
    let root = fs::canonicalize(unique_temp_dir("unsafe-get-attr-pos-import"))
        .expect("temp directory canonicalizes");
    let imported = root.join("attrs.nix");
    fs::write(&imported, b"{\n  a = 1;\n}").expect("import writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let source = r#"builtins.toJSON (
  let p = builtins.unsafeGetAttrPos "a" (import ./attrs.nix);
  in [ p.file p.line p.column ]
)"#;
    let actual = eval_string_bytes_with_options(source, options);
    let expected = format!(
        r#"["{}",1,5]"#,
        imported.to_str().expect("import path is UTF-8")
    );

    assert_eq!(actual, expected.as_bytes());

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn unsafe_get_attr_pos_type_checks_arguments_in_order() {
    let ir = lower("builtins.unsafeGetAttrPos 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let name = args[0];
    let name_span = ir.arena.node(name).expect("name argument exists").span;

    let error = eval_whnf(&ir).expect_err("unsafeGetAttrPos checks name before attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: name,
            expected: "string",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), name_span);

    let ir = lower(r#"builtins.unsafeGetAttrPos "a" 1"#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let attrs = args[1];
    let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

    let error = eval_whnf(&ir).expect_err("unsafeGetAttrPos requires an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: attrs,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), attrs_span);
}

#[test]
fn has_attr_primop_reports_presence_without_forcing_values() {
    assert_eq!(
        eval("builtins.hasAttr \"a\" { a = 1 / 0; }").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.hasAttr \"b\" { a = 1 / 0; }").as_bool(),
        Ok(false)
    );
    assert_eq!(
            eval("let builtins = { hasAttr = name: set: false; }; in builtins.hasAttr \"a\" { a = true; }")
                .as_bool(),
            Ok(false)
        );
}

#[test]
fn has_attr_primop_type_checks_name_before_attrset() {
    let ir = lower("builtins.hasAttr 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let name = args[0];
    let name_span = ir.arena.node(name).expect("name argument exists").span;

    let error = eval_whnf(&ir).expect_err("hasAttr checks the name before the attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: name,
            expected: "string",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), name_span);

    let ir = lower("builtins.hasAttr \"a\" 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let attrs = args[1];
    let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

    let error = eval_whnf(&ir).expect_err("hasAttr requires an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: attrs,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), attrs_span);
}

#[test]
fn remove_attrs_primop_removes_names_without_forcing_values() {
    assert_eq!(
        eval_list_string_bytes(
            "builtins.attrNames (builtins.removeAttrs { z = 1; a = 1 / 0; b = 2; } [ \"z\" \"missing\" \"z\" ])"
        ),
        vec![b"a".to_vec(), b"b".to_vec()]
    );
    assert_eq!(
        eval("let r = builtins.removeAttrs { a = 1 / 0; b = 2; } [ \"a\" ]; in r.b").as_int(),
        Ok(2)
    );
    assert_eq!(
            eval("let builtins = { removeAttrs = set: names: { local = true; }; }; in (builtins.removeAttrs {} []).local")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn remove_attrs_primop_type_checks_arguments_in_order() {
    let ir = lower("builtins.removeAttrs 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let attrs = args[0];
    let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

    let error = eval_whnf(&ir).expect_err("removeAttrs checks the attrset before names");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: attrs,
            expected: "attrs",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), attrs_span);

    let ir = lower("builtins.removeAttrs {} 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let names = args[1];
    let names_span = ir.arena.node(names).expect("names argument exists").span;

    let error = eval_whnf(&ir).expect_err("removeAttrs requires a name list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: names,
            expected: "list",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), names_span);

    let ir = lower("builtins.removeAttrs {} [ 1 ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let names = args[1];
    let names_span = ir.arena.node(names).expect("names argument exists").span;

    let error = eval_whnf(&ir).expect_err("removeAttrs requires string names");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: names,
            expected: "string",
            actual: ValueTag::Int
        }
    );
    assert_eq!(error.span(), names_span);
}

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

#[test]
fn store_path_primop_returns_context_bearing_store_strings() {
    let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src";
    let child = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src/sub";
    let context_json =
        br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true}}"#.to_vec();

    assert_eq!(
        eval_string_bytes(&format!("builtins.storePath {root}")),
        root.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(r#"builtins.storePath "{root}/.""#)),
        root.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(r#"builtins.storePath "{child}""#)),
        child.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(r#"builtins.storePath {{ outPath = "{root}"; }}"#)),
        root.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.typeOf (builtins.storePath {root})")),
        b"string"
    );
    assert_eq!(
        eval_json_bytes(&format!("builtins.getContext (builtins.storePath {root})")),
        context_json
    );
    assert_eq!(
        eval_json_bytes(&format!(
            r#"builtins.getContext (builtins.storePath "{child}")"#
        )),
        br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true}}"#.to_vec()
    );
}

#[test]
fn store_path_primop_unions_existing_string_context() {
    let source = r#"builtins.getContext (
            builtins.storePath (
                builtins.appendContext
                  "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src"
                  {
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other" = {
                      path = true;
                    };
                  }
            )
        )"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other":{"path":true}}"#.to_vec()
        );
}

#[test]
fn store_path_context_is_observed_by_derivation_strict_as_input_src() {
    let source = r#"let
             src = builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src";
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               inherit src;
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
             src = src;
             srcContext = builtins.getContext src;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/vkbcsd0wpf20mil1mngbk8dzrh9z3sdv-x.drv","out":"/nix/store/y1q9h2irnds1pphaf2cpyxdv54y87w6d-x","src":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src","srcContext":{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true}}}"#.to_vec()
        );
}

#[test]
fn store_path_primop_uses_configured_store_dir() {
    let root = "/custom/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src";
    let options =
        TreeWalkOptions::with_store_dir(b"/custom/store".to_vec()).expect("store dir configures");

    assert_eq!(
        eval_string_bytes_with_options(&format!("builtins.storePath {root}"), options.clone()),
        root.as_bytes()
    );
    assert_eq!(
        eval_json_bytes_with_options(
            &format!(r#"builtins.getContext (builtins.storePath "{root}/sub")"#),
            options,
        ),
        br#"{"/custom/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true}}"#.to_vec()
    );
}

#[test]
fn store_path_primop_rejects_non_store_paths() {
    let error = eval_whnf_owned(&lower(r#"builtins.storePath "/tmp/not-store""#))
        .expect_err("storePath rejects paths outside the store");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StorePathNotInStore {
            path,
            ..
        } if path.as_slice() == b"/tmp/not-store"
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src/..""#,
    ))
    .expect_err("storePath rejects normalized store dir");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StorePathNotInStore {
            path,
            ..
        } if path.as_slice() == b"/nix/store"
    ));

    let error = eval_whnf_owned(&lower("builtins.storePath 1"))
        .expect_err("storePath coerces its argument to a string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn store_path_primop_is_gated_by_filesystem_policy() {
    let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src";
    let source = format!(r#"builtins.storePath "{root}""#);
    let ir = lower(&source);

    let error = eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure))
        .expect_err("pure mode rejects storePath calls");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StorePathPureEval { id: ir.root }
    );

    assert_eq!(
        eval_with_options(
            "builtins ? storePath",
            TreeWalkOptions::with_eval_mode(EvalMode::Pure)
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.typeOf builtins.storePath",
            TreeWalkOptions::with_eval_mode(EvalMode::Pure)
        ),
        b"lambda"
    );
    let fallback_ir = lower("builtins.storePath or 42");
    assert_eq!(
        eval_whnf_owned_with_options(
            &fallback_ir,
            TreeWalkOptions::with_eval_mode(EvalMode::Pure)
        )
        .expect("storePath is visible to select-or in pure mode")
        .value()
        .tag(),
        ValueTag::Primop
    );

    let invalid_ir = lower("builtins.storePath 1");
    let (argument, argument_span) = primop_argument(&invalid_ir, 0);
    let error =
        eval_whnf_owned_with_options(&invalid_ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure))
            .expect_err("pure storePath still validates its argument before mode rejection");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let mut allowed_pure_options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
    allowed_pure_options
        .add_allowed_path(b"/nix/store".to_vec())
        .expect("store root configures as allowed");
    let error = eval_whnf_owned_with_options(&ir, allowed_pure_options)
        .expect_err("pure mode rejects storePath even when path policy would allow it");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StorePathPureEval { id: ir.root }
    );

    let selected_call = lower(&format!(r#"let f = builtins.storePath; in f "{root}""#));
    let error = eval_whnf_owned_with_options(
        &selected_call,
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure mode rejects selected first-class storePath calls");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StorePathPureEval { .. }
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(b"/nix/store".to_vec())
        .expect("store root configures as allowed");
    assert_eq!(
        eval_string_bytes_with_options(&source, options),
        root.as_bytes()
    );
}

#[test]
fn to_file_primop_builds_text_store_paths_and_context() {
    let source = r#"let
            p = builtins.toFile "foo" "bar";
            nested = builtins.toFile "baz" p;
            dot = builtins.toFile ".x" "x";
        in {
            path = p;
            ctx = builtins.getContext p;
            nested = nested;
            nestedCtx = builtins.getContext nested;
            dot = dot;
            firstClass = (builtins.toFile "hello") "abc";
        }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"ctx":{"/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo":{"path":true}},"dot":"/nix/store/1x49d9g8znzikskxdsx7k6kk2qzcdrps-.x","firstClass":"/nix/store/4falznnjmyg7iqca3qlskx9l79bh6hwd-hello","nested":"/nix/store/5xd714cbfnkz02h2vbsj4fm03x3f15nf-baz","nestedCtx":{"/nix/store/5xd714cbfnkz02h2vbsj4fm03x3f15nf-baz":{"path":true}},"path":"/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo"}"#.to_vec()
        );
}

#[test]
fn to_file_primop_validates_name_before_forcing_contents() {
    let error = eval_whnf_owned(&lower(r#"builtins.toFile 1 (builtins.throw "contents")"#))
        .expect_err("toFile validates the name type before forcing contents");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.toFile
                (builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src")
                (builtins.throw "contents")"#,
    ))
    .expect_err("toFile validates name context before forcing contents");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "toFile", .. }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.toFile "bad/name" (builtins.throw "contents")"#,
    ))
    .expect_err("toFile forces contents before constructing the store path");
    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
}

#[test]
fn to_file_text_store_is_visible_to_filesystem_builtins_and_import() {
    let source = r#"let
            p = builtins.toFile "x.nix" "1 + 2";
            scoped = builtins.toFile "scoped.nix" "y + 1";
        in {
            exists = builtins.pathExists p;
            type = builtins.readFileType p;
            read = builtins.readFile p;
            imported = import p;
            scoped = builtins.scopedImport { y = 4; } scoped;
        }"#;

    assert_eq!(
        eval_json_bytes(source),
        br#"{"exists":true,"imported":3,"read":"1 + 2","scoped":5,"type":"regular"}"#.to_vec()
    );
}

#[test]
fn to_file_text_store_read_file_preserves_references() {
    let source = r#"let
            p = builtins.toFile "foo" "bar";
            q = builtins.toFile "baz" p;
            read = builtins.readFile q;
        in {
            ctx = builtins.getContext read;
            sameAgain = builtins.toFile "again" read == builtins.toFile "again" p;
        }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"ctx":{"/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo":{"path":true}},"sameAgain":true}"#.to_vec()
        );
}

#[test]
fn to_file_text_store_import_uses_import_cache() {
    let outcome = eval_owned(
        r#"let
                p = builtins.toFile "cached.nix" "builtins.trace \"cached\" 1";
                values = [ (import p) (import p) ];
            in builtins.deepSeq values values"#,
    );

    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        b"cached",
    );
}

#[test]
fn to_file_text_store_read_file_rejects_nul_bytes() {
    let error = eval_whnf_owned(&lower(
        r#"builtins.readFile (builtins.toFile "nul" (builtins.fromJSON "\"a\\u0000b\""))"#,
    ))
    .expect_err("readFile rejects NUL bytes from text store files");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FileReadContainsNul { .. }
    ));
}

#[test]
fn to_file_primop_rejects_invalid_name_and_types() {
    for name in ["bad/name", "", ".", "..", ".-x", "..-x"] {
        let source = format!(r#"builtins.toFile "{name}" "x""#);
        let error =
            eval_whnf_owned(&lower(&source)).expect_err("invalid store path names are rejected");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::ToFilePath { .. }),
            "{name:?} rejected as ToFilePath, got {error:?}"
        );
    }

    let error = eval_whnf_owned(&lower(r#"builtins.toFile 1 "x""#))
        .expect_err("toFile name must be a string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(r#"builtins.toFile "x" 1"#))
        .expect_err("toFile contents must be a string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn to_file_primop_rejects_contextual_names_and_derivation_contents() {
    let error = eval_whnf_owned(&lower(
        r#"builtins.toFile
                (builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src")
                "x""#,
    ))
    .expect_err("toFile names cannot carry context");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "toFile", .. }
    ));

    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ ];
             };
           in builtins.toFile "bad" d.out"#;
    let error = eval_whnf_owned(&lower(source))
        .expect_err("toFile contents cannot reference derivation outputs");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::ToFileDerivationReference {
            kind: ContextKind::SingleOutput,
            ..
        }
    ));

    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ ];
             };
           in builtins.toFile "ok" (builtins.unsafeDiscardOutputDependency d.drvPath)"#;
    eval_whnf_owned(&lower(source))
        .expect("toFile allows derivation contexts downgraded to opaque paths");
}

#[test]
fn add_drv_output_dependencies_primop_upgrades_derivation_context() {
    assert_eq!(
        eval_string_bytes(
            "let builtins = { addDrvOutputDependencies = value: \"shadow\"; }; in builtins.addDrvOutputDependencies \"x\""
        ),
        b"shadow"
    );

    let ir = lower("builtins.addDrvOutputDependencies \"x\"");
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
        .expect("addDrvOutputDependencies argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let drv_path = b"/nix/store/derivation.drv";
    let context = StringContext::singleton(
        ContextElement::opaque_path(drv_path.to_vec()).expect("drv context is valid"),
    )
    .expect("context allocates");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(drv_path.to_vec(), context))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
        .expect("addDrvOutputDependencies evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result string exists");

    assert_eq!(string.bytes(), drv_path);
    assert_eq!(string.context().len(), 1);
    let element = string
        .context()
        .elements()
        .first()
        .expect("result context element exists");
    assert_eq!(element.kind(), ContextKind::DeepDerivation);
    assert_eq!(element.path(), drv_path);
}

#[test]
fn add_drv_output_dependencies_primop_is_idempotent_for_deep_context() {
    let ir = lower("builtins.addDrvOutputDependencies \"x\"");
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
        .expect("addDrvOutputDependencies argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let drv_path = b"/nix/store/deep.drv";
    let context = StringContext::singleton(
        ContextElement::deep_derivation(drv_path.to_vec()).expect("deep context is valid"),
    )
    .expect("context allocates");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(drv_path.to_vec(), context))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
        .expect("addDrvOutputDependencies evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result string exists");

    assert_eq!(string.bytes(), drv_path);
    assert_eq!(string.context().len(), 1);
    let element = string
        .context()
        .elements()
        .first()
        .expect("result context element exists");
    assert_eq!(element.kind(), ContextKind::DeepDerivation);
    assert_eq!(element.path(), drv_path);
}

#[test]
fn add_drv_output_dependencies_primop_rejects_invalid_context_shapes() {
    let ir = lower("builtins.addDrvOutputDependencies \"x\"");
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
        .expect("addDrvOutputDependencies argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("empty context is rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextElementCount {
            id: argument,
            len: 0,
        }
    );
    assert_eq!(error.span(), argument_span);

    let mut evaluator = TreeWalk::new(&ir);
    let context = StringContext::new(vec![
        ContextElement::opaque_path(b"/nix/store/a.drv".to_vec()).expect("first context is valid"),
        ContextElement::opaque_path(b"/nix/store/b.drv".to_vec()).expect("second context is valid"),
    ]);
    let value = evaluator
        .heap
        .alloc_string(NixString::new(b"x".to_vec(), context))
        .expect("context-bearing string allocates");
    let error = evaluator
        .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
        .expect_err("multiple context elements are rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextElementCount {
            id: argument,
            len: 2,
        }
    );

    let mut evaluator = TreeWalk::new(&ir);
    let source_path = b"/nix/store/source";
    let context = StringContext::singleton(
        ContextElement::opaque_path(source_path.to_vec()).expect("source context is valid"),
    )
    .expect("context allocates");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(source_path.to_vec(), context))
        .expect("context-bearing string allocates");
    let error = evaluator
        .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
        .expect_err("non-derivation context paths are rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextPathNotDerivation {
            id: argument,
            path: source_path.to_vec(),
        }
    );

    let mut evaluator = TreeWalk::new(&ir);
    let drv_path = b"/nix/store/output.drv";
    let context = StringContext::singleton(
        ContextElement::single_output(drv_path.to_vec(), b"out".to_vec())
            .expect("output context is valid"),
    )
    .expect("context allocates");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(drv_path.to_vec(), context))
        .expect("context-bearing string allocates");
    let error = evaluator
        .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
        .expect_err("output context is rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextDerivationOutput {
            id: argument,
            output: b"out".to_vec(),
        }
    );
}

#[test]
fn add_drv_output_dependencies_primop_coerces_argument() {
    let ir = lower("builtins.addDrvOutputDependencies 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("integer coercion is rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.addDrvOutputDependencies { outPath = \"x\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("coerced context-free string is rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextElementCount {
            id: argument,
            len: 0,
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn unsafe_discard_output_dependency_primop_downgrades_deep_contexts() {
    assert_eq!(
        eval_string_bytes("builtins.unsafeDiscardOutputDependency \"abc\""),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes("builtins.unsafeDiscardOutputDependency { outPath = \"abc\"; }"),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { unsafeDiscardOutputDependency = value: \"shadow\"; }; in builtins.unsafeDiscardOutputDependency \"abc\""
        ),
        b"shadow"
    );

    let ir = lower("builtins.unsafeDiscardOutputDependency \"x\"");
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
        .expect("unsafeDiscardOutputDependency argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source_path = b"/nix/store/source";
    let deep_path = b"/nix/store/deep.drv";
    let output_path = b"/nix/store/output.drv";
    let context = StringContext::new(vec![
        ContextElement::deep_derivation(deep_path.to_vec()).expect("deep context is valid"),
        ContextElement::opaque_path(deep_path.to_vec()).expect("opaque context is valid"),
        ContextElement::opaque_path(source_path.to_vec()).expect("source context is valid"),
        ContextElement::single_output(output_path.to_vec(), b"out".to_vec())
            .expect("output context is valid"),
    ]);
    let value = evaluator
        .heap
        .alloc_string(NixString::new(b"x".to_vec(), context))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_unsafe_discard_output_dependency_primop(argument, argument_span, value)
        .expect("unsafeDiscardOutputDependency evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result string exists");

    assert_eq!(string.bytes(), b"x");
    assert_eq!(string.context().len(), 3);
    assert!(string.context().contains(
        &ContextElement::opaque_path(source_path.to_vec()).expect("source context builds")
    ));
    assert!(string.context().contains(
        &ContextElement::opaque_path(deep_path.to_vec()).expect("deep path context builds")
    ));
    assert!(
        string.context().contains(
            &ContextElement::single_output(output_path.to_vec(), b"out".to_vec())
                .expect("output context builds")
        )
    );
    assert!(!string.context().contains(
        &ContextElement::deep_derivation(deep_path.to_vec()).expect("deep context builds")
    ));
}

#[test]
fn unsafe_discard_output_dependency_primop_coerces_argument() {
    let ir = lower("builtins.unsafeDiscardOutputDependency 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("integer coercion is rejected");

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
fn unsafe_discard_string_context_primop_returns_context_free_string() {
    assert_eq!(
        eval_string_bytes("builtins.unsafeDiscardStringContext \"abc\""),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes("builtins.unsafeDiscardStringContext { outPath = \"abc\"; }"),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes("builtins.unsafeDiscardStringContext { __toString = self: \"custom\"; }"),
        b"custom"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { unsafeDiscardStringContext = value: \"shadow\"; }; in builtins.unsafeDiscardStringContext \"abc\""
        ),
        b"shadow"
    );

    let ir = lower("builtins.unsafeDiscardStringContext \"x\"");
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
        .expect("unsafeDiscardStringContext argument exists");
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

    let result = evaluator
        .eval_unsafe_discard_string_context_primop(argument, argument_span, value)
        .expect("unsafeDiscardStringContext evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result string exists");

    assert_eq!(string.bytes(), b"x");
    assert!(!string.has_context());
}

#[test]
fn unsafe_discard_string_context_primop_forces_and_coerces_argument() {
    let ir = lower("builtins.unsafeDiscardStringContext (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("unsafeDiscardStringContext forces its argument");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: argument }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.unsafeDiscardStringContext 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("integer is not string-coercible here");

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
fn string_length_primop_counts_coerced_string_bytes() {
    assert_eq!(eval("builtins.stringLength \"abc\"").as_int(), Ok(3));
    assert_eq!(eval("builtins.stringLength \"a\\n\"").as_int(), Ok(2));
    assert_eq!(
        eval("builtins.stringLength { outPath = \"abc\"; }").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("builtins.stringLength { __toString = self: self.name; name = \"custom\"; }").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval("let builtins = { stringLength = value: 42; }; in builtins.stringLength \"abc\"")
            .as_int(),
        Ok(42)
    );
}

#[test]
fn string_length_primop_forces_and_coerces_argument() {
    let ir = lower("builtins.stringLength (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("stringLength forces its argument");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: argument }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.stringLength 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("integer is not string-coercible here");

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
fn match_primop_matches_full_strings_and_captures() {
    assert_eq!(
        eval_list_string_bytes(r#"builtins.match "a(.)c" "abc""#),
        vec![b"b".to_vec()]
    );
    assert_eq!(eval(r#"builtins.match "a(.)" "abc""#).as_null(), Ok(()));
    assert_eq!(
        eval(r#"builtins.length (builtins.match "abc" "abc")"#).as_int(),
        Ok(0)
    );
    assert_eq!(
        eval(r#"builtins.length (builtins.match "a|aa" "aa")"#).as_int(),
        Ok(0)
    );
    assert_eq!(
        eval_list_string_bytes(r#"builtins.match "(a|aa)" "aa""#),
        vec![b"aa".to_vec()]
    );
    assert_eq!(
        eval(r#"builtins.elemAt (builtins.match "(a)?b" "b") 0"#).as_null(),
        Ok(())
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.elemAt (builtins.match "(a*)" "") 0"#),
        b""
    );
    assert_eq!(
        eval_list_string_bytes(r#"let m = builtins.match "a(.)c"; in m "abc""#),
        vec![b"b".to_vec()]
    );
    assert_eq!(
        eval_string_bytes(
            r#"let builtins = { match = pattern: value: "shadow"; }; in builtins.match "a" "a""#
        ),
        b"shadow"
    );
}

#[test]
fn match_primop_checks_arguments_and_regexes() {
    let ir = lower(r#"builtins.match 1 (1 / 0)"#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let pattern = args[0];
    let pattern_span = ir.arena.node(pattern).expect("pattern exists").span;

    let error = eval_whnf_owned(&ir).expect_err("match type-checks pattern first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: pattern,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), pattern_span);

    let ir = lower(r#"builtins.match "a" 1"#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string exists").span;

    let error = eval_whnf_owned(&ir).expect_err("match type-checks string second");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: string,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), string_span);

    for source in [
        r#"builtins.match "[" (builtins.throw "boom")"#,
        r#"builtins.match "[" 1"#,
        r#"let m = builtins.match "["; in m 1"#,
    ] {
        let error =
            eval_whnf_owned(&lower(source)).expect_err("match compiles regex before string");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::RegexCompile { .. }),
            "unexpected error for {source}: {error:?}"
        );
    }

    let ir = lower(r#"builtins.match "[" "x""#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let pattern = args[0];
    let pattern_span = ir.arena.node(pattern).expect("pattern exists").span;

    let error = eval_whnf_owned(&ir).expect_err("match rejects invalid regexes");

    match error.kind() {
        TreeWalkErrorKind::RegexCompile {
            id,
            pattern: rejected,
            ..
        } => {
            assert_eq!(id, pattern);
            assert_eq!(rejected, b"[".to_vec());
        }
        other => panic!("unexpected error kind: {other:?}"),
    }
    assert_eq!(error.span(), pattern_span);

    let ir = lower(r#"builtins.match "" """#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let pattern = args[0];
    let pattern_span = ir.arena.node(pattern).expect("pattern exists").span;

    let error = eval_whnf_owned(&ir).expect_err("match rejects empty regexes");

    match error.kind() {
        TreeWalkErrorKind::RegexCompile {
            id,
            pattern: rejected,
            ..
        } => {
            assert_eq!(id, pattern);
            assert_eq!(rejected, Vec::<u8>::new());
        }
        other => panic!("unexpected error kind: {other:?}"),
    }
    assert_eq!(error.span(), pattern_span);

    let ir = lower(r#"builtins.match "()" """#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let pattern = args[0];
    let pattern_span = ir.arena.node(pattern).expect("pattern exists").span;

    let error = eval_whnf_owned(&ir).expect_err("match rejects empty POSIX groups");

    match error.kind() {
        TreeWalkErrorKind::RegexCompile {
            id,
            pattern: rejected,
            ..
        } => {
            assert_eq!(id, pattern);
            assert_eq!(rejected, b"()".to_vec());
        }
        other => panic!("unexpected error kind: {other:?}"),
    }
    assert_eq!(error.span(), pattern_span);

    let ir = lower(r#"builtins.match "(?:a)" "a""#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let pattern = args[0];
    let pattern_span = ir.arena.node(pattern).expect("pattern exists").span;

    let error = eval_whnf_owned(&ir).expect_err("match rejects Rust-only groups");

    match error.kind() {
        TreeWalkErrorKind::RegexCompile {
            id,
            pattern: rejected,
            ..
        } => {
            assert_eq!(id, pattern);
            assert_eq!(rejected, b"(?:a)".to_vec());
        }
        other => panic!("unexpected error kind: {other:?}"),
    }
    assert_eq!(error.span(), pattern_span);

    let ir = lower(r#"builtins.match "\\d" "1""#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let pattern = args[0];
    let pattern_span = ir.arena.node(pattern).expect("pattern exists").span;

    let error = eval_whnf_owned(&ir).expect_err("match rejects Rust-only escapes");

    match error.kind() {
        TreeWalkErrorKind::RegexCompile {
            id,
            pattern: rejected,
            ..
        } => {
            assert_eq!(id, pattern);
            assert_eq!(rejected, b"\\d".to_vec());
        }
        other => panic!("unexpected error kind: {other:?}"),
    }
    assert_eq!(error.span(), pattern_span);

    for source in [
        r#"builtins.match "a*?" "aaa""#,
        r#"builtins.match "a+?" "aaa""#,
        r#"builtins.match "a??" "aaa""#,
        r#"builtins.match "a{1}?" "aaa""#,
        r#"builtins.match "a{1,}?" "aaa""#,
        r#"builtins.match "a{1,2}?" "aaa""#,
        r#"builtins.match "a|" "a""#,
        r#"builtins.match "|a" "a""#,
        r#"builtins.match "a||b" "a""#,
        r#"builtins.match "(|a)" "a""#,
        r#"builtins.match "(a|)" "a""#,
        r#"builtins.match "\\x61" "a""#,
        r#"builtins.match "\\n" "n""#,
        r#"builtins.match "\\t" "t""#,
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("match rejects invalid regexes");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::RegexCompile { .. }),
            "unexpected error for {source}: {error:?}"
        );
    }
}

#[test]
fn match_primop_rejects_string_context() {
    let ir = lower(r#"builtins.match "a" "a""#);
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let pattern = args[0];
    let string = args[1];
    let pattern_span = ir.arena.node(pattern).expect("pattern exists").span;
    let string_span = ir.arena.node(string).expect("string exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let context_pattern = evaluator
        .heap
        .alloc_string(NixString::new(
            b"a".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");
    let context_free_string = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"a".to_vec()))
        .expect("context-free string allocates");

    let error = evaluator
        .eval_match_primop_value(
            ir.root,
            root.span,
            EvalPrimOpArg::new(pattern, pattern_span, context_pattern),
            EvalPrimOpArg::new(string, string_span, context_free_string),
        )
        .expect_err("match rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: pattern,
            op: "match",
        }
    );
    assert_eq!(error.span(), pattern_span);

    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let context_free_pattern = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"a".to_vec()))
        .expect("context-free string allocates");
    let context_string = evaluator
        .heap
        .alloc_string(NixString::new(
            b"a".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let error = evaluator
        .eval_match_primop_value(
            ir.root,
            root.span,
            EvalPrimOpArg::new(pattern, pattern_span, context_free_pattern),
            EvalPrimOpArg::new(string, string_span, context_string),
        )
        .expect_err("match rejects string argument context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: string,
            op: "match",
        }
    );
    assert_eq!(error.span(), string_span);
}

#[test]
fn split_primop_interleaves_text_and_capture_lists() {
    assert_eq!(
        eval_json_bytes(r#"builtins.split "-" "a-b-c""#),
        br#"["a",[],"b",[],"c"]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "(-)" "a-b-c""#),
        br#"["a",["-"],"b",["-"],"c"]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "x" "abc""#),
        br#"["abc"]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "(a)?b" "b-ab""#),
        br#"["",[null],"-",["a"],""]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"let split = builtins.split "-"; in split "a-b""#),
        br#"["a",[],"b"]"#.to_vec()
    );
    assert_eq!(
        eval_string_bytes(
            r#"let builtins = { split = pattern: value: "shadow"; }; in builtins.split "-" "a-b""#
        ),
        b"shadow"
    );
}

#[test]
fn split_primop_handles_zero_width_matches_like_cpp_nix() {
    assert_eq!(
        eval_json_bytes(r#"builtins.split "a*" "baac""#),
        br#"["",[],"b",[],"",[],"c",[],""]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "(a*)" "baac""#),
        br#"["",[""],"b",["aa"],"",[""],"c",[""],""]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "a?" "bc""#),
        br#"["",[],"b",[],"c",[],""]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "^" "abc""#),
        br#"["",[],"abc"]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "$" "abc""#),
        br#"["abc",[],""]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "^|$" "abc""#),
        br#"["",[],"abc",[],""]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "^|$" "a""#),
        br#"["",[],"a",[],""]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(r#"builtins.split "a*$" "baac""#),
        br#"["baac",[],""]"#.to_vec()
    );
}

#[test]
fn split_primop_matches_regexes_over_bytes_like_cpp_nix() {
    assert_eq!(
        eval(r#"builtins.length (builtins.split "." "éx")"#).as_int(),
        Ok(7)
    );
    assert_eq!(
        eval(
            r#"builtins.stringLength
                    (builtins.elemAt (builtins.elemAt (builtins.split "(.)" "éx") 1) 0)"#
        )
        .as_int(),
        Ok(1)
    );
}

#[test]
fn split_primop_checks_arguments_and_regexes() {
    let ir = lower(r#"builtins.split 1 (builtins.throw "boom")"#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let pattern = args[0];
    let pattern_span = ir.arena.node(pattern).expect("pattern exists").span;

    let error = eval_whnf_owned(&ir).expect_err("split type-checks pattern first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: pattern,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), pattern_span);

    let error = eval_whnf_owned(&lower(
        r#"let split = builtins.split 1; in split (builtins.throw "boom")"#,
    ))
    .expect_err("curried split type-checks pattern first");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    for source in [
        r#"builtins.split "[" (builtins.throw "boom")"#,
        r#"builtins.split "[" 1"#,
        r#"let split = builtins.split "["; in split (builtins.throw "boom")"#,
    ] {
        let error =
            eval_whnf_owned(&lower(source)).expect_err("split compiles regex before string");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::RegexCompile { .. }),
            "unexpected error for {source}: {error:?}"
        );
    }

    let ir = lower(r#"builtins.split "a" 1"#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string exists").span;

    let error = eval_whnf_owned(&ir).expect_err("split type-checks string second");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: string,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), string_span);

    for source in [
        r#"builtins.split "" "abc""#,
        r#"builtins.split "[" "x""#,
        r#"builtins.split "()" """#,
        r#"builtins.split "(?:a)" "a""#,
        r#"builtins.split "\\d" "1""#,
        r#"builtins.split "a|" "a""#,
        r#"builtins.split "|a" "a""#,
        r#"builtins.split "a||b" "a""#,
        r#"builtins.split "(|a)" "a""#,
        r#"builtins.split "(a|)" "a""#,
        r#"builtins.split "\\x61" "a""#,
        r#"builtins.split "\\n" "n""#,
        r#"builtins.split "\\t" "t""#,
        r#"builtins.split "a*?" "aaa""#,
        r#"builtins.split "a+?" "aaa""#,
        r#"builtins.split "a??" "aaa""#,
        r#"builtins.split "a{1}?" "aaa""#,
        r#"builtins.split "a{1,}?" "aaa""#,
        r#"builtins.split "a{1,2}?" "aaa""#,
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("split rejects invalid regexes");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::RegexCompile { .. }),
            "unexpected error for {source}: {error:?}"
        );
    }
}

#[test]
fn split_primop_rejects_string_context() {
    let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src";

    let error = eval_whnf_owned(&lower(&format!(
        r#"builtins.split
                (builtins.appendContext "a" {{ "{path}" = {{ path = true; }}; }})
                "a""#
    )))
    .expect_err("split rejects pattern context");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "split", .. }
    ));

    let error = eval_whnf_owned(&lower(&format!(
        r#"builtins.split
                "a"
                (builtins.appendContext "a" {{ "{path}" = {{ path = true; }}; }})"#
    )))
    .expect_err("split rejects string context");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "split", .. }
    ));
}

#[test]
fn replace_strings_primop_replaces_bytes() {
    assert_eq!(
        eval_string_bytes(
            "builtins.replaceStrings [ \"o\" \"l\" ] [ \"0\" \"L\" ] \"hello world\""
        ),
        b"heLL0 w0rLd"
    );
    assert_eq!(
        eval_string_bytes("builtins.replaceStrings [ \"\" ] [ \"x\" ] \"ab\""),
        b"xaxbx"
    );
    assert_eq!(
        eval_string_bytes("builtins.replaceStrings [ \"a\" \"ab\" ] [ \"X\" \"Y\" ] \"ababa\""),
        b"XbXbX"
    );
    assert_eq!(
        eval_string_bytes("builtins.replaceStrings [ \"ab\" \"a\" ] [ \"Y\" \"X\" ] \"ababa\""),
        b"YYX"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { replaceStrings = from: to: string: \"local\"; }; in builtins.replaceStrings [ \"a\" ] [ \"b\" ] \"a\""
        ),
        b"local"
    );
}

#[test]
fn replace_strings_primop_checks_lengths_before_elements() {
    let ir = lower("builtins.replaceStrings [ (1 / 0) ] [] (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");

    let error = eval_whnf_owned(&ir).expect_err("replaceStrings checks list lengths first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::ReplaceStringsLengthMismatch {
            id: ir.root,
            from_len: 1,
            to_len: 0,
        }
    );
    assert_eq!(error.span(), root.span);
}

#[test]
fn replace_strings_primop_forces_replacements_only_when_used() {
    assert_eq!(
        eval_string_bytes("builtins.replaceStrings [ \"x\" ] [ (1 / 0) ] \"z\""),
        b"z"
    );
    assert_eq!(
        eval_string_bytes("builtins.replaceStrings [ \"x\" ] [ 2 ] \"z\""),
        b"z"
    );
    assert_eq!(
        eval_string_bytes("builtins.replaceStrings [ \"z\" \"x\" ] [ \"y\" (1 / 0) ] \"z\""),
        b"y"
    );

    let ir = lower("builtins.replaceStrings [ \"x\" ] [ (1 / 0) ] \"x\"");
    let error = eval_whnf(&ir).expect_err("used replacement is forced");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. } | TreeWalkErrorKind::Force { .. }
    ));
}

#[test]
fn replace_strings_primop_type_checks_arguments() {
    let ir = lower("builtins.replaceStrings 1 [] \"x\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let from = args[0];
    let from_span = ir.arena.node(from).expect("from argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("from must be a list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: from,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), from_span);

    let ir = lower("builtins.replaceStrings [ 1 ] [ \"x\" ] \"1\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let from = args[0];
    let from_span = ir.arena.node(from).expect("from argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("from elements must be strings");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: from,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), from_span);

    let ir = lower("builtins.replaceStrings [ \"x\" ] [ 1 ] \"x\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let to = args[1];
    let to_span = ir.arena.node(to).expect("to argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("used replacements must be strings");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: to,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), to_span);

    let ir = lower("builtins.replaceStrings [ \"a\" ] [ \"x\" ] { outPath = \"a\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let string = args[2];
    let string_span = ir.arena.node(string).expect("string argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("string argument is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: string,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), string_span);
}

#[test]
fn replace_strings_primop_unions_source_and_used_replacement_contexts() {
    let ir = lower("builtins.replaceStrings [ \"x\" \"z\" ] [ \"used\" \"unused\" ] \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let to = args[1];
    let to_span = ir.arena.node(to).expect("to argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);

    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let used =
        ContextElement::opaque_path(b"/nix/store/used".to_vec()).expect("used context is valid");
    let unused = ContextElement::opaque_path(b"/nix/store/unused".to_vec())
        .expect("unused context is valid");
    let used_value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"USED".to_vec(),
            StringContext::singleton(used.clone()).expect("used context allocates"),
        ))
        .expect("used replacement allocates");
    let unused_value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"UNUSED".to_vec(),
            StringContext::singleton(unused.clone()).expect("unused context allocates"),
        ))
        .expect("unused replacement allocates");
    let patterns = vec![
        ReplaceStringPattern {
            from: b"x".to_vec(),
            replacement: used_value,
        },
        ReplaceStringPattern {
            from: b"z".to_vec(),
            replacement: unused_value,
        },
    ];

    let result = evaluator
        .replace_strings_bytes(
            ir.root,
            root.span,
            to,
            to_span,
            b"prexpost",
            StringContext::singleton(source.clone()).expect("source context allocates"),
            &patterns,
        )
        .expect("replaceStrings evaluates");

    assert_eq!(result.bytes(), b"preUSEDpost");
    assert!(result.context().contains(&source));
    assert!(result.context().contains(&used));
    assert!(!result.context().contains(&unused));
}

#[test]
fn concat_strings_sep_primop_joins_coerced_strings() {
    assert_eq!(eval_string_bytes("builtins.concatStringsSep \",\" []"), b"");
    assert_eq!(
        eval_string_bytes("builtins.concatStringsSep \",\" [ \"a\" ]"),
        b"a"
    );
    assert_eq!(
        eval_string_bytes("builtins.concatStringsSep \",\" [ \"a\" \"b\" \"c\" ]"),
        b"a,b,c"
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.concatStringsSep \",\" [ { outPath = \"a\"; } { __toString = self: \"b\"; } ]"
        ),
        b"a,b"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { concatStringsSep = sep: list: \"local\"; }; in builtins.concatStringsSep \",\" [ \"a\" \"b\" ]"
        ),
        b"local"
    );
}

#[test]
fn concat_strings_sep_primop_checks_arguments_left_to_right() {
    let ir = lower("builtins.concatStringsSep 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let separator = args[0];
    let separator_span = ir
        .arena
        .node(separator)
        .expect("separator argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("separator is checked first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: separator,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), separator_span);

    let ir = lower("builtins.concatStringsSep { outPath = \",\"; } [ \"a\" ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let separator = args[0];
    let separator_span = ir
        .arena
        .node(separator)
        .expect("separator argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("separator is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: separator,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), separator_span);

    let ir = lower("builtins.concatStringsSep \",\" 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("second argument must be a list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.concatStringsSep \",\" [ \"a\" 1 ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("list elements must coerce to strings");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);
}

#[test]
fn concat_strings_sep_primop_unions_separator_and_element_contexts() {
    let ir = lower("builtins.concatStringsSep \",\" []");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);

    let separator = ContextElement::opaque_path(b"/nix/store/separator".to_vec())
        .expect("separator context is valid");
    let element = ContextElement::opaque_path(b"/nix/store/element".to_vec())
        .expect("element context is valid");
    let element_value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"elem".to_vec(),
            StringContext::singleton(element.clone()).expect("element context allocates"),
        ))
        .expect("element string allocates");

    let empty = evaluator
        .concat_strings_sep_values(
            ir.root,
            root.span,
            list,
            list_span,
            b",",
            StringContext::singleton(separator.clone()).expect("separator context allocates"),
            &[],
        )
        .expect("empty concatStringsSep evaluates");

    assert_eq!(empty.bytes(), b"");
    assert!(empty.context().contains(&separator));

    let single = evaluator
        .concat_strings_sep_values(
            ir.root,
            root.span,
            list,
            list_span,
            b",",
            StringContext::singleton(separator.clone()).expect("separator context allocates"),
            &[element_value],
        )
        .expect("single-element concatStringsSep evaluates");

    assert_eq!(single.bytes(), b"elem");
    assert!(single.context().contains(&separator));
    assert!(single.context().contains(&element));
}

#[test]
fn substring_primop_slices_coerced_string_bytes() {
    assert_eq!(eval_string_bytes("builtins.substring 1 2 \"abcd\""), b"bc");
    assert_eq!(eval_string_bytes("builtins.substring 10 2 \"abcd\""), b"");
    assert_eq!(
        eval_string_bytes("builtins.substring 1 999 \"abcd\""),
        b"bcd"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 1 (-1) \"abcd\""),
        b"bcd"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 2147483647 1 \"abcd\""),
        b""
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 4294967296 1 \"abcd\""),
        b"a"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 4294967297 1 \"abcd\""),
        b"b"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring (-9223372036854775807) 1 \"abcd\""),
        b"b"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 0 4294967296 \"abcd\""),
        b""
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 0 4294967298 \"abcd\""),
        b"ab"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 0 (-4294967295) \"abcd\""),
        b"a"
    );
    assert_eq!(
        eval_string_bytes("builtins.substring 1 2 { outPath = \"abcd\"; }"),
        b"bc"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { substring = start: len: value: \"shadow\"; }; in builtins.substring 1 2 \"abcd\""
        ),
        b"shadow"
    );
}

#[test]
fn substring_primop_checks_arguments_left_to_right() {
    let ir = lower("builtins.substring true (1 / 0) \"abcd\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let start = args[0];
    let start_span = ir.arena.node(start).expect("start exists").span;

    let error = eval_whnf(&ir).expect_err("substring type-checks start first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: start,
            expected: "int",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), start_span);

    let ir = lower("builtins.substring (-1) (1 / 0) \"abcd\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let start = args[0];
    let start_span = ir.arena.node(start).expect("start exists").span;

    let error = eval_whnf(&ir).expect_err("negative start rejects before length");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::NegativeSubstringStart {
            id: start,
            start: -1,
        }
    );
    assert_eq!(error.span(), start_span);

    let ir = lower("builtins.substring 2147483648 1 \"abcd\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let start = args[0];
    let start_span = ir.arena.node(start).expect("start exists").span;

    let error = eval_whnf(&ir).expect_err("oversized start matches Nix start rejection");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::NegativeSubstringStart {
            id: start,
            start: -2_147_483_648,
        }
    );
    assert_eq!(error.span(), start_span);

    let ir = lower("builtins.substring 4294967295 1 \"abcd\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let start = args[0];
    let start_span = ir.arena.node(start).expect("start exists").span;

    let error = eval_whnf(&ir).expect_err("wrapped negative start rejects");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::NegativeSubstringStart {
            id: start,
            start: -1,
        }
    );
    assert_eq!(error.span(), start_span);

    let ir = lower("builtins.substring 1 true (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let len = args[1];
    let len_span = ir.arena.node(len).expect("length exists").span;

    let error = eval_whnf(&ir).expect_err("substring type-checks length before string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: len,
            expected: "int",
            actual: ValueTag::Bool,
        }
    );
    assert_eq!(error.span(), len_span);

    let ir = lower("builtins.substring 1 (-1) (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let string = args[2];
    let string_span = ir.arena.node(string).expect("string exists").span;

    let error = eval_whnf(&ir).expect_err("accepted negative length still forces string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: string }
    );
    assert_eq!(error.span(), string_span);
}

#[test]
fn base_name_and_dir_of_primops_split_path_strings() {
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"/a/b\""), b"b");
    assert_eq!(eval_string_bytes("builtins.dirOf \"/a/b\""), b"/a");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"\""), b"");
    assert_eq!(eval_string_bytes("builtins.dirOf \"\""), b".");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"/\""), b"");
    assert_eq!(eval_string_bytes("builtins.dirOf \"/\""), b"/");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"abc\""), b"abc");
    assert_eq!(eval_string_bytes("builtins.dirOf \"abc\""), b".");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"a/b/c\""), b"c");
    assert_eq!(eval_string_bytes("builtins.dirOf \"a/b/c\""), b"a/b");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"/a/b/\""), b"b");
    assert_eq!(eval_string_bytes("builtins.dirOf \"/a/b/\""), b"/a/b");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"a//\""), b"");
    assert_eq!(eval_string_bytes("builtins.dirOf \"a//\""), b"a");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"a//b\""), b"b");
    assert_eq!(eval_string_bytes("builtins.dirOf \"a//b\""), b"a");
    assert_eq!(eval_string_bytes("builtins.baseNameOf \"//a\""), b"a");
    assert_eq!(eval_string_bytes("builtins.dirOf \"//a\""), b"//");
}

#[test]
fn base_name_and_dir_of_primops_coerce_and_shadow() {
    assert_eq!(
        eval_string_bytes("builtins.baseNameOf { outPath = \"/a/b\"; }"),
        b"b"
    );
    assert_eq!(
        eval_string_bytes("builtins.dirOf { __toString = self: \"/a/b\"; }"),
        b"/a"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { baseNameOf = value: \"shadow\"; }; in builtins.baseNameOf \"/a/b\""
        ),
        b"shadow"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { dirOf = value: \"shadow\"; }; in builtins.dirOf \"/a/b\""
        ),
        b"shadow"
    );
}

#[test]
fn parse_drv_name_primop_splits_name_and_version() {
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-1.2\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-1.2\").version"),
        b"1.2"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-bar\").name"),
        b"foo-bar"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-bar\").version"),
        b""
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo--1\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo--1\").version"),
        b"-1"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-.1\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-.1\").version"),
        b".1"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-_1\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-_1\").version"),
        b"_1"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-A-1\").name"),
        b"foo-A"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-A-1\").version"),
        b"1"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-é-1\").name"),
        b"foo"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-é-1\").version"),
        "é-1".as_bytes()
    );
    assert_eq!(eval_string_bytes("(builtins.parseDrvName \"\").name"), b"");
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-\").name"),
        b"foo-"
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"foo-\").version"),
        b""
    );
    assert_eq!(
        eval_string_bytes("(builtins.parseDrvName \"-1\").version"),
        b"1"
    );
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames (builtins.parseDrvName \"foo-1\")"),
        vec![b"name".to_vec(), b"version".to_vec()]
    );
    assert_eq!(
            eval("let builtins = { parseDrvName = x: { name = \"local\"; version = \"\"; }; }; in builtins.parseDrvName \"foo-1\" == { name = \"local\"; version = \"\"; }")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn parse_drv_name_primop_requires_a_string() {
    let ir = lower("builtins.parseDrvName 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("parseDrvName requires a string");

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
fn parse_drv_name_primop_rejects_string_context() {
    let ir = lower("builtins.parseDrvName \"foo-1\"");
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
        .expect("parseDrvName argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"foo-1".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let error = evaluator
        .eval_parse_drv_name_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("parseDrvName rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "parseDrvName",
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn split_version_primop_tokenizes_components() {
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"1.2.3\""),
        vec![b"1".to_vec(), b"2".to_vec(), b"3".to_vec()]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"1.0pre2\""),
        vec![b"1".to_vec(), b"0".to_vec(), b"pre".to_vec(), b"2".to_vec()]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"foo-1.2_bar\""),
        vec![
            b"foo".to_vec(),
            b"1".to_vec(),
            b"2".to_vec(),
            b"_bar".to_vec()
        ]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"\""),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \".1..2-\""),
        vec![b"1".to_vec(), b"2".to_vec()]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"1+2~pre\""),
        vec![
            b"1".to_vec(),
            b"+".to_vec(),
            b"2".to_vec(),
            b"~pre".to_vec()
        ]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"pre123post45\""),
        vec![
            b"pre".to_vec(),
            b"123".to_vec(),
            b"post".to_vec(),
            b"45".to_vec()
        ]
    );
    assert_eq!(
        eval_list_string_bytes("builtins.splitVersion \"é1β2\""),
        vec![
            "é".as_bytes().to_vec(),
            b"1".to_vec(),
            "β".as_bytes().to_vec(),
            b"2".to_vec()
        ]
    );
    assert_eq!(
            eval("let builtins = { splitVersion = x: [ \"local\" ]; }; in builtins.splitVersion \"1.0\" == [ \"local\" ]")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn split_version_primop_requires_a_string() {
    let ir = lower("builtins.splitVersion 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("splitVersion requires a string");

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
fn split_version_primop_rejects_string_context() {
    let ir = lower("builtins.splitVersion \"1.0\"");
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
        .expect("splitVersion argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"1.0".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let error = evaluator
        .eval_split_version_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("splitVersion rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "splitVersion",
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn hash_string_primop_hashes_bytes() {
    assert_eq!(
        eval_string_bytes("builtins.hashString \"md5\" \"abc\""),
        b"900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        eval_string_bytes("builtins.hashString \"sha1\" \"abc\""),
        b"a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        eval_string_bytes("builtins.hashString \"sha256\" \"abc\""),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
            eval_string_bytes("builtins.hashString \"sha512\" \"abc\""),
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { hashString = type: value: \"local\"; }; in builtins.hashString \"sha256\" \"abc\""
        ),
        b"local"
    );
}

#[test]
fn first_class_binary_builtin_selects_are_curried() {
    assert_eq!(
        eval_string_bytes("let h = builtins.hashString \"sha256\"; in h \"abc\""),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(eval("let add = builtins.add 1; in add 2").as_int(), Ok(3));
    assert_eq!(
        eval("let less = builtins.lessThan 1; in less 2").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let cmp = builtins.compareVersions \"1.2\"; in cmp \"1.10\"").as_int(),
        Ok(-1)
    );
    assert_eq!(
        eval_string_bytes("let get = builtins.getAttr \"a\"; in get { a = \"x\"; }"),
        b"x"
    );
    assert_eq!(
        eval("let has = builtins.hasAttr \"a\"; in has { a = 1; }").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(
            "let remove = builtins.removeAttrs { a = 1; b = 2; }; in remove [ \"a\" ] == { b = 2; }"
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
            eval("let intersect = builtins.intersectAttrs { a = 0; c = 0; }; in intersect { a = 1; b = 2; } == { a = 1; }").as_bool(),
            Ok(true)
        );
    assert_eq!(
        eval_list_ints(
            "let cat = builtins.catAttrs \"a\"; in cat [ { a = 1; } { b = 2; } { a = 3; } ]"
        ),
        vec![1, 3]
    );
    assert_eq!(
        eval_string_bytes("let join = builtins.concatStringsSep \",\"; in join [ \"a\" \"b\" ]"),
        b"a,b"
    );
    assert_eq!(
        eval("let s = builtins.seq (1 / 0); in builtins.isFunction s").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let s = builtins.seq 1; in builtins.length (s [ 1 (1 / 0) ])").as_int(),
        Ok(2)
    );
}

#[test]
fn first_class_binary_builtin_type_checks_left_before_right() {
    for (source, expected, actual) in [
        (
            "let cmp = builtins.compareVersions 1; in cmp (1 / 0)",
            "string",
            ValueTag::Int,
        ),
        (
            "let and = builtins.bitAnd true; in and (1 / 0)",
            "int",
            ValueTag::Bool,
        ),
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("left argument is rejected");

        let TreeWalkErrorKind::Type {
            expected: found_expected,
            actual: found_actual,
            ..
        } = error.kind()
        else {
            panic!("expected a type error for {source}, got {error:?}");
        };
        assert_eq!(found_expected, expected, "{source}");
        assert_eq!(found_actual, actual, "{source}");
    }
}

#[test]
fn first_class_ternary_builtin_selects_are_curried() {
    assert_eq!(
        eval("let fold = builtins.foldl' builtins.add; sum = fold 0; in sum [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval_string_bytes("let slice = builtins.substring 1; take2 = slice 2; in take2 \"abcd\""),
        b"bc"
    );
    assert_eq!(
        eval_string_bytes(
            "let replace = builtins.replaceStrings [ \"a\" ]; swap = replace [ \"b\" ]; in swap \"a\""
        ),
        b"b"
    );
}

#[test]
fn hash_string_primop_hashes_context_bearing_string_bytes() {
    let ir = lower("builtins.hashString \"sha256\" \"abc\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"abc".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_hash_string_primop_with_string_value(
            ir.root,
            root.span,
            algorithm,
            string,
            string_span,
            value,
        )
        .expect("hashString evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result is a string");

    assert_eq!(
        string.bytes(),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(!string.has_context());
}

#[test]
fn hash_string_primop_rejects_context_bearing_algorithm() {
    let ir = lower("builtins.hashString \"sha256\" (1 / 0)");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"sha256".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing algorithm allocates");

    let error = evaluator
        .eval_hash_algorithm(algorithm, algorithm_span, value, "hashString")
        .expect_err("hashString rejects algorithm string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: algorithm,
            op: "hashString",
        }
    );
    assert_eq!(error.span(), algorithm_span);
}

#[test]
fn hash_string_primop_checks_algorithm_before_string() {
    let ir = lower("builtins.hashString \"bad\" (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("unknown algorithm is rejected first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"bad".to_vec(),
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let ir = lower("builtins.hashString \"SHA256\" \"abc\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];

    let error = eval_whnf_owned(&ir).expect_err("algorithm names are case-sensitive");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"SHA256".to_vec(),
        }
    );
}

#[test]
fn hash_string_primop_type_checks_arguments() {
    let ir = lower("builtins.hashString 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("algorithm must be a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: algorithm,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let ir = lower("builtins.hashString \"sha256\" { outPath = \"abc\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string exists").span;

    let error = eval_whnf_owned(&ir).expect_err("string argument is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: string,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), string_span);
}

#[test]
fn convert_hash_primop_converts_formats() {
    let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base64\"; }}"
        )),
        b"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"nix32\"; }}"
        )),
        b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base32\"; }}"
        )),
        b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"sri\"; }}"
        )),
        b"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"sha256:{sha256}\"; toHashFormat = \"base16\"; }}"
        )),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = builtins.hashString \"md5\" \"abc\"; hashAlgo = \"md5\"; toHashFormat = \"nix32\"; }"
        ),
        b"3jgzhjhz9zjvbb0kyj7jc500ch"
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = builtins.hashString \"sha1\" \"abc\"; hashAlgo = \"sha1\"; toHashFormat = \"base64\"; }"
        ),
        b"qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
    );
    assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = builtins.hashString \"sha512\" \"abc\"; hashAlgo = \"sha512\"; toHashFormat = \"nix32\"; }"
            ),
            b"2gs8k559z4rlahfx0y688s49m2vvszylcikrfinm30ly9rak69236nkam5ydvly1ai7xac99vxfc4ii84hawjbk876blyk1jfhkbbyx"
        );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { convertHash = args: \"local\"; }; in builtins.convertHash { hash = 1 / 0; }"
        ),
        b"local"
    );
}

#[test]
fn convert_hash_primop_can_be_selected_as_a_function() {
    assert_eq!(
        eval_string_bytes(
            "let convert = builtins.convertHash; in convert { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn convert_hash_primop_checks_arguments_in_nix_order() {
    let ir = lower("builtins.convertHash 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("argument must be an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = 1 / 0; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
    ))
    .expect_err("hash is forced first");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
    ))
    .expect_err("hashAlgo is forced second");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = 1 / 0; }",
    ))
    .expect_err("toHashFormat is forced third");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn convert_hash_primop_reports_missing_attributes() {
    let ir = lower("builtins.convertHash { hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("convertHash requires hash");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing hash attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(evaluator.symbols.resolve(symbol), Some(b"hash".as_slice()));

    let ir = lower(
        "builtins.convertHash { hash = builtins.hashString \"sha256\" \"abc\"; hashAlgo = \"sha256\"; }",
    );
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("convertHash requires toHashFormat");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing toHashFormat attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(
        evaluator.symbols.resolve(symbol),
        Some(b"toHashFormat".as_slice())
    );
}

#[test]
fn convert_hash_primop_requires_direct_strings() {
    let ir = lower(
        "builtins.convertHash { hash = { outPath = \"abc\"; }; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
    );
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("hash is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = null; toHashFormat = \"base16\"; }",
    ))
    .expect_err("hashAlgo must be a string when present");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = { outPath = \"base16\"; }; }",
        ))
        .expect_err("toHashFormat is not coerced");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Attrs,
            ..
        }
    ));
}

#[test]
fn convert_hash_primop_rejects_invalid_hashes() {
    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"bad\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("unknown algorithm is rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm { algorithm, .. }
            if algorithm.as_slice() == b"bad"
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"bad\"; }",
    ))
    .expect_err("unknown format is rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashFormat { format, .. }
            if format.as_slice() == b"bad"
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("untyped hashes require hashAlgo");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashAlgorithmRequired { hash, .. }
            if hash.as_slice() == b"abc"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"md5\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("typed hashes must agree with hashAlgo");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashAlgorithmMismatch { expected, .. }
            if expected.as_slice() == b"md5"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("short hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashWrongLength { hash, algorithm, .. }
            if hash.as_slice() == b"abc" && algorithm.as_slice() == b"sha256"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid hex hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidBase16Hash { .. }
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"????????????????????????????????????????????\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid base64 hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidBase64Hash { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"sha256-invalid\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("invalid SRI hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidSriHash { .. }
    ));
}

#[test]
fn placeholder_primop_matches_cpp_nix_hash_scheme() {
    assert_eq!(
        eval_string_bytes(r#"builtins.placeholder "out""#),
        b"/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.placeholder "dev""#),
        b"/02qcpld1y6xhs5gz9bchpxaw0xdhmsp5dv88lh25r2ss44kh8dxz"
    );
    assert_eq!(
        eval("builtins.stringLength (builtins.placeholder \"out\")").as_int(),
        Ok(53)
    );
    assert_eq!(
        eval_string_bytes(r#"let p = builtins.placeholder; in p "out""#),
        b"/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9"
    );
    assert_eq!(
        eval_string_bytes(
            r#"let builtins = { placeholder = output: "local"; }; in builtins.placeholder "out""#
        ),
        b"local"
    );
}

#[test]
fn placeholder_primop_requires_context_free_string_output() {
    let ir = lower("builtins.placeholder 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("placeholder argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("placeholder output must be a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"out".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing output allocates");

    let error = evaluator
        .eval_placeholder_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("placeholder rejects output string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "placeholder",
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        r#"builtins.placeholder (builtins.appendContext "out" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
            })"#,
    ))
    .expect_err("placeholder rejects context-bearing output expressions");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "placeholder",
            ..
        }
    ));
}

#[test]
fn path_literals_remain_paths_until_json_store_coercion() {
    let (dir, path) = temp_file_with_bytes("path-literal", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_string_bytes(&format!("builtins.typeOf {path}")),
        b"path"
    );
    assert_eq!(eval(&format!("builtins.isPath {path}")).as_bool(), Ok(true));
    assert_eq!(eval(&format!("{path} == {path}")).as_bool(), Ok(true));
    assert_eq!(
        eval_string_bytes(&format!("builtins.toJSON {path}")),
        br#""/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt""#
    );

    let ir = lower("./relative-file");
    let path_span = ir.arena.node(ir.root).expect("path exists").span;
    let error = eval_whnf_owned(&ir).expect_err("relative path literals need a source base");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathNotAbsolute {
            id: ir.root,
            path: b"./relative-file".to_vec(),
        }
    );
    assert_eq!(error.span(), path_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn relative_path_literals_resolve_against_path_literal_base() {
    let dir = unique_temp_dir("relative-path-literals");
    let base = dir.join("base");
    fs::create_dir(&base).expect("source base directory creates");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("./foo", options.clone()),
        base.join("foo").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("../bar", options.clone()),
        dir.join("bar").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("foo/bar", options.clone()),
        base.join("foo/bar").as_os_str().as_bytes()
    );
    let mut expected_trace = b"trace: [ ".to_vec();
    expected_trace.extend_from_slice(base.join("foo").as_os_str().as_bytes());
    expected_trace.extend_from_slice(b" ]\n");
    assert_eq!(
        eval_captured_stderr_with_options("builtins.trace [ ./foo ] null", options.clone()),
        expected_trace
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.typeOf foo/bar", options),
        b"path"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn dot_slash_dot_resolves_to_path_literal_base() {
    let dir = unique_temp_dir("dot-slash-dot-path");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(dir.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("./.", options.clone()),
        dir.as_os_str().as_bytes()
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.typeOf ./.", options),
        b"path"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_literals_normalize_dot_and_parent_components() {
    let dir = unique_temp_dir("path-literal-normalization");
    let base = dir.join("base");
    fs::create_dir(&base).expect("source base directory creates");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("foo/./bar", options.clone()),
        base.join("foo/bar").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("foo/../bar", options.clone()),
        base.join("bar").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("./foo/.", options.clone()),
        base.join("foo").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options("./foo/..", options),
        base.as_os_str().as_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn absolute_path_literals_are_absolute_path_values() {
    assert_eq!(
        eval_path_bytes_with_options("/etc/foo", TreeWalkOptions::new()),
        b"/etc/foo"
    );
    assert_eq!(eval_string_bytes("builtins.typeOf /etc/foo"), b"path");
    assert_eq!(eval("builtins.isPath /etc/foo").as_bool(), Ok(true));
}

#[test]
fn home_relative_path_literals_use_configured_home_outside_pure_eval() {
    let dir = unique_temp_dir("home-relative-path-literals");
    let home = dir.join("home");
    let source_base = dir.join("source");
    fs::create_dir(&home).expect("home directory creates");
    fs::create_dir(&source_base).expect("source base directory creates");

    let mut options = TreeWalkOptions::with_home_dir(home.as_os_str().as_bytes().to_vec())
        .expect("home directory configures");
    options
        .set_path_literal_base(source_base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("~/foo", options.clone()),
        home.join("foo").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.typeOf ~/foo", options.clone()),
        b"path"
    );
    assert_eq!(
        eval_with_options("builtins.isPath ~/foo", options).as_bool(),
        Ok(true)
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn home_relative_path_literals_reject_pure_eval_and_missing_home() {
    let mut pure_options = TreeWalkOptions::with_home_dir(b"/tmp/aos-home".to_vec())
        .expect("home directory configures");
    pure_options.set_eval_mode(EvalMode::Pure);
    let error = eval_whnf_owned_with_options(&lower("~/foo"), pure_options)
        .expect_err("pure evaluation rejects home path literals");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HomePathNotAllowed {
            path,
            mode: EvalMode::Pure,
            ..
        } if path.as_slice() == b"~/foo"
    ));

    let error = eval_whnf_owned_with_options(&lower("~/foo"), TreeWalkOptions::new())
        .expect_err("home path literals need a configured home directory");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HomePathUnavailable { path, .. }
            if path.as_slice() == b"~/foo"
    ));

    let options = TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/tmp/aos-home".to_vec());
    let error = eval_whnf_owned_with_options(&lower("~/foo"), options)
        .expect_err("HOME environment configuration does not drive home path expansion");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HomePathUnavailable { path, .. }
            if path.as_slice() == b"~/foo"
    ));
}

#[test]
fn relative_path_interpolation_resolves_against_path_literal_base() {
    let dir = unique_temp_dir("relative-path-interpolation");
    let base = dir.join("base");
    fs::create_dir(&base).expect("source base directory creates");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options(r#"./a/${"b"}/c"#, options.clone()),
        base.join("a/b/c").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_string_bytes_with_options(r#"builtins.typeOf (./a/${"b"}/c)"#, options.clone()),
        b"path"
    );
    assert_eq!(
        eval_with_options(r#"builtins.isPath (./a/${"b"}/c)"#, options.clone()).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_path_bytes_with_options(r#"./a/${"../b"}/c"#, options.clone()),
        base.join("b/c").as_os_str().as_bytes()
    );
    assert_eq!(
        eval_path_bytes_with_options(r#"./a/${/x}/y"#, options),
        base.join("a/x/y").as_os_str().as_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn slash_whitespace_disambiguates_division_from_path_literals() {
    let dir = unique_temp_dir("slash-path-disambiguation");
    let base = dir.join("base");
    fs::create_dir(&base).expect("source base directory creates");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(base.as_os_str().as_bytes().to_vec())
        .expect("path-literal base configures");

    assert_eq!(
        eval_path_bytes_with_options("1/2", options.clone()),
        base.join("1/2").as_os_str().as_bytes()
    );

    for source in ["1/ 2", "1 / 2", "1\t/\t2", "1\n/\n2", "1/*x*/ / 2"] {
        assert_eq!(
            eval_with_options(source, options.clone()).as_int(),
            Ok(0),
            "{source:?} should parse as integer division"
        );
    }

    let error = eval_whnf_owned_with_options(&lower("1 /2"), options.clone())
        .expect_err("whitespace before an absolute path parses as application");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Int,
            ..
        }
    ));
    let error = eval_whnf_owned_with_options(&lower("1/**//2"), options)
        .expect_err("comment before an absolute path parses as application");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Int,
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_interpolation_copies_sources_to_store_contexts() {
    let (dir, path) = temp_file_with_bytes("path-interpolation", b"abc");
    let path = path_source(&path);
    let store_path = "/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt";
    let context_json = br#"{"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt":{"path":true}}"#;

    assert_eq!(
        eval_string_bytes(&format!("\"${{{path}}}\"")),
        store_path.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON (builtins.getContext \"${{{path}}}\")"
        )),
        context_json
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON (builtins.getContext (builtins.toJSON {path}))"
        )),
        context_json
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON (builtins.getContext (builtins.toString {path}))"
        )),
        b"{}"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON {{ nested = [ {{ path = {path}; }} ]; }}"
        )),
        br#"{"nested":[{"path":"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt"}]}"#
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_coercion_context_is_observed_by_derivation_strict_as_input_src() {
    let (dir, path) = temp_file_with_bytes("path-context-input-src", b"abc");
    let path = path_source(&path);
    let source = format!(
        r#"let
                 d = derivationStrict {{
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                   src = {path};
                 }};
               in {{
                 drvPath = d.drvPath;
                 out = d.out;
                 srcContext = builtins.getContext "${{{path}}}";
               }}"#
    );

    assert_eq!(
            eval_json_bytes(&source),
            br#"{"drvPath":"/nix/store/jwfqrwzg1mpqn9fc0x8g3ml72nisim2i-x.drv","out":"/nix/store/z6ky3vpva494v17vnc8xrzx6rv8nrycr-x","srcContext":{"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt":{"path":true}}}"#.to_vec()
        );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_store_coercion_serializes_source_trees_and_symlinks() {
    let dir = unique_temp_dir("path-source-tree");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("tree directory creates");
    fs::write(tree.join("data.txt"), b"abc").expect("tree file writes");
    std::os::unix::fs::symlink("data.txt", tree.join("link.txt")).expect("tree symlink creates");
    fs::write(dir.join("data.txt"), b"abc").expect("symlink target writes");
    let link = dir.join("link.txt");
    std::os::unix::fs::symlink("data.txt", &link).expect("temp symlink creates");
    let executable = dir.join("tool.sh");
    fs::write(&executable, b"abc").expect("executable file writes");
    let mut permissions = fs::metadata(&executable)
        .expect("executable file stats")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("executable mode sets");
    let tree = path_source(&tree);
    let link = path_source(&link);
    let executable = path_source(&executable);

    assert_eq!(
        eval_string_bytes(&format!("\"${{{tree}}}\"")),
        b"/nix/store/nl7y1ns16db5c34f34mlfizf6g3lxll3-tree"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toJSON {tree}")),
        br#""/nix/store/nl7y1ns16db5c34f34mlfizf6g3lxll3-tree""#
    );
    assert_eq!(
        eval_string_bytes(&format!("\"${{{link}}}\"")),
        b"/nix/store/r8q4lajdsk010slx81y3yc6zzclarwpl-link.txt"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toJSON {link}")),
        br#""/nix/store/r8q4lajdsk010slx81y3yc6zzclarwpl-link.txt""#
    );
    assert_eq!(
        eval_string_bytes(&format!("\"${{{executable}}}\"")),
        b"/nix/store/4fgv55agm9sz9yxqvqbm8b5s483bmldn-tool.sh"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_primop_builds_source_store_paths_and_context() {
    let (dir, path) = temp_file_with_bytes("path-primop", b"abc");
    let path = path_source(&path);
    let store_path = b"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt";
    let renamed = b"/nix/store/lmv1fx64qbwh9yca6xv9a42fb3q3a1jx-renamed";

    assert_eq!(
        eval_string_bytes(&format!("builtins.path {{ path = {path}; }}")),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {}; }}",
            nix_string_literal(&path)
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {path}; name = \"renamed\"; }}"
        )),
        renamed
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let p = builtins.path; in p {{ path = {path}; name = \"renamed\"; }}"
        )),
        renamed
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "builtins.getContext (builtins.path {{ path = {path}; }})"
        )),
        br#"{"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt":{"path":true}}"#.to_vec()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_fetches_file_urls_and_records_context() {
    let (dir, path) = temp_file_with_bytes("fetchurl", b"abc");
    let url = format!("file://{}", path_source(&path));
    let url = nix_string_literal(&url);
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let sri = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
    let nix32 = "1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s";
    let store_path = b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt";
    let renamed = b"/nix/store/hy1mq1p855x9m96mxz4b9qaf1w0jjl5q-renamed";

    assert_eq!(
        eval_string_bytes(&format!("builtins.fetchurl {url}")),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}"
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"{sri}\"; }}"
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"{nix32}\"; }}"
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let fetchurl = builtins.fetchurl; in fetchurl {{ url = {url}; sha256 = \"{digest}\"; name = \"renamed\"; }}"
        )),
        renamed
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "builtins.getContext (builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }})"
        )),
        br#"{"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt":{"path":true}}"#.to_vec()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let p = builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}; in builtins.readFile p"
        )),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let p = builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}; in builtins.hashFile \"sha256\" p"
        )),
        digest.as_bytes()
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "let p = builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}; in [ (builtins.pathExists p) (builtins.readFileType p) ]"
        )),
        br#"[true,"regular"]"#.to_vec()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_uses_raw_url_basename_for_default_name() {
    let (dir, path) = temp_file_with_bytes("fetchurl-query", b"abc");
    let url = format!("file://{}?foo=bar", path_source(&path));
    let url = nix_string_literal(&url);

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; }}"
        )),
        b"/nix/store/cnsr0sbn6xzksm6fa7dh81a1d2yxx0fk-data.txt?foo=bar"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_rejects_invalid_arguments() {
    let (dir, path) = temp_file_with_bytes("fetchurl-invalid", b"abc");
    let url = format!("file://{}", path_source(&path));
    let url = nix_string_literal(&url);

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("hash mismatch rejects fetchurl");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlHashMismatch { .. }
    ));

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"\"; }}"
    ));
    let mut evaluator = TreeWalk::new(&ir);
    let error = evaluator
        .eval_root()
        .expect_err("empty fetchurl hash warns and then mismatches real content");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlHashMismatch { expected, .. }
            if expected.as_slice() == [0_u8; 32]
    ));
    assert_eq!(evaluator.warning_output().len(), 1);
    assert_warning_output(
        evaluator
            .warning_output()
            .first()
            .expect("warning output exists"),
        EMPTY_FETCHURL_SHA256_WARNING,
    );

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; bogus = 1; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("unknown fetchurl attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchUrlAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let ir = lower(
        r#"builtins.fetchurl { sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; }"#,
    );
    let error = eval_whnf_owned(&ir).expect_err("missing url rejects fetchurl");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; name = \"bad/name\"; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("invalid store name rejects fetchurl");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlStoreName { .. }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_obeys_eval_mode_gates() {
    let (dir, path) = temp_file_with_bytes("fetchurl-mode", b"abc");
    let path = path_source(&path);
    let url = nix_string_literal(&format!("file://{path}"));
    let source = format!("builtins.fetchurl {url}");

    let error = eval_whnf_owned_with_options(
        &lower(&source),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure eval rejects unpinned fetchurl before URL access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlHashRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; }}"
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Pure),
        ),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt"
    );

    let error = eval_whnf_owned_with_options(
            &lower(
                r#"builtins.fetchurl { url = "https://cache.example/data.txt"; sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; }"#,
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
        )
        .expect_err("restricted eval rejects disallowed network fetchurl before network access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_fetches_http_urls_as_identity_bytes() {
    let (url, body_hash, handle) = gzip_encoded_http_fixture("/data.txt", b"abc");
    let url = nix_string_literal(&url);
    let store_dir = unique_temp_dir("fetchurl-http-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                r#"
                let p = builtins.fetchurl {{
                  url = {url};
                  name = "http-identity-data";
                  sha256 = "{body_hash}";
                }};
                in builtins.hashFile "sha256" p
                "#
            ),
            options,
        ),
        body_hash.as_bytes()
    );
    fs::remove_dir_all(store_dir).expect("store temp directory removes");

    assert_http_fixture_requested_identity(
        handle.join().expect("HTTP fixture thread completes"),
        "fetchurl",
    );
}

#[test]
fn fetchurl_primop_reuses_materialized_fixed_output_paths_before_fetching() {
    let (dir, path) = temp_file_with_bytes("fetchurl-reuse", b"abc");
    let path = path_source(&path);
    let url = nix_string_literal(&format!("file://{path}"));
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let expected_path = String::from_utf8(eval_string_bytes(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; name = \"cached\"; }}"
    )))
    .expect("store paths are UTF-8");

    let pure_source = format!(
        r#"[
              (builtins.fetchurl {{ url = {url}; sha256 = "{digest}"; name = "cached"; }})
              (builtins.fetchurl {{ url = "https://example.invalid/missing"; sha256 = "{digest}"; name = "cached"; }})
            ]"#
    );
    let pure_options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
    assert_eq!(
        eval_json_bytes_with_options(&pure_source, pure_options),
        format!(r#"["{expected_path}","{expected_path}"]"#).into_bytes()
    );

    let restricted_source = format!(
        r#"[
              (builtins.fetchurl {{ url = {url}; sha256 = "{digest}"; name = "cached"; }})
              (builtins.fetchurl {{ url = "https://cache.example/missing"; sha256 = "{digest}"; name = "cached"; }})
            ]"#
    );
    let mut restricted_options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_path(path.as_bytes().to_vec())
        .expect("allowed path accepts absolute path");
    restricted_options
        .add_allowed_uri(b"https://cache.example/".to_vec())
        .expect("allowed URI prefix configures");
    assert_eq!(
        eval_json_bytes_with_options(&restricted_source, restricted_options),
        format!(r#"["{expected_path}","{expected_path}"]"#).into_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_rejects_reuse_through_restricted_file_url_policy() {
    let (allowed_dir, allowed_path) = temp_file_with_bytes("fetchurl-allowed", b"abc");
    let (blocked_dir, blocked_path) = temp_file_with_bytes("fetchurl-blocked", b"abc");
    let allowed_path = path_source(&allowed_path);
    let blocked_path = path_source(&blocked_path);
    let allowed_url = nix_string_literal(&format!("file://{allowed_path}"));
    let blocked_url = nix_string_literal(&format!("file://{blocked_path}"));
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let source = format!(
        r#"builtins.toJSON [
              (builtins.fetchurl {{ url = {allowed_url}; sha256 = "{digest}"; name = "cached"; }})
              (builtins.fetchurl {{ url = {blocked_url}; sha256 = "{digest}"; name = "cached"; }})
            ]"#
    );
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(allowed_path.as_bytes().to_vec())
        .expect("allowed path accepts absolute path");

    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("restricted file URL policy is checked before fixed-output reuse");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            path,
            mode: EvalMode::Restricted,
            ..
        } if path.as_slice() == blocked_path.as_bytes()
    ));

    fs::remove_dir_all(allowed_dir).expect("allowed temp directory removes");
    fs::remove_dir_all(blocked_dir).expect("blocked temp directory removes");
}

#[test]
fn fetchurl_primop_reuses_existing_configured_store_paths() {
    let store_dir = unique_temp_dir("fetchurl-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let (source_dir, source_path) = temp_file_with_bytes("fetchurl-existing-store", b"abc");
    let source_url = nix_string_literal(&format!("file://{}", path_source(&source_path)));
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let expected_path = eval_string_bytes_with_options(
        &format!(
            r#"builtins.fetchurl {{ url = {source_url}; sha256 = "{digest}"; name = "cached"; }}"#
        ),
        options.clone(),
    );
    let expected_path_text = std::str::from_utf8(&expected_path)
        .expect("store path is UTF-8")
        .to_owned();
    let expected_path_buf = PathBuf::from(expected_path_text.clone());
    fs::create_dir_all(
        expected_path_buf
            .parent()
            .expect("store path has parent directory"),
    )
    .expect("store directory creates");
    fs::write(&expected_path_buf, b"abc").expect("existing store path writes");
    options.set_eval_mode(EvalMode::Pure);

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                r#"builtins.fetchurl {{ url = "https://example.invalid/missing"; sha256 = "{digest}"; name = "cached"; }}"#
            ),
            options,
        ),
        expected_path,
    );

    fs::remove_dir_all(source_dir).expect("source temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_fetches_local_repo_and_returns_metadata() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git");
    let store_dir = unique_temp_dir("fetch-git-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url_text = format!("file://{}", path_source(&repo_dir));
    let url = nix_string_literal(&url_text);
    let rev = oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; rev = "{rev}"; }};
                in {{
                  names = builtins.attrNames x;
                  pathValue = x.outPath;
                  rev = x.rev;
                  shortRev = x.shortRev;
                  revCount = x.revCount;
                  lastModified = x.lastModified;
                  lastModifiedDate = x.lastModifiedDate;
                  narPrefix = builtins.substring 0 7 x.narHash;
                  submodules = x.submodules;
                  dir = builtins.readDir x;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchGit metadata JSON parses");
    assert_eq!(
        value["names"],
        serde_json::json!([
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "rev",
            "revCount",
            "shortRev",
            "submodules"
        ])
    );
    assert_eq!(value["rev"], rev);
    assert_eq!(value["shortRev"], &rev[..7]);
    assert_eq!(value["revCount"], 1);
    assert_eq!(value["lastModified"], 1_700_000_000);
    assert_eq!(value["lastModifiedDate"], "20231114221320");
    assert_eq!(value["narPrefix"], "sha256-");
    assert_eq!(value["submodules"], false);
    assert_eq!(value["dir"], serde_json::json!({ "data.txt": "regular" }));
    let out_path = value["pathValue"].as_str().expect("outPath is a string");
    assert!(out_path.starts_with(&path_source(&store_dir)));
    assert!(out_path.ends_with("-source"));
    assert_eq!(
        fs::read(Path::new(out_path).join("data.txt")).expect("fetchGit materializes file"),
        b"git-data"
    );
    assert!(!Path::new(out_path).join(".git").exists());

    let context = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; rev = "{rev}"; }};
                in builtins.getContext (toString x)
                "#
        ),
        options,
    );
    let context: serde_json::Value =
        serde_json::from_slice(&context).expect("fetchGit context JSON parses");
    assert_eq!(context[out_path]["path"], true);

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_exports_dirty_local_worktrees() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-dirty");
    fs::write(repo_dir.join("data.txt"), b"dirty-data").expect("tracked file dirties");
    fs::write(repo_dir.join("extra.txt"), b"untracked").expect("untracked file writes");
    let store_dir = unique_temp_dir("fetch-git-dirty-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let head_rev = oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; }};
                in {{
                  names = builtins.attrNames x;
                  rev = x.rev;
                  shortRev = x.shortRev;
                  dirtyRev = x.dirtyRev;
                  dirtyShortRev = x.dirtyShortRev;
                  revCount = x.revCount;
                  data = builtins.readFile "${{x}}/data.txt";
                  extra = builtins.pathExists "${{x}}/extra.txt";
                }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("dirty fetchGit JSON parses");
    assert_eq!(
        value["names"],
        serde_json::json!([
            "dirtyRev",
            "dirtyShortRev",
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "rev",
            "revCount",
            "shortRev",
            "submodules"
        ])
    );
    assert_eq!(value["rev"], "0000000000000000000000000000000000000000");
    assert_eq!(value["shortRev"], "0000000");
    assert_eq!(value["dirtyRev"], format!("{head_rev}-dirty"));
    assert_eq!(value["dirtyShortRev"], format!("{}-dirty", &head_rev[..7]));
    assert_eq!(value["revCount"], 0);
    assert_eq!(value["data"], "dirty-data");
    assert_eq!(value["extra"], false);

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_honors_export_ignore_attributes() {
    let repo_dir = unique_temp_dir("fetch-git-export-ignore");
    let repo = git2::Repository::init(&repo_dir).expect("git fixture repo initializes");
    fs::write(
        repo_dir.join(".gitattributes"),
        b"ignored.txt export-ignore\nsub/ignored.txt export-ignore\nignored-dir/** export-ignore\n",
    )
    .expect("git attributes file writes");
    fs::write(repo_dir.join("included.txt"), b"included").expect("included file writes");
    fs::write(repo_dir.join("ignored.txt"), b"ignored").expect("ignored file writes");
    fs::create_dir(repo_dir.join("sub")).expect("subdirectory creates");
    fs::write(repo_dir.join("sub").join("included.txt"), b"sub-included")
        .expect("sub included file writes");
    fs::write(repo_dir.join("sub").join("ignored.txt"), b"sub-ignored")
        .expect("sub ignored file writes");
    fs::create_dir(repo_dir.join("ignored-dir")).expect("ignored directory creates");
    fs::write(
        repo_dir.join("ignored-dir").join("leaf.txt"),
        b"ignored-leaf",
    )
    .expect("ignored directory leaf writes");
    let mut index = repo.index().expect("git index opens");
    for path in [
        ".gitattributes",
        "included.txt",
        "ignored.txt",
        "sub/included.txt",
        "sub/ignored.txt",
        "ignored-dir/leaf.txt",
    ] {
        index
            .add_path(Path::new(path))
            .expect("git fixture path stages");
    }
    index.write().expect("git index writes");
    drop(index);
    let oid = git_commit_index(&repo, "fixture commit", 1_700_000_000);
    let store_dir = unique_temp_dir("fetch-git-export-ignore-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let rev = oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; rev = "{rev}"; }};
                in {{
                  included = builtins.readFile "${{x}}/included.txt";
                  ignored = builtins.pathExists "${{x}}/ignored.txt";
                  subIncluded = builtins.readFile "${{x}}/sub/included.txt";
                  subIgnored = builtins.pathExists "${{x}}/sub/ignored.txt";
                  ignoredDir = builtins.pathExists "${{x}}/ignored-dir";
                }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("export-ignore fetchGit JSON parses");
    assert_eq!(value["included"], "included");
    assert_eq!(value["ignored"], false);
    assert_eq!(value["subIncluded"], "sub-included");
    assert_eq!(value["subIgnored"], false);
    assert_eq!(value["ignoredDir"], false);

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_resolves_ref_without_rev() {
    let (repo_dir, tagged_oid) = git_repo_with_tag("fetch-git-ref-without-rev");
    let repo = git2::Repository::open(&repo_dir).expect("git fixture repo opens");
    let head_oid = git_commit_file(&repo, "data.txt", b"head-data", 1_700_000_060);
    assert_ne!(tagged_oid, head_oid);
    let store_dir = unique_temp_dir("fetch-git-ref-without-rev-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let tagged_rev = tagged_oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; ref = "refs/tags/v1"; }};
                in {{ rev = x.rev; data = builtins.readFile "${{x}}/data.txt"; }}
                "#
        ),
        options,
    );
    let value: serde_json::Value = serde_json::from_slice(&json).expect("ref fetchGit JSON parses");
    assert_eq!(value["rev"], tagged_rev);
    assert_eq!(value["data"], "git-data");

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_resolves_fetched_ref_without_local_name() {
    let repo_dir = unique_temp_dir("fetch-git-fetch-head-ref");
    let repo = git2::Repository::init(&repo_dir).expect("git fixture repo initializes");
    let custom_oid = git_commit_file(&repo, "data.txt", b"custom-data", 1_700_000_000);
    repo.reference("refs/custom/v1", custom_oid, false, "fixture custom ref")
        .expect("git fixture custom ref creates");
    let head_oid = git_commit_file(&repo, "data.txt", b"head-data", 1_700_000_060);
    assert_ne!(custom_oid, head_oid);
    let store_dir = unique_temp_dir("fetch-git-fetch-head-ref-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let custom_rev = custom_oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; ref = "refs/custom/v1"; }};
                in {{ rev = x.rev; data = builtins.readFile "${{x}}/data.txt"; }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("custom-ref fetchGit JSON parses");
    assert_eq!(value["rev"], custom_rev);
    assert_eq!(value["data"], "custom-data");

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_formats_last_modified_date_as_utc() {
    let repo_dir = unique_temp_dir("fetch-git-utc-date");
    let repo = git2::Repository::init(&repo_dir).expect("git fixture repo initializes");
    let oid = git_commit_file_with_offset(&repo, "data.txt", b"git-data", 1_699_967_600, 540);
    let store_dir = unique_temp_dir("fetch-git-utc-date-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let rev = oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; rev = "{rev}"; }};
                in {{ lastModified = x.lastModified; lastModifiedDate = x.lastModifiedDate; }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("UTC-date fetchGit JSON parses");
    assert_eq!(value["lastModified"], 1_699_967_600);
    assert_eq!(value["lastModifiedDate"], "20231114131320");

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_honors_ref_and_submodules() {
    let (tagged_repo_dir, tagged_oid) = git_repo_with_tag("fetch-git-tagged");
    let tag_store_dir = unique_temp_dir("fetch-git-tagged-store");
    let tag_options =
        TreeWalkOptions::with_store_dir(tag_store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    let tag_url = nix_string_literal(&format!("file://{}", path_source(&tagged_repo_dir)));
    let tagged_rev = tagged_oid.to_string();
    let tagged_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{
                  url = {tag_url};
                  ref = "refs/tags/v1";
                  rev = "{tagged_rev}";
                  name = "tagged";
                }};
                in {{ rev = x.rev; pathValue = x.outPath; data = builtins.readFile "${{x}}/data.txt"; }}
                "#
        ),
        tag_options,
    );
    let tagged_value: serde_json::Value =
        serde_json::from_slice(&tagged_json).expect("tagged fetchGit JSON parses");
    assert_eq!(tagged_value["rev"], tagged_rev);
    assert!(
        tagged_value["pathValue"]
            .as_str()
            .expect("tagged outPath is a string")
            .ends_with("-tagged")
    );
    assert_eq!(tagged_value["data"], "git-data");

    let (parent_dir, sub_dir, parent_oid) = git_repo_with_submodule("fetch-git-submodule");
    let sub_store_dir = unique_temp_dir("fetch-git-submodule-store");
    let sub_options =
        TreeWalkOptions::with_store_dir(sub_store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    let parent_url = nix_string_literal(&format!("file://{}", path_source(&parent_dir)));
    let parent_rev = parent_oid.to_string();
    let sub_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{
                  url = {parent_url};
                  rev = "{parent_rev}";
                  submodules = true;
                }};
                in {{
                  submodules = x.submodules;
                  root = builtins.readFile "${{x}}/root.txt";
                  sub = builtins.readFile "${{x}}/deps/sub/sub.txt";
                  subGit = builtins.pathExists "${{x}}/deps/sub/.git";
                }}
                "#
        ),
        sub_options,
    );
    let sub_value: serde_json::Value =
        serde_json::from_slice(&sub_json).expect("submodule fetchGit JSON parses");
    assert_eq!(sub_value["submodules"], true);
    assert_eq!(sub_value["root"], "root-data");
    assert_eq!(sub_value["sub"], "submodule-data");
    assert_eq!(sub_value["subGit"], false);

    fs::remove_dir_all(tagged_repo_dir).expect("tagged repo temp directory removes");
    fs::remove_dir_all(tag_store_dir).expect("tag store temp directory removes");
    fs::remove_dir_all(parent_dir).expect("parent repo temp directory removes");
    fs::remove_dir_all(sub_dir).expect("sub repo temp directory removes");
    fs::remove_dir_all(sub_store_dir).expect("sub store temp directory removes");
}

#[test]
fn fetch_git_primop_validates_arguments_and_store_reuse() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-invalid");
    let store_dir = unique_temp_dir("fetch-git-invalid-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let rev = oid.to_string();

    let ir = lower(&format!(
        r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; bogus = 1; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("unknown fetchGit attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchGitAttr { attr, .. } if attr.as_slice() == b"bogus"
    ));

    let ir = lower(&format!(
        r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; name = "bad/name"; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("invalid fetchGit store name rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchGitStoreName { .. }
    ));

    let ir = lower(&format!(r#"builtins.fetchGit {{ rev = "{rev}"; }}"#));
    let error = eval_whnf_owned(&ir).expect_err("missing fetchGit url rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let ir = lower(&format!(
        r#"builtins.fetchGit {{ url = {url}; rev = "not-a-rev"; }}"#
    ));
    let error = eval_whnf_owned_with_options(&ir, options.clone())
        .expect_err("invalid fetchGit rev rejects");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchGit { .. }));

    let source = format!(r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; }}"#);
    let path_json = eval_json_bytes_with_options(&source, options.clone());
    let path =
        serde_json::from_slice::<serde_json::Value>(&path_json).expect("fetchGit path JSON parses");
    let out_path = path.as_str().expect("fetchGit coerces to outPath");
    fs::remove_file(Path::new(out_path).join("data.txt"))
        .expect("materialized fetchGit path corrupts");
    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("corrupt existing fetchGit store path rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchGitHashMismatch { .. }
    ));

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_obeys_eval_mode_gates() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-mode");
    let store_dir = unique_temp_dir("fetch-git-mode-store");
    let url_text = format!("file://{}", path_source(&repo_dir));
    let url = nix_string_literal(&url_text);
    let rev = oid.to_string();

    let error = eval_whnf_owned_with_options(
        &lower(&format!("builtins.fetchGit {url}")),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure eval rejects unpinned fetchGit before repo access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchGitRevRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    let mut pure_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    pure_options.set_eval_mode(EvalMode::Pure);
    let pure_json = eval_json_bytes_with_options(
        &format!(r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; }}"#),
        pure_options,
    );
    let pure_path = serde_json::from_slice::<serde_json::Value>(&pure_json)
        .expect("pure fetchGit path JSON parses");
    assert!(
        pure_path
            .as_str()
            .expect("pure fetchGit coerces to outPath")
            .ends_with("-source")
    );

    let restricted_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted eval rejects disallowed fetchGit before repo access");
    assert!(matches!(
        restricted_error.kind(),
        TreeWalkErrorKind::FetchGitAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut restricted_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(format!("git+{url_text}?exportIgnore=1&rev={rev}").into_bytes())
        .expect("git allowed URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; }}"#),
        restricted_options,
    );
    let restricted_path = serde_json::from_slice::<serde_json::Value>(&restricted_json)
        .expect("restricted fetchGit path JSON parses");
    assert!(
        restricted_path
            .as_str()
            .expect("restricted fetchGit coerces to outPath")
            .ends_with("-source")
    );
    let all_refs_canonical_uri = TreeWalk::fetch_git_canonical_uri(&FetchGitArguments {
        url: url_text.as_bytes().to_vec(),
        transport_url: None,
        name: "source".to_owned(),
        rev: Some(rev.as_bytes().to_vec()),
        reference: None,
        submodules: false,
        shallow: false,
        all_refs: true,
        export_ignore: true,
        extra_query: BTreeMap::new(),
    });
    assert_eq!(
        all_refs_canonical_uri,
        format!("git+{url_text}?exportIgnore=1&rev={rev}").into_bytes()
    );
    let queried_canonical_uri = TreeWalk::fetch_git_canonical_uri(&FetchGitArguments {
        url: format!("{url_text}?foo=bar").into_bytes(),
        transport_url: None,
        name: "source".to_owned(),
        rev: Some(rev.as_bytes().to_vec()),
        reference: None,
        submodules: false,
        shallow: false,
        all_refs: false,
        export_ignore: true,
        extra_query: BTreeMap::new(),
    });
    assert_eq!(
        queried_canonical_uri,
        format!("git+{url_text}?foo=bar&exportIgnore=1&rev={rev}").into_bytes()
    );
    let path_with_question_canonical_uri = TreeWalk::fetch_git_canonical_uri(&FetchGitArguments {
        url: b"/tmp/repo?literal".to_vec(),
        transport_url: None,
        name: "source".to_owned(),
        rev: Some(rev.as_bytes().to_vec()),
        reference: None,
        submodules: false,
        shallow: false,
        all_refs: false,
        export_ignore: true,
        extra_query: BTreeMap::new(),
    });
    assert_eq!(
        path_with_question_canonical_uri,
        format!("git+/tmp/repo?literal?exportIgnore=1&rev={rev}").into_bytes()
    );

    let (tagged_repo_dir, tagged_oid) = git_repo_with_tag("fetch-git-mode-tagged");
    let tagged_url_text = format!("file://{}", path_source(&tagged_repo_dir));
    let tagged_url = nix_string_literal(&tagged_url_text);
    let tagged_rev = tagged_oid.to_string();
    let tagged_rev_bytes = tagged_rev.as_bytes().to_vec();
    let canonical_uri = TreeWalk::fetch_git_canonical_uri(&FetchGitArguments {
        url: tagged_url_text.as_bytes().to_vec(),
        transport_url: None,
        name: "source".to_owned(),
        rev: Some(tagged_rev_bytes),
        reference: Some(b"refs/tags/v1".to_vec()),
        submodules: true,
        shallow: true,
        all_refs: false,
        export_ignore: false,
        extra_query: BTreeMap::new(),
    });
    assert_eq!(
        canonical_uri,
        format!("git+{tagged_url_text}?ref=refs/tags/v1&rev={tagged_rev}&shallow=1&submodules=1")
            .into_bytes()
    );
    let mut tagged_restricted_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    tagged_restricted_options.set_eval_mode(EvalMode::Restricted);
    tagged_restricted_options
        .add_allowed_uri(
            format!("git+{tagged_url_text}?ref=refs/tags/v1&rev={tagged_rev}&submodules=1")
                .into_bytes(),
        )
        .expect("ref-qualified git allowed URI configures");
    let tagged_restricted_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{
                  url = {tagged_url};
                  ref = "refs/tags/v1";
                  rev = "{tagged_rev}";
                  submodules = true;
                }};
                in {{ rev = x.rev; submodules = x.submodules; }}
                "#
        ),
        tagged_restricted_options,
    );
    let tagged_restricted_value: serde_json::Value =
        serde_json::from_slice(&tagged_restricted_json)
            .expect("restricted ref fetchGit JSON parses");
    assert_eq!(tagged_restricted_value["rev"], tagged_rev);
    assert_eq!(tagged_restricted_value["submodules"], true);

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(tagged_repo_dir).expect("tagged repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_path_input_returns_locked_tree_metadata() {
    let dir = unique_temp_dir("fetch-tree-path");
    let source_dir = dir.join("source");
    fs::create_dir(&source_dir).expect("source directory creates");
    fs::write(source_dir.join("file.txt"), b"path-data").expect("source file writes");
    fs::create_dir(source_dir.join("sub")).expect("source subdirectory creates");
    fs::write(source_dir.join("sub").join("nested.txt"), b"nested")
        .expect("source nested file writes");
    let store_dir = unique_temp_dir("fetch-tree-path-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let path = nix_string_literal(&path_source(&source_dir));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {{ type = "path"; path = {path}; }};
                in {{
                  keys = builtins.attrNames x;
                  data = builtins.readFile "${{x.outPath}}/file.txt";
                  nested = builtins.readFile "${{x.outPath}}/sub/nested.txt";
                  narHash = x.narHash;
                  pathValue = x.outPath;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree path JSON parses");
    assert_eq!(
        value["keys"],
        serde_json::json!(["lastModified", "lastModifiedDate", "narHash", "outPath"])
    );
    assert_eq!(value["data"], "path-data");
    assert_eq!(value["nested"], "nested");
    assert!(
        value["narHash"]
            .as_str()
            .expect("narHash is a string")
            .starts_with("sha256-")
    );
    assert!(
        value["pathValue"]
            .as_str()
            .expect("pathValue is a string")
            .starts_with(path_source(&store_dir).as_str())
    );

    let nar_hash = value["narHash"].as_str().expect("narHash is a string");
    let denied_pure_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "path"; path = {path}; narHash = "{nar_hash}"; }}"#
        )),
        {
            let mut options = options.clone();
            options.set_eval_mode(EvalMode::Pure);
            options
        },
    )
    .expect_err("pure fetchTree path requires an allowed source path");
    assert!(matches!(
        denied_pure_error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            path: denied,
            mode: EvalMode::Pure,
            ..
        } if denied.as_slice() == source_dir.as_os_str().as_bytes()
    ));

    let mut pure_options = options.clone();
    pure_options.set_eval_mode(EvalMode::Pure);
    pure_options
        .add_allowed_path(source_dir.as_os_str().as_bytes().to_vec())
        .expect("pure fetchTree source path configures as allowed");
    let pure_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {{ type = "path"; path = {path}; narHash = "{nar_hash}"; }};
                in x.narHash
                "#
        ),
        pure_options,
    );
    assert_eq!(
        pure_json,
        serde_json::to_vec(nar_hash).expect("narHash JSON serializes")
    );

    let error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "path"; path = {path}; }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure fetchTree path requires narHash");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLockedInputRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("source temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_file_and_tarball_inputs_materialize_expected_store_paths() {
    let (file_dir, file_path) = temp_file_with_bytes("fetch-tree-file", b"plain-data");
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-tarball");
    let store_dir = unique_temp_dir("fetch-tree-file-tarball-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let file_url = nix_string_literal(&format!("file://{}", path_source(&file_path)));
    let tarball_url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  file = builtins.fetchTree {{ type = "file"; url = {file_url}; }};
                  fileUnpack = builtins.fetchTree {{ type = "file"; url = {file_url}; unpack = true; }};
                  tarball = builtins.fetchTree {{
                    type = "tarball";
                    url = {tarball_url};
                    narHash = "{recursive_digest}";
                    rev = "abcdef1234567890";
                    revCount = 7;
                  }};
                  tarballNoUnpack = builtins.fetchTree {{
                    type = "tarball";
                    url = {tarball_url};
                    narHash = "{recursive_digest}";
                    unpack = false;
                  }};
                in {{
                  fileKeys = builtins.attrNames file;
                  fileData = builtins.readFile file.outPath;
                  fileUnpackData = builtins.readFile fileUnpack.outPath;
                  tarballKeys = builtins.attrNames tarball;
                  tarballData = builtins.readFile "${{tarball.outPath}}/file.txt";
                  tarballNested = builtins.readFile "${{tarball.outPath}}/sub/nested.txt";
                  tarballNoUnpackData = builtins.readFile "${{tarballNoUnpack.outPath}}/file.txt";
                  tarballRev = tarball.rev;
                  tarballShortRev = tarball.shortRev;
                  tarballRevCount = tarball.revCount;
                }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree file/tarball JSON parses");
    assert_eq!(value["fileKeys"], serde_json::json!(["narHash", "outPath"]));
    assert_eq!(value["fileData"], "plain-data");
    assert_eq!(value["fileUnpackData"], "plain-data");
    assert_eq!(
        value["tarballKeys"],
        serde_json::json!([
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "rev",
            "revCount",
            "shortRev"
        ])
    );
    assert_eq!(value["tarballData"], "data");
    assert_eq!(value["tarballNested"], "inner");
    assert_eq!(value["tarballNoUnpackData"], "data");
    assert_eq!(value["tarballRev"], "abcdef1234567890");
    assert_eq!(value["tarballShortRev"], "abcdef1");
    assert_eq!(value["tarballRevCount"], 7);

    let error = eval_whnf_owned(&lower(&format!(
            r#"builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; }}"#
        )))
        .expect_err("wrong fetchTree tarball hash rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeHashMismatch { .. }
    ));

    fs::remove_dir_all(file_dir).expect("file temp directory removes");
    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_file_http_input_uses_identity_bytes() {
    let (url, body_hash, handle) = gzip_encoded_http_fixture("/tree-data.bin", b"abc");
    let url = nix_string_literal(&url);
    let store_dir = unique_temp_dir("fetch-tree-http-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                r#"
                    let x = builtins.fetchTree {{ type = "file"; url = {url}; }};
                    in builtins.hashFile "sha256" x.outPath
                    "#
            ),
            options,
        ),
        body_hash.as_bytes()
    );
    fs::remove_dir_all(store_dir).expect("store temp directory removes");

    assert_http_fixture_requested_identity(
        handle.join().expect("HTTP fixture thread completes"),
        "fetchTree",
    );
}

#[test]
fn fetch_tree_string_refs_dispatch_to_supported_inputs() {
    let dir = unique_temp_dir("fetch-tree-string-refs");
    let source_dir = dir.join("source");
    fs::create_dir(&source_dir).expect("source directory creates");
    fs::write(source_dir.join("file.txt"), b"path-data").expect("source file writes");
    let (file_dir, file_path) = temp_file_with_bytes("fetch-tree-string-file", b"plain-data");
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-string-tarball");
    let store_dir = unique_temp_dir("fetch-tree-string-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let path_ref = nix_string_literal(&format!("path:{}", path_source(&source_dir)));
    let file_ref = nix_string_literal(&format!("file+file://{}", path_source(&file_path)));
    let tarball_ref = nix_string_literal(&format!(
        "file://{}?lastModified=1&narHash=da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2&rev=abcdef1234567890&revCount=7",
        path_source(&archive_path)
    ));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  pathTree = builtins.fetchTree {path_ref};
                  fileTree = builtins.fetchTree {file_ref};
                  tarballTree = builtins.fetchTree {tarball_ref};
                in {{
                  pathData = builtins.readFile "${{pathTree.outPath}}/file.txt";
                  fileData = builtins.readFile fileTree.outPath;
                  tarballData = builtins.readFile "${{tarballTree.outPath}}/file.txt";
                  tarballRev = tarballTree.rev;
                  tarballShortRev = tarballTree.shortRev;
                  tarballRevCount = tarballTree.revCount;
                  tarballLastModified = tarballTree.lastModified;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree string ref JSON parses");
    assert_eq!(value["pathData"], "path-data");
    assert_eq!(value["fileData"], "plain-data");
    assert_eq!(value["tarballData"], "data");
    assert_eq!(value["tarballRev"], "abcdef1234567890");
    assert_eq!(value["tarballShortRev"], "abcdef1");
    assert_eq!(value["tarballRevCount"], 7);
    assert_eq!(value["tarballLastModified"], 1);

    let bare_path_ref = nix_string_literal(&path_source(&source_dir));
    let error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {bare_path_ref}"#)),
        options,
    )
    .expect_err("bare absolute path string fetchTree rejects");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    fs::remove_dir_all(dir).expect("source temp directory removes");
    fs::remove_dir_all(file_dir).expect("file temp directory removes");
    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_refs_reroot_dir_metadata() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-string-dir-tarball");
    let (repo_dir, _) = git_repo_with_file("fetch-tree-string-dir-git");
    let repo = git2::Repository::open(&repo_dir).expect("git fixture repo opens");
    let oid = git_commit_file(&repo, "sub/nested.txt", b"git-subdir", 1_700_000_120);
    let store_dir = unique_temp_dir("fetch-tree-string-dir-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let tarball_url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let tarball_ref = nix_string_literal(&format!("file://{}?dir=sub", path_source(&archive_path)));
    let raw_git_ref = format!("git+file://{}?dir=sub&rev={}", path_source(&repo_dir), oid);
    let git_ref = nix_string_literal(&raw_git_ref);
    let git_url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let expected_git_url = format!("file://{}?dir=sub", path_source(&repo_dir));
    let expected_git_transport_url = format!("file://{}", path_source(&repo_dir));
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let evaluator = TreeWalk::new(&ir);
    let attrs = TreeWalk::parse_flake_ref_attrs(ir.root, span, raw_git_ref.as_bytes())
        .expect("git dir flake ref parses");
    let arguments = evaluator
        .fetch_tree_flake_ref_arguments(ir.root, span, raw_git_ref.as_bytes(), &attrs)
        .expect("git dir flake ref lowers to fetchTree arguments");
    let FetchTreeArguments::Git { args, .. } = arguments else {
        panic!("git dir flake ref lowers to git arguments");
    };
    assert_eq!(args.url, expected_git_url.as_bytes());
    assert_eq!(
        args.transport_url.as_deref(),
        Some(expected_git_transport_url.as_bytes())
    );

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  tarballTree = builtins.fetchTree {tarball_ref};
                  directTarballTree = builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; dir = "sub"; }};
                  gitTree = builtins.fetchTree {git_ref};
                  directGitTree = builtins.fetchTree {{ type = "git"; url = {git_url}; rev = "{oid}"; dir = "sub"; }};
                in {{
                  tarballNested = builtins.readFile "${{tarballTree.outPath}}/nested.txt";
                  directTarballNested = builtins.readFile "${{directTarballTree.outPath}}/nested.txt";
                  tarballRootFile = builtins.pathExists "${{tarballTree.outPath}}/file.txt";
                  tarballSubNested = builtins.pathExists "${{tarballTree.outPath}}/sub/nested.txt";
                  gitNested = builtins.readFile "${{gitTree.outPath}}/nested.txt";
                  directGitNested = builtins.readFile "${{directGitTree.outPath}}/nested.txt";
                  gitRootData = builtins.pathExists "${{gitTree.outPath}}/data.txt";
                  gitSubNested = builtins.pathExists "${{gitTree.outPath}}/sub/nested.txt";
                  gitRev = gitTree.rev;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree dir string ref JSON parses");
    assert_eq!(value["tarballNested"], "inner");
    assert_eq!(value["directTarballNested"], "inner");
    assert_eq!(value["tarballRootFile"], false);
    assert_eq!(value["tarballSubNested"], false);
    assert_eq!(value["gitNested"], "git-subdir");
    assert_eq!(value["directGitNested"], "git-subdir");
    assert_eq!(value["gitRootData"], false);
    assert_eq!(value["gitSubNested"], false);
    assert_eq!(value["gitRev"], oid.to_string());

    let escaping_dir_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; dir = "../root"; }}"#
        )),
        options.clone(),
    )
    .expect_err("fetchTree dir cannot escape the fetched tree");
    assert!(matches!(
        escaping_dir_error.kind(),
        TreeWalkErrorKind::FetchTree { .. }
    ));

    let missing_dir_ref = nix_string_literal(&format!(
        "git+file://{}?dir=missing&rev={}",
        path_source(&repo_dir),
        oid
    ));
    let missing_dir_error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {missing_dir_ref}"#)),
        options.clone(),
    )
    .expect_err("fetchTree dir must exist");
    assert!(matches!(
        missing_dir_error.kind(),
        TreeWalkErrorKind::FetchTree { .. }
    ));

    let mut stripped_uri_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    stripped_uri_options.set_eval_mode(EvalMode::Restricted);
    stripped_uri_options
        .add_allowed_uri(
            format!(
                "git+file://{}?rev={oid}&shallow=1&exportIgnore=1",
                path_source(&repo_dir)
            )
            .into_bytes(),
        )
        .expect("stripped git allowed URI configures");
    let error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {git_ref}"#)),
        stripped_uri_options,
    )
    .expect_err("restricted fetchTree git dir requires original URI");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut original_uri_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    original_uri_options.set_eval_mode(EvalMode::Restricted);
    original_uri_options
        .add_allowed_uri(
            format!(
                "git+file://{}?dir=sub&rev={oid}&shallow=1&exportIgnore=1",
                path_source(&repo_dir)
            )
            .into_bytes(),
        )
        .expect("original git allowed URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(r#"let x = builtins.fetchTree {git_ref}; in x.rev"#),
        original_uri_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(&oid.to_string()).expect("rev JSON serializes")
    );

    let file_ref = nix_string_literal(&format!(
        "file+file://{}?dir=sub",
        path_source(&archive_path)
    ));
    let error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {file_ref}"#)),
        options,
    )
    .expect_err("fetchTree file refs reject dir metadata");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_dir_rejects_symlinked_intermediate_components() {
    let root = unique_temp_dir("fetch-tree-dir-symlink-root");
    let outside = unique_temp_dir("fetch-tree-dir-symlink-outside");
    fs::create_dir(root.join("sub")).expect("valid subdir creates");
    fs::create_dir(outside.join("nested")).expect("outside nested dir creates");
    std::os::unix::fs::symlink(&outside, root.join("link")).expect("symlink creates");

    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let valid =
        TreeWalk::fetch_tree_subdir_root(ir.root, span, b"fetchTree", &root, Some(b"./sub"))
            .expect("ordinary subdir resolves");
    assert_eq!(valid, root.join("sub"));

    let error =
        TreeWalk::fetch_tree_subdir_root(ir.root, span, b"fetchTree", &root, Some(b"link/nested"))
            .expect_err("intermediate symlink cannot escape fetched tree");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    fs::remove_dir_all(root).expect("root temp directory removes");
    fs::remove_dir_all(outside).expect("outside temp directory removes");
}

#[test]
fn fetch_tree_git_input_returns_flake_lock_metadata() {
    let (repo_dir, _) = git_repo_with_file("fetch-tree-git");
    let repo = git2::Repository::open(&repo_dir).expect("git fixture repo opens");
    fs::write(
        repo_dir.join(".gitattributes"),
        b"ignored.txt export-ignore\n",
    )
    .expect("git attributes file writes");
    fs::write(repo_dir.join("ignored.txt"), b"ignored").expect("ignored file writes");
    let mut index = repo.index().expect("git index opens");
    for path in [".gitattributes", "ignored.txt"] {
        index
            .add_path(Path::new(path))
            .expect("git fixture path stages");
    }
    index.write().expect("git index writes");
    drop(index);
    let oid = git_commit_index(&repo, "export-ignore fixture commit", 1_700_000_060);
    let store_dir = unique_temp_dir("fetch-tree-git-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url_text = format!("file://{}", path_source(&repo_dir));
    let url = nix_string_literal(&url_text);
    let rev = oid.to_string();
    let public_keys_json = r#"[{"key":"abc","type":"ssh-ed25519"},{"key":"def","type":"ssh-rsa"}]"#;
    let public_keys_query = String::from_utf8(TreeWalk::percent_encode_flake_ref_query(
        public_keys_json.as_bytes(),
    ))
    .expect("publicKeys query is UTF-8");
    let combined_public_keys_json =
        r#"[{"key":"abc","type":"ssh-ed25519"},{"key":"def","type":"ssh-ed25519"}]"#;
    let combined_public_keys_query = String::from_utf8(TreeWalk::percent_encode_flake_ref_query(
        combined_public_keys_json.as_bytes(),
    ))
    .expect("combined publicKeys query is UTF-8");

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  shallow = builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; }};
                  noExportIgnore = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    exportIgnore = false;
                  }};
                  dirty = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    dirtyRev = "{rev}-dirty";
                    dirtyShortRev = "dirty-lock";
                  }};
                  full = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    shallow = false;
                    revCount = 2;
                  }};
                  publicKey = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKey = "abc";
                  }};
                  publicKeys = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [ {{ type = "ssh-ed25519"; key = "abc"; }} ];
                  }};
                  emptyPublicKeys = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [];
                    publicKey = "abc";
                  }};
                  combinedPublicKeys = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [ {{ type = "ssh-ed25519"; key = "abc"; }} ];
                    publicKey = "def";
                  }};
                  multiPublicKeys = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [
                      {{ type = "ssh-ed25519"; key = "abc"; }}
                      {{ type = "ssh-rsa"; key = "def"; }}
                    ];
                  }};
                in {{
                  keys = builtins.attrNames shallow;
                  rev = shallow.rev;
                  shortRev = shallow.shortRev;
                  submodules = shallow.submodules;
                  hasRevCount = shallow ? revCount;
                  data = builtins.readFile "${{shallow.outPath}}/data.txt";
                  ignored = builtins.pathExists "${{shallow.outPath}}/ignored.txt";
                  noExportIgnored = builtins.readFile "${{noExportIgnore.outPath}}/ignored.txt";
                  dirtyKeys = builtins.attrNames dirty;
                  dirtyRev = dirty.dirtyRev;
                  dirtyShortRev = dirty.dirtyShortRev;
                  dirtyHasRev = dirty ? rev;
                  fullRevCount = full.revCount;
                  publicKeyData = builtins.readFile "${{publicKey.outPath}}/data.txt";
                  publicKeysData = builtins.readFile "${{publicKeys.outPath}}/data.txt";
                  emptyPublicKeysData = builtins.readFile "${{emptyPublicKeys.outPath}}/data.txt";
                  combinedPublicKeysData = builtins.readFile "${{combinedPublicKeys.outPath}}/data.txt";
                  multiPublicKeysData = builtins.readFile "${{multiPublicKeys.outPath}}/data.txt";
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree git JSON parses");
    assert_eq!(
        value["keys"],
        serde_json::json!([
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "rev",
            "shortRev",
            "submodules"
        ])
    );
    assert_eq!(value["rev"], rev);
    assert_eq!(value["shortRev"], &rev[..7]);
    assert_eq!(value["submodules"], false);
    assert_eq!(value["hasRevCount"], false);
    assert_eq!(value["data"], "git-data");
    assert_eq!(value["ignored"], false);
    assert_eq!(value["noExportIgnored"], "ignored");
    assert_eq!(
        value["dirtyKeys"],
        serde_json::json!([
            "dirtyRev",
            "dirtyShortRev",
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "submodules"
        ])
    );
    assert_eq!(value["dirtyRev"], format!("{rev}-dirty"));
    assert_eq!(value["dirtyShortRev"], "dirty-lock");
    assert_eq!(value["dirtyHasRev"], false);
    assert_eq!(value["fullRevCount"], 2);
    assert_eq!(value["publicKeyData"], "git-data");
    assert_eq!(value["publicKeysData"], "git-data");
    assert_eq!(value["emptyPublicKeysData"], "git-data");
    assert_eq!(value["combinedPublicKeysData"], "git-data");
    assert_eq!(value["multiPublicKeysData"], "git-data");

    let mut pure_options = options.clone();
    pure_options.set_eval_mode(EvalMode::Pure);
    let pure_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; }};
                in x.rev
                "#
        ),
        pure_options,
    );
    assert_eq!(
        pure_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    let restricted_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted fetchTree git rejects disallowed canonical URI");
    assert!(matches!(
        restricted_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut restricted_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(format!("git+{url_text}?rev={rev}&shallow=1&exportIgnore=1").into_bytes())
        .expect("git allowed URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(
            r#"let x = builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; }}; in x.rev"#
        ),
        restricted_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    let restricted_keyed_error = eval_whnf_owned_with_options(
            &lower(&format!(
                r#"builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; verifyCommit = false; publicKey = "abc"; }}"#
            )),
            TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
        )
        .expect_err("restricted keyed fetchTree git rejects disallowed canonical URI");
    assert!(matches!(
        restricted_keyed_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!(
            "git+{url_text}?keytype=ssh-ed25519&publicKey=abc&rev={rev}&shallow=1&exportIgnore=1"
        ).as_bytes()
    ));

    let restricted_empty_keyed_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [];
                    publicKey = "abc";
                }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted empty publicKeys fetchTree git uses singular key URI");
    assert!(matches!(
        restricted_empty_keyed_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!(
            "git+{url_text}?keytype=ssh-ed25519&publicKey=abc&rev={rev}&shallow=1&exportIgnore=1"
        ).as_bytes()
    ));

    let restricted_combined_keyed_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [ {{ type = "ssh-ed25519"; key = "abc"; }} ];
                    publicKey = "def";
                }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted combined publicKeys fetchTree git appends singular key");
    assert!(matches!(
        restricted_combined_keyed_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!(
            "git+{url_text}?publicKeys={combined_public_keys_query}&rev={rev}&shallow=1&exportIgnore=1"
        ).as_bytes()
    ));

    let restricted_multi_keyed_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [
                      {{ type = "ssh-ed25519"; key = "abc"; }}
                      {{ type = "ssh-rsa"; key = "def"; }}
                    ];
                }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted multi-key fetchTree git rejects disallowed canonical URI");
    assert!(matches!(
        restricted_multi_keyed_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!(
            "git+{url_text}?publicKeys={public_keys_query}&rev={rev}&shallow=1&exportIgnore=1"
        ).as_bytes()
    ));

    let mut restricted_keyed_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    restricted_keyed_options.set_eval_mode(EvalMode::Restricted);
    restricted_keyed_options
            .add_allowed_uri(
                format!(
                    "git+{url_text}?keytype=ssh-ed25519&publicKey=abc&rev={rev}&shallow=1&exportIgnore=1"
                )
                .into_bytes(),
            )
            .expect("keyed git allowed URI configures");
    let restricted_keyed_json = eval_json_bytes_with_options(
        &format!(
            r#"let x = builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; verifyCommit = false; publicKey = "abc"; }}; in x.rev"#
        ),
        restricted_keyed_options,
    );
    assert_eq!(
        restricted_keyed_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    let verified_error = eval_whnf_owned_with_options(
            &lower(&format!(
                r#"builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; verifyCommit = true; publicKey = "abc"; }}"#
            )),
            options,
        )
        .expect_err("verified fetchTree git remains unsupported");
    assert!(matches!(
        verified_error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "verified git fetches",
            ..
        }
    ));

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_git_string_ref_returns_flake_lock_metadata() {
    let (repo_dir, _) = git_repo_with_file("fetch-tree-git-string");
    let repo = git2::Repository::open(&repo_dir).expect("git fixture repo opens");
    let oid = repo
        .head()
        .expect("git fixture HEAD exists")
        .target()
        .expect("git fixture HEAD targets a commit");
    let store_dir = unique_temp_dir("fetch-tree-git-string-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let rev = oid.to_string();
    let raw_git_ref = format!("git+file://{}?rev={rev}", path_source(&repo_dir));
    let git_ref = nix_string_literal(&raw_git_ref);
    let raw_keyed_git_ref = format!(
        "git+file://{}?rev={rev}&publicKey=abc",
        path_source(&repo_dir)
    );
    let keyed_git_ref = nix_string_literal(&raw_keyed_git_ref);

    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let evaluator = TreeWalk::new(&ir);
    let attrs = TreeWalk::parse_flake_ref_attrs(ir.root, span, raw_keyed_git_ref.as_bytes())
        .expect("keyed git flake ref parses");
    let arguments = evaluator
        .fetch_tree_flake_ref_arguments(ir.root, span, raw_keyed_git_ref.as_bytes(), &attrs)
        .expect("keyed git flake ref lowers to fetchTree arguments");
    let FetchTreeArguments::Git { args, .. } = arguments else {
        panic!("keyed git flake ref lowers to git arguments");
    };
    assert_eq!(
        args.url,
        format!("file://{}", path_source(&repo_dir)).as_bytes()
    );
    assert_eq!(args.transport_url, None);
    assert_eq!(
        TreeWalk::fetch_tree_git_canonical_uri(&args),
        format!(
            "git+file://{}?keytype=ssh-ed25519&publicKey=abc&rev={rev}&shallow=1&exportIgnore=1",
            path_source(&repo_dir)
        )
        .into_bytes()
    );

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {git_ref};
                    keyed = builtins.fetchTree {keyed_git_ref};
                in {{
                  data = builtins.readFile "${{x.outPath}}/data.txt";
                  keyedData = builtins.readFile "${{keyed.outPath}}/data.txt";
                  rev = x.rev;
                  keyedRev = keyed.rev;
                  shortRev = x.shortRev;
                  submodules = x.submodules;
                  narHash = x.narHash;
                  lastModified = x.lastModified;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree git string JSON parses");
    assert_eq!(value["data"], "git-data");
    assert_eq!(value["keyedData"], "git-data");
    assert_eq!(value["rev"], rev);
    assert_eq!(value["keyedRev"], rev);
    assert_eq!(value["shortRev"], &rev[..7]);
    assert_eq!(value["submodules"], false);
    assert_eq!(value["lastModified"], 1_700_000_000);
    let nar_hash = value["narHash"]
        .as_str()
        .expect("fetchTree git result exposes narHash");
    let nar_hash_query =
        url::form_urlencoded::byte_serialize(nar_hash.as_bytes()).collect::<String>();

    let locked_metadata_ref = nix_string_literal(&format!(
        "git+file://{}?rev={rev}&narHash={nar_hash_query}&lastModified=1700000000&revCount=1&shallow=0",
        path_source(&repo_dir)
    ));
    let locked_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {locked_metadata_ref};
                in {{
                  data = builtins.readFile "${{x.outPath}}/data.txt";
                  rev = x.rev;
                  revCount = x.revCount;
                  lastModified = x.lastModified;
                  narHash = x.narHash;
                }}
                "#
        ),
        options.clone(),
    );
    let locked_value: serde_json::Value =
        serde_json::from_slice(&locked_json).expect("locked fetchTree git string JSON parses");
    assert_eq!(locked_value["data"], "git-data");
    assert_eq!(locked_value["rev"], rev);
    assert_eq!(locked_value["revCount"], 1);
    assert_eq!(locked_value["lastModified"], 1_700_000_000);
    assert_eq!(locked_value["narHash"], nar_hash);

    let mismatched_metadata_ref = nix_string_literal(&format!(
        "git+file://{}?rev={rev}&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&lastModified=1700000001&revCount=2&shallow=0",
        path_source(&repo_dir)
    ));
    let mismatched_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {mismatched_metadata_ref};
                in {{
                  revCount = x.revCount;
                  lastModified = x.lastModified;
                  narHash = x.narHash;
                }}
                "#
        ),
        options.clone(),
    );
    let mismatched_value: serde_json::Value = serde_json::from_slice(&mismatched_json)
        .expect("mismatched metadata fetchTree git string JSON parses");
    assert_eq!(mismatched_value["revCount"], 1);
    assert_eq!(mismatched_value["lastModified"], 1_700_000_000);
    assert_eq!(mismatched_value["narHash"], nar_hash);

    let mut pure_options = options.clone();
    pure_options.set_eval_mode(EvalMode::Pure);
    let pure_json = eval_json_bytes_with_options(
        &format!(r#"let x = builtins.fetchTree {git_ref}; in x.rev"#),
        pure_options,
    );
    assert_eq!(
        pure_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    let restricted_error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {git_ref}"#)),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted fetchTree git string rejects disallowed canonical URI");
    assert!(matches!(
        restricted_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut restricted_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(
            format!(
                "git+file://{}?rev={rev}&shallow=1&exportIgnore=1",
                path_source(&repo_dir)
            )
            .into_bytes(),
        )
        .expect("git string allowed URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(r#"let x = builtins.fetchTree {git_ref}; in x.rev"#),
        restricted_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_forge_refs_lower_to_archive_urls_and_gate_access() {
    let rev = "0000000000000000000000000000000000000000";
    let nar_hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let nar_hash_query = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D";
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let evaluator = TreeWalk::new(&ir);

    for (raw, canonical, archive) in [
        (
            format!("github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("https://github.com/NixOS/nixpkgs/archive/{rev}.tar.gz"),
        ),
        (
            format!("github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("https://github.com/NixOS/nixpkgs/archive/{rev}.tar.gz"),
        ),
        (
            format!("gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!(
                "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={rev}"
            ),
        ),
        (
            format!("gitlab:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("gitlab:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!(
                "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={rev}"
            ),
        ),
        (
            format!("sourcehut:~andyl/aos/{rev}?narHash={nar_hash_query}"),
            format!("sourcehut:~andyl/aos/{rev}?narHash={nar_hash_query}"),
            format!("https://git.sr.ht/~andyl/aos/archive/{rev}.tar.gz"),
        ),
        (
            format!("sourcehut:~andyl/aos/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("sourcehut:~andyl/aos/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("https://git.sr.ht/~andyl/aos/archive/{rev}.tar.gz"),
        ),
    ] {
        let attrs = TreeWalk::parse_flake_ref_attrs(ir.root, span, raw.as_bytes())
            .expect("forge flake ref parses");
        let arguments = evaluator
            .fetch_tree_flake_ref_arguments(ir.root, span, raw.as_bytes(), &attrs)
            .expect("forge flake ref lowers to fetchTree arguments");
        let FetchTreeArguments::Forge {
            canonical_uri,
            archive_url,
            rev: actual_rev,
            expected_nar_hash,
            ..
        } = arguments
        else {
            panic!("forge flake ref lowers to forge arguments");
        };
        assert_eq!(canonical_uri, canonical.as_bytes());
        assert_eq!(archive_url, archive.as_bytes());
        assert_eq!(actual_rev, rev.as_bytes());
        assert!(expected_nar_hash.is_some());
    }

    let enterprise_url = TreeWalk::fetch_tree_forge_archive_url(
        ir.root,
        span,
        b"github",
        b"NixOS",
        b"nixpkgs",
        Some(b"git.example"),
        rev.as_bytes(),
    )
    .expect("enterprise GitHub archive URL renders");
    assert_eq!(
        enterprise_url,
        format!("https://git.example/api/v3/repos/NixOS/nixpkgs/tarball/{rev}").into_bytes()
    );

    let encoded_url = TreeWalk::fetch_tree_forge_archive_url(
        ir.root,
        span,
        b"github",
        b"NixOS?org",
        b"nixpkgs#repo",
        Some(b"git.example"),
        rev.as_bytes(),
    )
    .expect("enterprise GitHub archive URL encodes path components");
    assert_eq!(
        encoded_url,
        format!("https://git.example/api/v3/repos/NixOS%3Forg/nixpkgs%23repo/tarball/{rev}")
            .into_bytes()
    );

    let github_ref_url = TreeWalk::fetch_tree_github_ref_url(
        ir.root,
        span,
        b"NixOS",
        b"nixpkgs",
        None,
        b"release/23.05",
    )
    .expect("GitHub ref resolution URL renders");
    assert_eq!(
        github_ref_url,
        b"https://api.github.com/repos/NixOS/nixpkgs/commits/release%2F23.05"
    );

    let enterprise_ref_url = TreeWalk::fetch_tree_github_ref_url(
        ir.root,
        span,
        b"NixOS",
        b"nixpkgs",
        Some(b"git.example"),
        b"main",
    )
    .expect("GitHub Enterprise ref resolution URL renders");
    assert_eq!(
        enterprise_ref_url,
        b"https://git.example/api/v3/repos/NixOS/nixpkgs/commits/main"
    );

    let gitlab_ref_url = TreeWalk::fetch_tree_gitlab_ref_url(
        ir.root,
        span,
        b"NixOS",
        b"nixpkgs",
        None,
        b"release/23.05",
    )
    .expect("GitLab ref resolution URL renders");
    assert_eq!(
        gitlab_ref_url,
        b"https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/commits/release%2F23.05"
    );

    let custom_gitlab_ref_url = TreeWalk::fetch_tree_gitlab_ref_url(
        ir.root,
        span,
        b"NixOS",
        b"nixpkgs",
        Some(b"git.example"),
        b"main",
    )
    .expect("custom GitLab ref resolution URL renders");
    assert_eq!(
        custom_gitlab_ref_url,
        b"https://git.example/api/v4/projects/NixOS%2Fnixpkgs/repository/commits/main"
    );

    let resolved_rev = TreeWalk::fetch_tree_github_rev_from_commit_response(
        ir.root,
        span,
        b"github:NixOS/nixpkgs/main",
        br#"{"sha":"0123456789abcdef0123456789abcdef01234567"}"#,
    )
    .expect("GitHub commit response exposes a full rev");
    assert_eq!(resolved_rev, b"0123456789abcdef0123456789abcdef01234567");

    let error = TreeWalk::fetch_tree_github_rev_from_commit_response(
        ir.root,
        span,
        b"github:NixOS/nixpkgs/main",
        br#"{"sha":"main"}"#,
    )
    .expect_err("GitHub commit response requires a full rev");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    let resolved_rev = TreeWalk::fetch_tree_gitlab_rev_from_commit_response(
        ir.root,
        span,
        b"gitlab:NixOS/nixpkgs/main",
        br#"{"id":"0123456789abcdef0123456789abcdef01234567"}"#,
    )
    .expect("GitLab commit response exposes a full rev");
    assert_eq!(resolved_rev, b"0123456789abcdef0123456789abcdef01234567");

    let error = TreeWalk::fetch_tree_gitlab_rev_from_commit_response(
        ir.root,
        span,
        b"gitlab:NixOS/nixpkgs/main",
        br#"{"id":"main"}"#,
    )
    .expect_err("GitLab commit response requires a full rev");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    let pure_attrs = TreeWalk::parse_flake_ref_attrs(ir.root, span, b"github:NixOS/nixpkgs/main")
        .expect("GitHub ref parses");
    let pure_evaluator =
        TreeWalk::with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure));
    let error = pure_evaluator
        .fetch_tree_flake_ref_arguments(ir.root, span, b"github:NixOS/nixpkgs/main", &pure_attrs)
        .expect_err("pure GitHub ref rejects before resolver access without narHash");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLockedInputRequired {
            input,
            mode: EvalMode::Pure,
            ..
        } if input == b"github:NixOS/nixpkgs/main"
    ));

    let restricted_source = format!(
        r#"builtins.fetchTree {{ type = "github"; owner = "NixOS"; repo = "nixpkgs"; rev = "{rev}"; narHash = "{nar_hash}"; host = "git.example"; }}"#
    );
    let error = eval_whnf_owned_with_options(
        &lower(&restricted_source),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted forge fetchTree rejects before archive access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}").as_bytes()
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!(
            "github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"
        ))
        .expect("canonical forge URI is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(&lower(&restricted_source), options)
        .expect_err("custom forge host requires archive URL authorization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("https://git.example/api/v3/repos/NixOS/nixpkgs/tarball/{rev}").as_bytes()
    ));

    let restricted_gitlab_source = format!(
        r#"builtins.fetchTree {{ type = "gitlab"; owner = "NixOS"; repo = "nixpkgs"; rev = "{rev}"; narHash = "{nar_hash}"; host = "git.example"; }}"#
    );
    let error = eval_whnf_owned_with_options(
        &lower(&restricted_gitlab_source),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted GitLab fetchTree rejects before archive access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}").as_bytes()
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!(
            "gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"
        ))
        .expect("canonical GitLab forge URI is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(&lower(&restricted_gitlab_source), options)
        .expect_err("custom GitLab host requires archive URL authorization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("https://git.example/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={rev}").as_bytes()
    ));

    let restricted_dir_source = format!(
        r#"builtins.fetchTree "github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}""#
    );
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!(
            "github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"
        ))
        .expect("forge URI without dir is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(&lower(&restricted_dir_source), options)
        .expect_err("restricted forge fetchTree canonical URI includes dir metadata");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}").as_bytes()
    ));

    for (source, allowed_uri, denied_uri) in [
        (
            format!(
                r#"builtins.fetchTree {{ type = "github"; owner = "NixOS"; repo = "nixpkgs"; rev = "{rev}"; narHash = "{nar_hash}"; dir = "lib"; }}"#
            ),
            format!("github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
        ),
        (
            format!(
                r#"builtins.fetchTree {{ type = "gitlab"; owner = "NixOS"; repo = "nixpkgs"; rev = "{rev}"; narHash = "{nar_hash}"; dir = "lib"; }}"#
            ),
            format!("gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("gitlab:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
        ),
        (
            format!(
                r#"builtins.fetchTree {{ type = "sourcehut"; owner = "~andyl"; repo = "aos"; rev = "{rev}"; narHash = "{nar_hash}"; dir = "lib"; }}"#
            ),
            format!("sourcehut:~andyl/aos/{rev}?narHash={nar_hash_query}"),
            format!("sourcehut:~andyl/aos/{rev}?dir=lib&narHash={nar_hash_query}"),
        ),
    ] {
        let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
        options
            .add_allowed_uri(allowed_uri)
            .expect("forge URI without dir is a valid allowed URI prefix");
        let error = eval_whnf_owned_with_options(&lower(&source), options)
            .expect_err("restricted attrset forge fetchTree canonical URI includes dir metadata");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::FetchTreeAccessDenied {
                input,
                mode: EvalMode::Restricted,
                ..
            } if input == denied_uri.as_bytes()
        ));
    }

    for source in [
        format!(
            r#"builtins.fetchTree {{ type = "gitlab"; owner = "group"; repo = "project/private"; rev = "{rev}"; narHash = "{nar_hash}"; }}"#
        ),
        format!(
            r#"builtins.fetchTree {{ type = "gitlab"; owner = ""; repo = "project"; rev = "{rev}"; narHash = "{nar_hash}"; }}"#
        ),
        format!(
            r#"builtins.fetchTree {{ type = "gitlab"; owner = "group"; repo = ""; rev = "{rev}"; narHash = "{nar_hash}"; }}"#
        ),
    ] {
        let error = eval_whnf_owned(&lower(&source))
            .expect_err("forge owner and repo must be single path segments");
        assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));
    }

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!(
            "gitlab:group/project/{rev}?narHash={nar_hash_query}"
        ))
        .expect("canonical gitlab forge URI is a valid allowed URI prefix");
    let source = format!(
        r#"builtins.fetchTree {{ type = "gitlab"; owner = "group"; repo = "project/private"; rev = "{rev}"; narHash = "{nar_hash}"; }}"#
    );
    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("slash-bearing forge repo rejects before restricted prefix can overmatch");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    let pure_source = format!(r#"builtins.fetchTree "github:NixOS/nixpkgs/{rev}""#);
    let error = eval_whnf_owned_with_options(
        &lower(&pure_source),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure forge fetchTree requires a narHash lock");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLockedInputRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    for (source, expected_input) in [
        (
            format!(r#"builtins.fetchTree "github:NixOS/nixpkgs/main?narHash={nar_hash_query}""#),
            format!("github:NixOS/nixpkgs/main?narHash={nar_hash_query}"),
        ),
        (
            format!(
                r#"builtins.fetchTree {{ type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "main"; narHash = "{nar_hash}"; }}"#
            ),
            format!("github:NixOS/nixpkgs/main?narHash={nar_hash_query}"),
        ),
        (
            format!(r#"builtins.fetchTree "gitlab:NixOS/nixpkgs/main?narHash={nar_hash_query}""#),
            format!("gitlab:NixOS/nixpkgs/main?narHash={nar_hash_query}"),
        ),
        (
            format!(
                r#"builtins.fetchTree {{ type = "gitlab"; owner = "NixOS"; repo = "nixpkgs"; ref = "main"; narHash = "{nar_hash}"; }}"#
            ),
            format!("gitlab:NixOS/nixpkgs/main?narHash={nar_hash_query}"),
        ),
    ] {
        let error = eval_whnf_owned_with_options(
            &lower(&source),
            TreeWalkOptions::with_eval_mode(EvalMode::Pure),
        )
        .expect_err("pure forge fetchTree rejects mutable refs even with narHash");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::FetchTreeLockedInputRequired {
                    input,
                    mode: EvalMode::Pure,
                    ..
                } if input == expected_input.as_bytes()
            ),
            "{source}: {error:?}",
        );
    }

    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchTree "github:NixOS/nixpkgs/main""#),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted unresolved forge ref denies its canonical URI");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == b"github:NixOS/nixpkgs/main"
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri("sourcehut:~andyl/aos/main")
        .expect("unresolved sourcehut URI is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchTree "sourcehut:~andyl/aos/main""#),
        options,
    )
    .expect_err("allowed unresolved forge ref still needs resolution support");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "forge reference resolution",
            ..
        }
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri("sourcehut:~andyl/aos/main?dir=lib")
        .expect("dir-bearing forge URI is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchTree "sourcehut:~andyl/aos/main?dir=lib""#),
        options,
    )
    .expect_err("unresolved forge access drops dir metadata");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == b"sourcehut:~andyl/aos/main"
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri("sourcehut:~andyl/aos/main")
        .expect("dir-stripped forge URI is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchTree "sourcehut:~andyl/aos/main?dir=lib""#),
        options,
    )
    .expect_err("allowed unresolved forge ref still needs resolution support");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "forge reference resolution",
            ..
        }
    ));
}

#[test]
fn fetch_tree_github_refs_resolve_with_test_url_responses() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-github-ref");
    let archive_bytes = fs::read(&archive_path).expect("archive fixture reads");
    let store_dir = unique_temp_dir("fetch-tree-github-ref-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let resolved_rev = "0123456789abcdef0123456789abcdef01234567";
    let recursive_nar_hash = "sha256-2huQKpXoKVd3jyPd2WSNvpaYPRMVWmOk+ehCZVNq3KI=";
    let recursive_nar_hash_query =
        url::form_urlencoded::byte_serialize(recursive_nar_hash.as_bytes()).collect::<String>();

    options.add_fetch_tree_url_response(
        "https://api.github.com/repos/NixOS/nixpkgs/commits/main",
        format!(r#"{{"sha":"{resolved_rev}"}}"#).into_bytes(),
    );
    options.add_fetch_tree_url_response(
        format!("https://github.com/NixOS/nixpkgs/archive/{resolved_rev}.tar.gz"),
        archive_bytes,
    );

    let source = format!(
        r#"
            let x = builtins.fetchTree "github:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}";
            in {{
              data = builtins.readFile "${{x.outPath}}/file.txt";
              nested = builtins.readFile "${{x.outPath}}/sub/nested.txt";
              rev = x.rev;
              shortRev = x.shortRev;
              narHash = x.narHash;
            }}
            "#
    );
    let json = eval_json_bytes_with_options(&source, options.clone());
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("GitHub fetchTree JSON parses");
    assert_eq!(value["data"], "data");
    assert_eq!(value["nested"], "inner");
    assert_eq!(value["rev"], resolved_rev);
    assert_eq!(value["shortRev"], &resolved_rev[..7]);
    assert_eq!(value["narHash"], recursive_nar_hash);

    let mut restricted_options = options;
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(format!(
            "github:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}"
        ))
        .expect("restricted GitHub ref URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(
            r#"let x = builtins.fetchTree "github:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}"; in x.rev"#
        ),
        restricted_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(resolved_rev).expect("rev JSON serializes")
    );

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_gitlab_refs_resolve_with_test_url_responses() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-gitlab-ref");
    let archive_bytes = fs::read(&archive_path).expect("archive fixture reads");
    let store_dir = unique_temp_dir("fetch-tree-gitlab-ref-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let resolved_rev = "0123456789abcdef0123456789abcdef01234567";
    let recursive_nar_hash = "sha256-2huQKpXoKVd3jyPd2WSNvpaYPRMVWmOk+ehCZVNq3KI=";
    let recursive_nar_hash_query =
        url::form_urlencoded::byte_serialize(recursive_nar_hash.as_bytes()).collect::<String>();

    options.add_fetch_tree_url_response(
        "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/commits/main",
        format!(r#"{{"id":"{resolved_rev}"}}"#).into_bytes(),
    );
    options.add_fetch_tree_url_response(
            format!(
                "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={resolved_rev}"
            ),
            archive_bytes,
        );

    let source = format!(
        r#"
            let x = builtins.fetchTree "gitlab:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}";
            in {{
              data = builtins.readFile "${{x.outPath}}/file.txt";
              nested = builtins.readFile "${{x.outPath}}/sub/nested.txt";
              rev = x.rev;
              shortRev = x.shortRev;
              narHash = x.narHash;
            }}
            "#
    );
    let json = eval_json_bytes_with_options(&source, options.clone());
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("GitLab fetchTree JSON parses");
    assert_eq!(value["data"], "data");
    assert_eq!(value["nested"], "inner");
    assert_eq!(value["rev"], resolved_rev);
    assert_eq!(value["shortRev"], &resolved_rev[..7]);
    assert_eq!(value["narHash"], recursive_nar_hash);

    let mut restricted_options = options;
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(format!(
            "gitlab:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}"
        ))
        .expect("restricted GitLab ref URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(
            r#"let x = builtins.fetchTree "gitlab:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}"; in x.rev"#
        ),
        restricted_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(resolved_rev).expect("rev JSON serializes")
    );

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_validates_input_shape() {
    let dir = unique_temp_dir("fetch-tree-invalid");
    fs::write(dir.join("data.txt"), b"data").expect("source file writes");
    let path = nix_string_literal(&path_source(&dir));

    let error = eval_whnf_owned(&lower(&format!(
        r#"builtins.fetchTree {{ type = "path"; path = {path}; bogus = 1; }}"#
    )))
    .expect_err("unknown fetchTree attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let error = eval_whnf_owned(&lower(&format!(
        r#"builtins.fetchTree {{ type = "path"; path = {path}; name = "bad"; }}"#
    )))
    .expect_err("fetchTree rejects name attr");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeAttr { attr, .. }
            if attr.as_slice() == b"name"
    ));

    let error = eval_whnf_owned(&lower(&format!(
        r#"builtins.fetchTree {{ path = {path}; }}"#
    )))
    .expect_err("fetchTree requires type attr");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; }"#,
    ))
    .expect_err("unresolved forge fetchTree rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "forge inputs without a resolved rev",
            ..
        }
    ));

    for (source, expected_uri) in [
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; }"#,
                b"github:NixOS/nixpkgs".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "main"; dir = "lib"; }"#,
                b"github:NixOS/nixpkgs/main".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "main"; dir = "lib"; narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; }"#,
                b"github:NixOS/nixpkgs/main?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = ""; }"#,
                b"github:NixOS/nixpkgs/".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "bad?ref"; }"#,
                b"github:NixOS/nixpkgs/bad%3Fref".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = ""; repo = "nixpkgs"; }"#,
                b"github:/nixpkgs".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "gitlab"; owner = "group"; repo = "project/private"; }"#,
                b"gitlab:group/project/private".as_slice(),
            ),
            (
                r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; host = "bad host"; }"#,
                b"github:NixOS/nixpkgs".as_slice(),
            ),
        ] {
            let error = eval_whnf_owned_with_options(
                &lower(source),
                TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
            )
            .expect_err("restricted unresolved forge attrset denies its canonical URI");
            assert!(matches!(
                error.kind(),
                TreeWalkErrorKind::FetchTreeAccessDenied {
                    input,
                    mode: EvalMode::Restricted,
                    ..
                } if input == expected_uri
            ));
        }

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri("sourcehut:")
        .expect("sourcehut URI prefix is a valid allowed URI");
    for source in [
        r#"builtins.fetchTree { type = "sourcehut"; owner = "~andyl"; repo = "aos"; ref = ""; }"#,
        r#"builtins.fetchTree { type = "sourcehut"; owner = "~andyl"; repo = "aos"; ref = "bad?ref"; }"#,
    ] {
        let error = eval_whnf_owned_with_options(&lower(source), options.clone())
            .expect_err("allowed unresolved forge attrset still needs resolution support");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedFetchTreeFeature {
                feature: "forge reference resolution",
                ..
            }
        ));
    }

    let error = eval_whnf_owned(&lower(
            r#"builtins.fetchTree { type = "git"; url = "file:///no-such-repo"; verifyCommit = true; }"#,
        ))
        .expect_err("unsupported fetchTree verified git fetch rejects before repo access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "verified git fetches",
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            r#"builtins.fetchTree { type = "git"; url = "file:///no-such-repo"; verifyCommit = false; publicKey = 1; }"#,
        ))
        .expect_err("fetchTree publicKey must be a string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            r#"builtins.fetchTree { type = "git"; url = "file:///no-such-repo"; verifyCommit = false; publicKeys = [ { key = 1; type = "ssh-ed25519"; } ]; }"#,
        ))
        .expect_err("fetchTree publicKeys entries must carry string keys");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(r#"builtins.fetchTree "github:NixOS/nixpkgs""#))
        .expect_err("unsupported string flake ref type rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "forge inputs without a resolved rev",
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetch_tarball_primop_unpacks_root_and_hashes_recursive_tree() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball");
    let store_dir = unique_temp_dir("fetch-tarball-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let path = eval_string_bytes_with_options(
        &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
        options.clone(),
    );
    let path_text = std::str::from_utf8(&path)
        .expect("store path is UTF-8")
        .to_owned();
    assert!(path_text.starts_with(path_source(&store_dir).as_str()));
    assert!(path_text.ends_with("-source"));
    assert_eq!(
        fs::read(PathBuf::from(&path_text).join("file.txt"))
            .expect("fetchTarball materializes root-stripped file"),
        b"data"
    );
    assert_eq!(
        fs::read(PathBuf::from(&path_text).join("sub").join("nested.txt"))
            .expect("fetchTarball materializes nested file"),
        b"inner"
    );

    assert_eq!(
        eval_json_bytes_with_options(
            &format!(
                r#"builtins.readDir (builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }})"#
            ),
            options,
        ),
        br#"{"file.txt":"regular","sub":"directory"}"#.to_vec()
    );

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tarball_primop_sniffs_extensionless_archives() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-extensionless");
    let extensionless_path = archive_dir.join("archive");
    fs::copy(&archive_path, &extensionless_path).expect("extensionless tarball copies");
    let store_dir = unique_temp_dir("fetch-tarball-extensionless-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&extensionless_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let path = eval_string_bytes_with_options(
        &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
        options,
    );
    let path_text = std::str::from_utf8(&path).expect("store path is UTF-8");
    assert_eq!(
        fs::read(PathBuf::from(path_text).join("file.txt"))
            .expect("extensionless fetchTarball materializes file"),
        b"data"
    );

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tarball_reuse_trusts_only_default_nix_store_paths() {
    let default_eval = TreeWalk::new(&lower("null"));
    assert!(
        default_eval.should_query_default_nix_store_for_fetch_tarball_path(
            b"/nix/store/00000000000000000000000000000000-source"
        )
    );
    assert!(!default_eval.can_trust_existing_fetch_tarball_store_path(
        b"/nix/store/00000000000000000000000000000000-source"
    ));
    assert!(
        !default_eval
            .should_query_default_nix_store_for_fetch_tarball_path(b"/tmp/store/not-a-store-path")
    );

    let store_dir = unique_temp_dir("fetch-tarball-trust-store");
    let custom_options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let custom_eval = TreeWalk::with_options(&lower("null"), custom_options);
    assert!(
        !custom_eval.should_query_default_nix_store_for_fetch_tarball_path(
            b"/nix/store/00000000000000000000000000000000-source"
        )
    );
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tarball_default_store_validity_pins_local_store_and_scrubs_env() {
    let command =
        TreeWalk::nix_store_validity_command("/nix/store/00000000000000000000000000000000-source");
    let args = command
        .get_args()
        .map(|arg| arg.as_bytes())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        [
            b"--store".as_slice(),
            b"daemon".as_slice(),
            b"--check-validity".as_slice(),
            b"/nix/store/00000000000000000000000000000000-source".as_slice(),
        ]
    );
    for (key, value) in [
        ("HOME", "/var/empty"),
        ("XDG_CONFIG_HOME", "/var/empty/.config"),
        ("XDG_CONFIG_DIRS", "/var/empty"),
        ("NIX_USER_CONF_FILES", ""),
    ] {
        assert!(
            matches!(
                command.get_envs().find(|(name, _)| *name == key),
                Some((_, Some(found))) if found == std::ffi::OsStr::new(value)
            ),
            "{key} should be pinned for nix-store validity checks"
        );
    }
    for key in [
        "AOS_NIX_NATIVE",
        "AOS_NIX_NATIVE_VERIFY",
        "NIX_REMOTE",
        "NIX_CONFIG",
        "NIX_CONF_DIR",
        "NIX_STORE_DIR",
        "NIX_STATE_DIR",
        "NIX_LOG_DIR",
    ] {
        assert!(
            matches!(
                command.get_envs().find(|(name, _)| *name == key),
                Some((_, None))
            ),
            "{key} should be explicitly removed from nix-store validity checks"
        );
    }
}

#[test]
fn fetch_tarball_primop_rejects_unwritable_store_materialization() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-unwritable-store");
    let store_dir = unique_temp_dir("fetch-tarball-unwritable-store-root");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o555))
        .expect("store directory permissions tighten");

    let result = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#
        )),
        options,
    );

    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o755))
        .expect("store directory permissions restore");
    let error = result.expect_err("unwritable store rejects fetchTarball materialization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarball { .. }
    ));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tarball_primop_rejects_corrupt_existing_store_path() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-corrupt-store");
    let store_dir = unique_temp_dir("fetch-tarball-corrupt-store-root");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";
    let source =
        format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#);
    let path = eval_string_bytes_with_options(&source, options.clone());
    let path_text = std::str::from_utf8(&path)
        .expect("store path is UTF-8")
        .to_owned();
    fs::remove_file(PathBuf::from(&path_text).join("sub").join("nested.txt"))
        .expect("materialized store path corrupts");

    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("corrupt existing fetchTarball store path rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballHashMismatch { .. }
    ));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tarball_primop_validates_arguments_and_hashes() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-invalid");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let ir = lower(&format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "0000000000000000000000000000000000000000000000000000000000000000"; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("hash mismatch rejects fetchTarball");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballHashMismatch { .. }
    ));

    let ir = lower(&format!(
        "builtins.fetchTarball {{ url = {url}; sha256 = \"\"; }}"
    ));
    let mut evaluator = TreeWalk::new(&ir);
    let error = evaluator
        .eval_root()
        .expect_err("empty fetchTarball hash warns and mismatches real content");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballHashMismatch { expected, .. }
            if expected.as_slice() == [0_u8; 32]
    ));
    assert_eq!(evaluator.warning_output().len(), 1);
    assert_warning_output(
        evaluator
            .warning_output()
            .first()
            .expect("warning output exists"),
        EMPTY_FETCHURL_SHA256_WARNING,
    );

    let ir = lower(&format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; bogus = 1; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("unknown fetchTarball attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTarballAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let ir = lower(&format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; name = "bad/name"; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("invalid store name rejects fetchTarball");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballStoreName { .. }
    ));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
}

#[test]
fn fetch_tarball_primop_obeys_eval_mode_gates() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-mode");
    let store_dir = unique_temp_dir("fetch-tarball-mode-store");
    let path = path_source(&archive_path);
    let url = nix_string_literal(&format!("file://{path}"));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let error = eval_whnf_owned_with_options(
        &lower(&format!("builtins.fetchTarball {url}")),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure eval rejects unpinned fetchTarball before URL access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballHashRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    let mut pure_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    pure_options.set_eval_mode(EvalMode::Pure);
    assert!(
        String::from_utf8(eval_string_bytes_with_options(
            &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
            pure_options,
        ))
        .expect("store path is UTF-8")
        .ends_with("-source")
    );

    let error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted eval rejects disallowed file fetchTarball");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            path: denied,
            mode: EvalMode::Restricted,
            ..
        } if denied.as_slice() == path.as_bytes()
    ));

    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    options.set_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(path.as_bytes().to_vec())
        .expect("allowed path accepts absolute path");
    assert!(
        String::from_utf8(eval_string_bytes_with_options(
            &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
            options,
        ))
        .expect("store path is UTF-8")
        .ends_with("-source")
    );

    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    options.set_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!("file://{path}").into_bytes())
        .expect("file URL prefix configures as allowed URI");
    assert!(
        String::from_utf8(eval_string_bytes_with_options(
            &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
            options,
        ))
        .expect("store path is UTF-8")
        .ends_with("-source")
    );

    let error = eval_whnf_owned_with_options(
            &lower(
                r#"builtins.fetchTarball { url = "https://cache.example/src.tar.gz"; sha256 = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2"; }"#,
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
        )
        .expect_err("restricted eval rejects disallowed network fetchTarball before network access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn path_primop_supports_flat_hashing_and_sha256_checks() {
    let (dir, path) = temp_file_with_bytes("path-primop-flat", b"abc");
    let path = path_source(&path);
    let recursive_digest = "11a71b4754d812f4aea20161c533bdaa112ac5c853013e65d3aa9640b5735230";
    let flat_digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {path}; sha256 = \"{recursive_digest}\"; }}"
        )),
        b"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {path}; recursive = false; }}"
        )),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {path}; recursive = false; sha256 = \"{flat_digest}\"; }}"
        )),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt"
    );

    let ir = lower(&format!(
        "builtins.path {{ path = {path}; sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("sha256 mismatch rejects source path");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::SourcePathHashMismatch { .. }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn filter_source_primop_filters_recursive_source_trees() {
    let dir = unique_temp_dir("filter-source");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("tree directory creates");
    fs::write(tree.join("a"), b"one").expect("included file writes");
    fs::write(tree.join("b"), b"two").expect("excluded file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.hasContext path == false && builtins.baseNameOf path == "a""#;

    let filtered = eval_string_bytes(&format!("builtins.filterSource ({keep}) {tree}"));
    assert_eq!(
        filtered,
        eval_string_bytes(&format!(
            "builtins.path {{ path = {tree}; filter = ({keep}); }}"
        ))
    );
    assert_eq!(
        filtered,
        eval_string_bytes(&format!(
            "let filterSource = builtins.filterSource; in filterSource ({keep}) {tree}"
        ))
    );
    assert_ne!(
        filtered,
        eval_string_bytes(&format!("builtins.path {{ path = {tree}; }}"))
    );
    assert!(
        String::from_utf8(filtered)
            .expect("store path is UTF-8")
            .ends_with("-tree")
    );

    let traced = eval_owned(&format!(
        "builtins.path {{ path = {tree}; filter = path: type: builtins.trace (builtins.baseNameOf path) true; }}"
    ));
    let traces = traced.trace_output();
    assert_eq!(traces.len(), 2);
    assert_trace_output(&traces[0], EvalTraceKind::Trace, b"a");
    assert_trace_output(&traces[1], EvalTraceKind::Trace, b"b");

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn filter_source_does_not_filter_root_files() {
    let (dir, path) = temp_file_with_bytes("filter-source-root-file", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.filterSource (path: type: builtins.throw \"called\") {path}"
        )),
        b"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_primop_rejects_invalid_arguments() {
    let dir = unique_temp_dir("path-primop-invalid");
    let file = dir.join("data.txt");
    fs::write(&file, b"abc").expect("temp file writes");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("tree directory creates");
    fs::write(tree.join("data.txt"), b"abc").expect("tree file writes");
    let file = path_source(&file);
    let tree = path_source(&tree);

    let ir = lower(&format!("builtins.path {{ path = {file}; bogus = 1; }}"));
    let error = eval_whnf_owned(&ir).expect_err("unknown path attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedSourcePathAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let ir = lower(&format!(
        "builtins.path {{ path = {file}; filter = null; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("filter must be callable");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Null,
            ..
        }
    ));

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {file}; recursive = false; filter = path: type: builtins.throw \"called\"; }}"
        )),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt"
    );

    let ir = lower(&format!(
        "builtins.path {{ path = {tree}; recursive = false; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("flat directory source paths reject");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::SourcePathArchive { .. }
    ));

    let ir = lower(&format!("builtins.filterSource null {file}"));
    let error = eval_whnf_owned(&ir).expect_err("filterSource filter must be callable");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Null,
            ..
        }
    ));

    for source in [
        r#"builtins.filterSource null (builtins.throw "path")"#,
        r#"let filterSource = builtins.filterSource; in filterSource null (builtins.throw "path")"#,
    ] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("filterSource forces path before filter");
        assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
    }

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_store_coercion_rejects_invalid_source_store_names() {
    let dir = unique_temp_dir("invalid-store-name");
    let path = dir.join("a b.txt");
    fs::write(&path, b"abc").expect("temp file writes");
    let source = format!(
        r#"let p = builtins.findFile [ {{ path = {}; }} ] "a b.txt"; in "${{p}}""#,
        nix_string_literal(&path_source(&dir))
    );
    let ir = lower(&source);
    let error = eval_whnf_owned(&ir).expect_err("invalid source names reject store coercion");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::SourcePathStoreName { .. }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn string_coercion_primops_accept_paths_without_store_copy() {
    let (dir, path) = temp_file_with_bytes("path-string-coercion", b"abc");
    let path = path_source(&path);
    let expected_dir = path_source(&dir);

    assert_eq!(
        eval_string_bytes(&format!("builtins.toString {path}")),
        path.as_bytes()
    );
    assert_eq!(
        eval(&format!("builtins.stringLength {path}")).as_int(),
        Ok(path.len() as i64)
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.substring 0 1 {path}")),
        b"/"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.concatStringsSep \",\" [ \"x\" {path} ]")),
        format!("x,{path}").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.baseNameOf {path}")),
        b"data.txt"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.typeOf (builtins.dirOf {path})")),
        b"path"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString (builtins.dirOf {path})")),
        expected_dir.as_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn hash_file_primop_hashes_file_contents() {
    let (dir, path) = temp_file_with_bytes("hash-file", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_string_bytes(&format!("builtins.hashFile \"md5\" {path}")),
        b"900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.hashFile \"sha1\" {path}")),
        b"a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.hashFile \"sha256\" {path}")),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
            eval_string_bytes(&format!("builtins.hashFile \"sha512\" {path}")),
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.hashFile \"sha256\" {}",
            nix_string_literal(&path)
        )),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.hashFile \"sha256\" {{ outPath = {}; }}",
            nix_string_literal(&path)
        )),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.hashFile "sha256" (builtins.toFile "x" "abc")"#),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { hashFile = type: path: \"local\"; }; in builtins.hashFile \"sha256\" \"relative.txt\""
        ),
        b"local"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn hash_file_primop_rejects_context_bearing_algorithm() {
    let ir = lower("builtins.hashFile \"sha256\" ./crates/Cargo.toml");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"sha256".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing algorithm allocates");

    let error = evaluator
        .eval_hash_algorithm(algorithm, algorithm_span, value, "hashFile")
        .expect_err("hashFile rejects algorithm string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: algorithm,
            op: "hashFile",
        }
    );
    assert_eq!(error.span(), algorithm_span);
}

#[test]
fn hash_file_primop_checks_algorithm_before_path() {
    let ir = lower("builtins.hashFile \"bad\" (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("unknown algorithm is rejected first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"bad".to_vec(),
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let error = eval_whnf_owned(&lower("builtins.hashFile \"sha256\" (1 / 0)"))
        .expect_err("valid algorithm demands path argument");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn hash_file_primop_rejects_relative_strings() {
    let ir = lower("builtins.hashFile \"sha256\" \"relative.txt\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let path = args[1];
    let path_span = ir.arena.node(path).expect("path exists").span;

    let error = eval_whnf_owned(&ir).expect_err("relative strings are rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathNotAbsolute {
            id: path,
            path: b"relative.txt".to_vec(),
        }
    );
    assert_eq!(error.span(), path_span);
}

#[test]
fn hash_file_primop_reports_file_read_errors() {
    let dir = unique_temp_dir("hash-file-missing");
    let path = path_source(&dir.join("missing.txt"));
    let ir = lower(&format!(
        "builtins.hashFile \"sha256\" {}",
        nix_string_literal(&path)
    ));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let path_id = args[1];
    let path_span = ir.arena.node(path_id).expect("path exists").span;

    let error = eval_whnf_owned(&ir).expect_err("missing file is reported");

    match error.kind() {
        TreeWalkErrorKind::FileRead {
            id,
            path: actual,
            message,
        } => {
            assert_eq!(id, path_id);
            assert_eq!(actual.as_slice(), path.as_bytes());
            assert!(!message.is_empty());
        }
        other => panic!("expected file-read error, got {other:?}"),
    }
    assert_eq!(error.span(), path_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_blocks_unallowed_filesystem_reads() {
    let (dir, path) = temp_file_with_bytes("fs-policy-denied", b"abc");
    let path = path_source(&path);
    let source = format!("builtins.readFile {}", nix_string_literal(&path));
    let ir = lower(&source);
    let (argument, argument_span) = primop_argument(&ir, 0);

    let error =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Restricted))
            .expect_err("restricted mode rejects unallowed reads");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            id: argument,
            path: path.as_bytes().to_vec(),
            mode: EvalMode::Restricted,
        }
    );
    assert_eq!(error.span(), argument_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_allows_configured_roots() {
    let dir = unique_temp_dir("fs-policy-allowed");
    let regular = dir.join("regular.txt");
    fs::write(&regular, b"abc").expect("regular file writes");
    let dir_path = path_source(&dir);
    let file_path = path_source(&regular);
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(dir.as_os_str().as_bytes().to_vec())
        .expect("allowed root configures");

    assert_eq!(
        eval_string_bytes_with_options(
            &format!("builtins.readFile {}", nix_string_literal(&file_path)),
            options.clone(),
        ),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                "builtins.hashFile \"sha256\" {}",
                nix_string_literal(&file_path)
            ),
            options.clone(),
        ),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            &format!("builtins.readFileType {}", nix_string_literal(&file_path)),
            options.clone(),
        ),
        b"regular"
    );
    assert_eq!(
        eval_list_string_bytes_with_options(
            &format!(
                "builtins.attrNames (builtins.readDir {})",
                nix_string_literal(&dir_path)
            ),
            options.clone(),
        ),
        vec![b"regular.txt".to_vec()]
    );
    assert_eq!(
        eval_with_options(
            &format!("builtins.pathExists {}", nix_string_literal(&file_path)),
            options,
        )
        .as_bool(),
        Ok(true)
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_normalizes_paths_before_matching() {
    let base = unique_temp_dir("fs-policy-normalized");
    let allowed = base.join("allowed");
    let sibling = base.join("allowed-sibling");
    fs::create_dir(&allowed).expect("allowed directory creates");
    fs::create_dir(&sibling).expect("sibling directory creates");
    fs::write(allowed.join("data.txt"), b"allowed").expect("allowed file writes");
    fs::write(sibling.join("data.txt"), b"denied").expect("sibling file writes");
    let allowed_path = path_source(&allowed);
    let allowed_with_parent = format!("{allowed_path}/../allowed/data.txt");
    let sibling_path = path_source(&sibling.join("data.txt"));
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(allowed.as_os_str().as_bytes().to_vec())
        .expect("allowed root configures");

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                "builtins.readFile {}",
                nix_string_literal(&allowed_with_parent)
            ),
            options.clone(),
        ),
        b"allowed"
    );

    let source = format!("builtins.readFile {}", nix_string_literal(&sibling_path));
    let ir = lower(&source);
    let error = eval_whnf_owned_with_options(&ir, options)
        .expect_err("sibling prefix is not under the allowed root");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    fs::remove_dir_all(base).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_blocks_resolved_symlink_escapes() {
    let base = unique_temp_dir("fs-policy-symlink");
    let allowed = base.join("allowed");
    let outside = base.join("outside.txt");
    let link = allowed.join("link.txt");
    fs::create_dir(&allowed).expect("allowed directory creates");
    fs::write(&outside, b"outside").expect("outside file writes");
    std::os::unix::fs::symlink(&outside, &link).expect("escape symlink creates");
    let link_path = path_source(&link);
    let outside_path = fs::canonicalize(&outside).expect("outside path resolves");
    let outside_path = normalize_absolute_path_bytes(outside_path.as_os_str().as_bytes());
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(allowed.as_os_str().as_bytes().to_vec())
        .expect("allowed root configures");

    let source = format!("builtins.readFile {}", nix_string_literal(&link_path));
    let ir = lower(&source);
    let error = eval_whnf_owned_with_options(&ir, options)
        .expect_err("symlink escapes outside allowed roots are rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            id: primop_argument(&ir, 0).0,
            path: outside_path,
            mode: EvalMode::Restricted,
        }
    );

    fs::remove_dir_all(base).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_gates_find_file_candidates() {
    let base = unique_temp_dir("fs-policy-find-file");
    let root = base.join("nixpkgs");
    fs::create_dir(&root).expect("search root creates");
    fs::write(root.join("default.nix"), b"{ }").expect("search file writes");
    let root_path = path_source(&root);
    let source = format!(
        r#"builtins.typeOf (builtins.findFile [ {{ prefix = "nixpkgs"; path = {}; }} ] "nixpkgs/default.nix")"#,
        nix_string_literal(&root_path)
    );
    let ir = lower(&source);

    let error =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Restricted))
            .expect_err("restricted mode rejects unallowed findFile candidates");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(root.as_os_str().as_bytes().to_vec())
        .expect("allowed root configures");
    assert_eq!(eval_string_bytes_with_options(&source, options), b"path");

    fs::remove_dir_all(base).expect("temp directory removes");
}

#[test]
fn filesystem_access_policy_blocks_source_path_serialization() {
    let (dir, path) = temp_file_with_bytes("fs-policy-source-path", b"abc");
    let path_source = path_source(&path);
    let source = format!("\"${{{path_source}}}\"");
    let ir = lower(&source);

    let error =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Restricted))
            .expect_err("restricted mode rejects unallowed source path serialization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(dir.as_os_str().as_bytes().to_vec())
        .expect("allowed source root configures");
    assert_eq!(
        eval_string_bytes_with_options(&source, options),
        b"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_exists_primop_checks_filesystem_presence() {
    let dir = unique_temp_dir("path-exists");
    let file = dir.join("regular.txt");
    let dangling = dir.join("dangling");
    fs::write(&file, b"data").expect("regular file writes");
    std::os::unix::fs::symlink(dir.join("missing-target"), &dangling)
        .expect("dangling symlink creates");
    let dir_path = path_source(&dir);
    let file_path = path_source(&file);
    let dangling_path = path_source(&dangling);
    let missing_path = path_source(&dir.join("missing.txt"));

    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&file_path)
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&missing_path)
        ))
        .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&dangling_path)
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{dangling_path}/"))
        ))
        .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{dir_path}/"))
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{file_path}/"))
        ))
        .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {}",
            nix_string_literal(&format!("{file_path}/."))
        ))
        .as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {{ outPath = {}; }}",
            nix_string_literal(&format!("{file_path}/"))
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "builtins.pathExists {{ outPath = {}; }}",
            nix_string_literal(&format!("{file_path}/."))
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!(
            "let f = builtins.pathExists; in f {}",
            nix_string_literal(&file_path)
        ))
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let builtins = { pathExists = path: false; }; in builtins.pathExists \"/\"")
            .as_bool(),
        Ok(false)
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_exists_primop_type_checks_and_rejects_relative_strings() {
    let ir = lower("builtins.pathExists 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("pathExists requires a path");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.pathExists \"relative.txt\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("relative strings are rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathNotAbsolute {
            id: argument,
            path: b"relative.txt".to_vec(),
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn read_file_type_primop_reports_filesystem_node_types() {
    let dir = unique_temp_dir("read-file-type");
    let regular = dir.join("regular");
    let nested = dir.join("nested");
    let link = dir.join("link");
    let link_dir = dir.join("link-dir");
    let dangling = dir.join("dangling");
    fs::write(&regular, b"data").expect("regular file writes");
    fs::create_dir(&nested).expect("nested directory creates");
    std::os::unix::fs::symlink(&regular, &link).expect("symlink creates");
    std::os::unix::fs::symlink(&nested, &link_dir).expect("directory symlink creates");
    std::os::unix::fs::symlink(dir.join("missing-target"), &dangling)
        .expect("dangling symlink creates");
    let regular_path = path_source(&regular);
    let nested_path = path_source(&nested);
    let link_path = path_source(&link);
    let link_dir_path = path_source(&link_dir);
    let dangling_path = path_source(&dangling);

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&regular_path)
        )),
        b"regular"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&nested_path)
        )),
        b"directory"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&link_path)
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{regular_path}/"))
        )),
        b"regular"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{regular_path}/."))
        )),
        b"regular"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{link_dir_path}/"))
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{link_dir_path}/."))
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{dangling_path}/"))
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&format!("{dangling_path}/."))
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let f = builtins.readFileType; in f {}",
            nix_string_literal(&regular_path)
        )),
        b"regular"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_file_type_primop_reports_stat_errors() {
    let dir = unique_temp_dir("read-file-type-missing");
    let missing_path = path_source(&dir.join("missing"));
    let ir = lower(&format!(
        "builtins.readFileType {}",
        nix_string_literal(&missing_path)
    ));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("missing path is reported");

    match error.kind() {
        TreeWalkErrorKind::PathStat { id, path, message } => {
            assert_eq!(id, argument);
            assert_eq!(path.as_slice(), missing_path.as_bytes());
            assert!(!message.is_empty());
        }
        other => panic!("expected stat error, got {other:?}"),
    }
    assert_eq!(error.span(), argument_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_dir_primop_lists_entry_types() {
    let dir = unique_temp_dir("read-dir");
    let regular = dir.join("regular");
    let nested = dir.join("nested");
    let link = dir.join("link");
    fs::write(&regular, b"data").expect("regular file writes");
    fs::create_dir(&nested).expect("nested directory creates");
    std::os::unix::fs::symlink(&regular, &link).expect("symlink creates");
    let dir_path = path_source(&dir);

    assert_eq!(
        eval_list_string_bytes(&format!(
            "builtins.attrNames (builtins.readDir {})",
            nix_string_literal(&dir_path)
        )),
        vec![b"link".to_vec(), b"nested".to_vec(), b"regular".to_vec()]
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "(builtins.readDir {}).link",
            nix_string_literal(&dir_path)
        )),
        b"symlink"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "(builtins.readDir {}).nested",
            nix_string_literal(&dir_path)
        )),
        b"directory"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "(builtins.readDir {}).regular",
            nix_string_literal(&dir_path)
        )),
        b"regular"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let f = builtins.readDir; d = f {}; in d.regular",
            nix_string_literal(&dir_path)
        )),
        b"regular"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_dir_primop_type_checks_and_reports_directory_errors() {
    let ir = lower("builtins.readDir 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("readDir requires a path");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let dir = unique_temp_dir("read-dir-file");
    let regular = dir.join("regular");
    fs::write(&regular, b"data").expect("regular file writes");
    let regular_path = path_source(&regular);
    let ir = lower(&format!(
        "builtins.readDir {}",
        nix_string_literal(&regular_path)
    ));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("file is not a directory");

    match error.kind() {
        TreeWalkErrorKind::DirectoryRead { id, path, message } => {
            assert_eq!(id, argument);
            assert_eq!(path.as_slice(), regular_path.as_bytes());
            assert!(!message.is_empty());
        }
        other => panic!("expected directory-read error, got {other:?}"),
    }
    assert_eq!(error.span(), argument_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn to_string_primop_converts_scalar_values() {
    assert_eq!(eval_string_bytes("builtins.toString \"x\""), b"x");
    assert_eq!(eval_string_bytes("builtins.toString 1"), b"1");
    assert_eq!(eval_string_bytes("builtins.toString (-2)"), b"-2");
    assert_eq!(
        eval_string_bytes("builtins.toString 9223372036854775807"),
        b"9223372036854775807"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString (-9223372036854775807 - 1)"),
        b"-9223372036854775808"
    );
    assert_eq!(eval_string_bytes("builtins.toString 1.0"), b"1.000000");
    assert_eq!(eval_string_bytes("builtins.toString 1.25"), b"1.250000");
    assert_eq!(
        eval_string_bytes("builtins.toString 1.23456789"),
        b"1.234568"
    );
    assert_eq!(eval_string_bytes("builtins.toString (-0.0)"), b"0.000000");
    assert_eq!(eval_string_bytes("builtins.toString 0.00001"), b"0.000010");
    assert_eq!(
        eval_string_bytes("builtins.toString 0.0000001"),
        b"0.000000"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString 1000000.0"),
        b"1000000.000000"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))"),
        b"nan"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString (1.0e308 * 1.0e308)"),
        b"inf"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString (builtins.sub 0.0 (1.0e308 * 1.0e308))"),
        b"-inf"
    );
    assert_eq!(eval_string_bytes("builtins.toString true"), b"1");
    assert_eq!(eval_string_bytes("builtins.toString false"), b"");
    assert_eq!(eval_string_bytes("builtins.toString null"), b"");
    assert_eq!(
        eval_string_bytes("let builtins = { toString = x: \"local\"; }; in builtins.toString 1"),
        b"local"
    );
}

#[test]
fn to_string_primop_flattens_lists_with_spaces() {
    assert_eq!(
        eval_string_bytes("builtins.toString [ 1 \"x\" true false null ]"),
        b"1 x 1  "
    );
    assert_eq!(
        eval_string_bytes("builtins.toString [ \"x\" [] \"y\" ]"),
        b"x y"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString [ \"x\" [ \"\" ] \"y\" ]"),
        b"x  y"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString [ [ \"a\" \"b\" ] [ \"c\" \"\" ] [ \"\" \"d\" ] ]"),
        b"a b c   d"
    );
    assert_eq!(eval_string_bytes("builtins.toString [ \"\" \"\" ]"), b" ");
}

#[test]
fn to_string_primop_coerces_attrsets_with_full_to_string_rules() {
    assert_eq!(
        eval_string_bytes("builtins.toString { __toString = self: 1; outPath = 1 / 0; }"),
        b"1"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString { __toString = self: [ \"a\" \"b\" ]; }"),
        b"a b"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString { outPath = [ \"a\" \"b\" ]; }"),
        b"a b"
    );
    assert_eq!(
        eval_string_bytes("builtins.toString [ \"x\" { __toString = self: []; } \"y\" ]"),
        b"x  y"
    );
}

#[test]
fn derivation_magic_attrs_are_ordinary_language_attrs() {
    let source = r#"let
             attrs = {
               __contentAddressed = "ca";
               __darwinAllowLocalNetworking = "net";
               __ignoreNulls = null;
               __impure = false;
               __structuredAttrs = "structured";
             };
             inherit (attrs)
               __contentAddressed
               __darwinAllowLocalNetworking
               __ignoreNulls
               __impure
               __structuredAttrs;
           in {
             ca = __contentAddressed;
             ignoredIsNull = __ignoreNulls == null;
             impure = __impure;
             names = builtins.attrNames attrs;
             net = __darwinAllowLocalNetworking;
             structured = __structuredAttrs;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"ca":"ca","ignoredIsNull":true,"impure":false,"names":["__contentAddressed","__darwinAllowLocalNetworking","__ignoreNulls","__impure","__structuredAttrs"],"net":"net","structured":"structured"}"#.to_vec()
        );
}

#[test]
fn to_string_primop_forces_arguments_and_rejects_non_coercible_values() {
    let ir = lower("builtins.toString [ \"a\" (1 / 0) ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let _argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("toString argument exists");

    let error = eval_whnf_owned(&ir).expect_err("toString forces list elements");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let ir = lower("builtins.toString (x: x)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("toString argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("functions are not string-coercible");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Lambda,
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower(r#"builtins.toString { __toString = "bad"; outPath = "fallback"; }"#);
    let error = eval_whnf_owned(&ir).expect_err("__toString takes precedence over outPath");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::String,
            ..
        }
    ));
}

#[test]
fn to_string_primop_preserves_string_contexts() {
    let ir = lower("builtins.toString []");
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
        .expect("toString argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let first_context =
        ContextElement::opaque_path(b"/nix/store/first".to_vec()).expect("first context builds");
    let second_context =
        ContextElement::opaque_path(b"/nix/store/second".to_vec()).expect("second context builds");
    let first = evaluator
        .heap
        .alloc_string(NixString::new(
            b"a".to_vec(),
            StringContext::singleton(first_context.clone()).expect("first context allocates"),
        ))
        .expect("first string allocates");
    let second = evaluator
        .heap
        .alloc_string(NixString::new(
            b"b".to_vec(),
            StringContext::singleton(second_context.clone()).expect("second context allocates"),
        ))
        .expect("second string allocates");
    let list = evaluator
        .heap
        .alloc_list(NixList::new(vec![first, Value::int(1), second]))
        .expect("list allocates");

    let result = evaluator
        .eval_to_string_primop(ir.root, root.span, argument, argument_span, list)
        .expect("toString evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result is a string");

    assert_eq!(string.bytes(), b"a 1 b");
    assert!(string.context().contains(&first_context));
    assert!(string.context().contains(&second_context));
}

#[test]
fn to_path_primop_returns_normalized_absolute_strings() {
    assert_eq!(
        eval_string_bytes(r#"builtins.toPath "/tmp/../var/./tmp//""#),
        b"/var/tmp"
    );
    assert_eq!(eval_string_bytes(r#"builtins.toPath "/""#), b"/");
    assert_eq!(eval_string_bytes("builtins.toPath /tmp"), b"/tmp");
    assert_eq!(
        eval_string_bytes(r#"let f = builtins.toPath; in f "/tmp/foo//bar""#),
        b"/tmp/foo/bar"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.typeOf (builtins.toPath "/tmp")"#),
        b"string"
    );
}

#[test]
fn to_path_primop_coerces_attrsets_and_preserves_context() {
    assert_eq!(
        eval_string_bytes(r#"builtins.toPath { outPath = "/tmp/from-out-path"; }"#),
        b"/tmp/from-out-path"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.toPath { __toString = self: "/tmp/from-to-string"; }"#),
        b"/tmp/from-to-string"
    );
    assert_eq!(
        eval_json_bytes(
            r#"builtins.getContext (
                    builtins.toPath (
                        builtins.appendContext "/tmp/from-context" {
                            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = {
                                path = true;
                            };
                        }
                    )
                )"#
        ),
        br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true}}"#.to_vec()
    );
}

#[test]
fn to_path_primop_rejects_non_absolute_or_non_coercible_values() {
    let error = eval_whnf_owned(&lower(r#"builtins.toPath "relative/path""#))
        .expect_err("toPath rejects relative strings");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathNotAbsolute {
            path,
            ..
        } if path.as_slice() == b"relative/path"
    ));

    let error = eval_whnf_owned(&lower("builtins.toPath 1"))
        .expect_err("toPath coerces through string rules");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn to_json_primop_serializes_scalars_and_containers() {
    assert_eq!(eval_string_bytes("builtins.toJSON null"), b"null");
    assert_eq!(eval_string_bytes("builtins.toJSON true"), b"true");
    assert_eq!(eval_string_bytes("builtins.toJSON false"), b"false");
    assert_eq!(eval_string_bytes("builtins.toJSON 42"), b"42");
    assert_eq!(
        eval_string_bytes("builtins.toJSON \"é\""),
        "\"é\"".as_bytes()
    );
    assert_eq!(
        eval_string_bytes("builtins.toJSON \"\\t\\r\\n\\\\\\\"\""),
        br#""\t\r\n\\\"""#
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.toJSON (builtins.fromJSON "\"\\b\"")"#),
        br#""\b""#
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.toJSON (builtins.fromJSON "\"\\f\"")"#),
        br#""\f""#
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.toJSON (builtins.fromJSON "\"\\u0001\"")"#),
        br#""\u0001""#
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.toJSON (builtins.fromJSON "\"\\u001f\"")"#),
        br#""\u001f""#
    );
    assert_eq!(
        eval_string_bytes("builtins.toJSON { b = 1; a = [ true false null \"x\" ]; }"),
        br#"{"a":[true,false,null,"x"],"b":1}"#
    );
    assert_eq!(
        eval_string_bytes("builtins.toJSON { \"10\" = 10; \"2\" = 2; A = 1; a = 2; }"),
        br#"{"10":10,"2":2,"A":1,"a":2}"#
    );
}

#[test]
fn to_json_primop_formats_floats_like_cpp_nix_json() {
    assert_eq!(eval_string_bytes("builtins.toJSON 1.0"), b"1.0");
    assert_eq!(eval_string_bytes("builtins.toJSON 1.50"), b"1.5");
    assert_eq!(eval_string_bytes("builtins.toJSON (-0.0)"), b"0.0");
    assert_eq!(eval_string_bytes("builtins.toJSON 0.000001"), b"1e-06");
    assert_eq!(
        eval_string_bytes("builtins.toJSON 100000000000000000000.0"),
        b"1e+20"
    );
    assert_eq!(
        eval_string_bytes("builtins.toJSON ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))"),
        b"null"
    );
    assert_eq!(
        eval_string_bytes("builtins.toJSON (1.0e308 * 1.0e308)"),
        b"null"
    );
}

#[test]
fn to_json_primop_coerces_special_attrsets() {
    let (dir, path) = temp_file_with_bytes("json-path-attr-coercion", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_string_bytes("builtins.toJSON { __toString = self: \"hook\"; outPath = \"out\"; }"),
        br#""hook""#
    );
    assert_eq!(
        eval_string_bytes("builtins.toJSON { __toString = self: { outPath = \"nested\"; }; }"),
        br#""nested""#
    );
    assert_eq!(
        eval_string_bytes("builtins.toJSON { outPath = [ \"a\" \"b\" ]; }"),
        br#"["a","b"]"#
    );
    assert_eq!(
        eval_string_bytes("builtins.toJSON { outPath = \"out\"; a = 1; }"),
        br#""out""#
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toJSON {{ __toString = self: {path}; }}")),
        format!("{path:?}").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toJSON {{ outPath = {path}; }}")),
        br#""/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt""#
    );
    assert_eq!(eval_string_bytes("builtins.toJSON {}"), b"{}");

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn to_json_primop_reports_attr_coercion_and_unsupported_values() {
    let ir = lower("builtins.toJSON { __toString = self: 1; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("toJSON argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("__toString result must be a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.toJSON [ (x: x) ]");
    let error = eval_whnf_owned(&ir).expect_err("functions cannot become JSON");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::JsonUnsupportedValue {
            actual: ValueTag::Lambda,
            ..
        }
    ));

    let ir = lower("builtins.toJSON [ 1 (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("toJSON forces list elements");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn to_json_primop_unions_string_contexts() {
    let ir = lower("builtins.toJSON []");
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
        .expect("toJSON argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let direct_context =
        ContextElement::opaque_path(b"/nix/store/direct".to_vec()).expect("direct context builds");
    let out_path_context = ContextElement::opaque_path(b"/nix/store/out-path".to_vec())
        .expect("outPath context builds");
    let direct = evaluator
        .heap
        .alloc_string(NixString::new(
            b"direct".to_vec(),
            StringContext::singleton(direct_context.clone()).expect("direct context allocates"),
        ))
        .expect("direct string allocates");
    let out_path = evaluator
        .heap
        .alloc_string(NixString::new(
            b"out".to_vec(),
            StringContext::singleton(out_path_context.clone()).expect("outPath context allocates"),
        ))
        .expect("outPath string allocates");
    let out_path_symbol = evaluator
        .symbols
        .intern(OUT_PATH_ATTR)
        .expect("outPath symbol interns");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::new(out_path_symbol, out_path)],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let list = evaluator
        .heap
        .alloc_list(NixList::new(vec![direct, attrs]))
        .expect("list allocates");

    let result = evaluator
        .eval_to_json_primop(ir.root, root.span, argument, argument_span, list)
        .expect("toJSON evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result is a string");

    assert_eq!(string.bytes(), br#"["direct","out"]"#);
    assert!(string.context().contains(&direct_context));
    assert!(string.context().contains(&out_path_context));
}

#[test]
fn to_xml_primop_serializes_scalars_and_containers() {
    assert_eq!(
        eval_xml_bytes(r#"{ a = 1; b = [ true false null "x<y&\"z" ]; }"#),
        br#"<?xml version='1.0' encoding='utf-8'?>
<expr>
  <attrs>
    <attr name="a">
      <int value="1" />
    </attr>
    <attr name="b">
      <list>
        <bool value="true" />
        <bool value="false" />
        <null />
        <string value="x&lt;y&amp;&quot;z" />
      </list>
    </attr>
  </attrs>
</expr>
"#
    );
    assert_eq!(
        eval_xml_bytes(
            r#""a
<&>\"b""#
        ),
        br#"<?xml version='1.0' encoding='utf-8'?>
<expr>
  <string value="a&#xA;&lt;&amp;&gt;&quot;b" />
</expr>
"#
    );
}

#[test]
fn to_xml_primop_serializes_paths_and_floats() {
    let (dir, path) = temp_file_with_bytes("xml-path", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_xml_bytes(&path),
        format!(
            "<?xml version='1.0' encoding='utf-8'?>\n\
                 <expr>\n\
                 \x20\x20<path value=\"{path}\" />\n\
                 </expr>\n"
        )
        .as_bytes()
    );
    assert_eq!(
        eval_xml_bytes(
            r#"[ 1.25 (-0.0) 0.000001 1000000.0 100000000000000000000.0 1.23456789 1234567.0 ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) (1.0e308 * 1.0e308) (builtins.sub 0.0 (1.0e308 * 1.0e308)) ]"#
        ),
        br#"<?xml version='1.0' encoding='utf-8'?>
<expr>
  <list>
    <float value="1.25" />
    <float value="0" />
    <float value="1e-06" />
    <float value="1e+06" />
    <float value="1e+20" />
    <float value="1.23457" />
    <float value="1.23457e+06" />
    <float value="nan" />
    <float value="inf" />
    <float value="-inf" />
  </list>
</expr>
"#
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn to_xml_primop_serializes_functions_and_derivations() {
    assert_eq!(
        eval_xml_bytes("x: x"),
        br#"<?xml version='1.0' encoding='utf-8'?>
<expr>
  <function>
    <varpat name="x" />
  </function>
</expr>
"#
    );
    assert_eq!(
        eval_xml_bytes("{ a, b ? 1, ... }: a"),
        br#"<?xml version='1.0' encoding='utf-8'?>
<expr>
  <function>
    <attrspat ellipsis="1">
      <attr name="a" />
      <attr name="b" />
    </attrspat>
  </function>
</expr>
"#
    );
    assert_eq!(
        eval_xml_bytes("args@{ a, ... }: a"),
        br#"<?xml version='1.0' encoding='utf-8'?>
<expr>
  <function>
    <attrspat ellipsis="1" name="args">
      <attr name="a" />
    </attrspat>
  </function>
</expr>
"#
    );
    assert_eq!(
        eval_xml_bytes("builtins.length"),
        br#"<?xml version='1.0' encoding='utf-8'?>
<expr>
  <unevaluated />
</expr>
"#
    );

    let drv_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";
    let out_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x";
    assert_eq!(
        eval_xml_bytes(&format!(
            r#"{{ type = "derivation"; drvPath = "{drv_path}"; outPath = "{out_path}"; name = "x"; }}"#
        )),
        format!(
            "<?xml version='1.0' encoding='utf-8'?>\n\
                 <expr>\n\
                 \x20\x20<derivation drvPath=\"{drv_path}\" outPath=\"{out_path}\">\n\
                 \x20\x20\x20\x20<attr name=\"drvPath\">\n\
                 \x20\x20\x20\x20\x20\x20<string value=\"{drv_path}\" />\n\
                 \x20\x20\x20\x20</attr>\n\
                 \x20\x20\x20\x20<attr name=\"name\">\n\
                 \x20\x20\x20\x20\x20\x20<string value=\"x\" />\n\
                 \x20\x20\x20\x20</attr>\n\
                 \x20\x20\x20\x20<attr name=\"outPath\">\n\
                 \x20\x20\x20\x20\x20\x20<string value=\"{out_path}\" />\n\
                 \x20\x20\x20\x20</attr>\n\
                 \x20\x20\x20\x20<attr name=\"type\">\n\
                 \x20\x20\x20\x20\x20\x20<string value=\"derivation\" />\n\
                 \x20\x20\x20\x20</attr>\n\
                 \x20\x20</derivation>\n\
                 </expr>\n"
        )
        .as_bytes()
    );
    assert_eq!(
        eval_xml_bytes(r#"{ type = "derivation"; drvPath = 1; outPath = 2; }"#),
        br#"<?xml version='1.0' encoding='utf-8'?>
<expr>
  <derivation>
    <repeated />
  </derivation>
</expr>
"#
    );
}

#[test]
fn to_xml_primop_unions_string_contexts_and_forces_values() {
    assert_eq!(
        eval_json_bytes(
            r#"builtins.getContext (
                    builtins.toXML [
                      (builtins.appendContext "direct" {
                        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-direct" = { path = true; };
                      })
                    ]
                )"#
        ),
        br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-direct":{"path":true}}"#.to_vec()
    );

    let ir = lower("builtins.toXML [ 1 (1 / 0) ]");
    let error = eval_whnf_owned(&ir).expect_err("toXML forces list elements");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn from_json_primop_decodes_json_values() {
    let json = r#"''{"b":1,"a":[true,false,null,"x"],"c":{"n":2.5}}''"#;
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames (builtins.fromJSON {json})")),
        [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    );
    assert_eq!(
        eval(&format!("builtins.elemAt (builtins.fromJSON {json}).a 0")).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(&format!("builtins.elemAt (builtins.fromJSON {json}).a 1")).as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(&format!("builtins.elemAt (builtins.fromJSON {json}).a 2")).as_null(),
        Ok(())
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.elemAt (builtins.fromJSON {json}).a 3")),
        b"x"
    );
    assert_eq!(
        eval(&format!("(builtins.fromJSON {json}).b")).as_int(),
        Ok(1)
    );
    assert_eq!(
        eval(&format!("(builtins.fromJSON {json}).c.n")).as_float(),
        Ok(2.5)
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.fromJSON ''"é"''"#),
        "é".as_bytes()
    );
    assert_eq!(
        eval(r#"let builtins = { fromJSON = x: 42; }; in builtins.fromJSON "{}""#).as_int(),
        Ok(42)
    );
}

#[test]
fn from_json_primop_matches_number_edges_and_duplicate_keys() {
    assert_eq!(
        eval(r#"builtins.fromJSON "9223372036854775808""#).as_int(),
        Ok(i64::MIN)
    );
    assert_eq!(
        eval(r#"builtins.fromJSON "18446744073709551615""#).as_int(),
        Ok(-1)
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.typeOf (builtins.fromJSON "-9223372036854775809")"#),
        b"float"
    );
    assert_eq!(
        eval(r#"(builtins.fromJSON ''{"a":1,"a":2}'').a"#).as_int(),
        Ok(2)
    );
}

#[test]
fn from_json_primop_checks_argument_and_json() {
    let ir = lower("builtins.fromJSON 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("fromJSON requires a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower(r#"builtins.fromJSON "01""#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("fromJSON rejects invalid JSON");

    match error.kind() {
        TreeWalkErrorKind::JsonParse { id, message } => {
            assert_eq!(id, argument);
            assert!(!message.is_empty());
        }
        kind => panic!("unexpected error kind: {kind:?}"),
    }
    assert_eq!(error.span(), argument_span);
}

#[test]
fn from_json_primop_rejects_string_context() {
    let ir = lower("builtins.fromJSON \"{}\"");
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
        .expect("fromJSON argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"{}".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let error = evaluator
        .eval_from_json_primop(argument, argument_span, value)
        .expect_err("fromJSON rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "fromJSON",
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn from_toml_primop_decodes_toml_values() {
    assert_eq!(
        eval_json_bytes(
            r#"builtins.fromTOML ''
                    a = 1
                    b = 1.5
                    c = true
                    d = "x"
                    e = [1, "x", true, [2]]

                    [owner]
                    name = "Tom"
                ''"#
        ),
        br#"{"a":1,"b":1.5,"c":true,"d":"x","e":[1,"x",true,[2]],"owner":{"name":"Tom"}}"#
    );
    assert_eq!(
        eval_json_bytes(
            r#"builtins.fromTOML ''
                    [[fruit]]
                    name = "apple"
                    [[fruit]]
                    name = "banana"
                ''"#
        ),
        br#"{"fruit":[{"name":"apple"},{"name":"banana"}]}"#
    );
    assert_eq!(
        eval("let f = builtins.fromTOML; in (f \"a = 1\").a").as_int(),
        Ok(1)
    );
    assert_eq!(
            eval("let builtins = { fromTOML = value: { local = true; }; }; in (builtins.fromTOML \"a = 1\").local")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn from_toml_primop_matches_cpp_nix_integer_overflow_quirks() {
    assert_eq!(
            eval_json_bytes(
                r#"builtins.fromTOML ''
                    positive = 9223372036854775808
                    negative = -9223372036854775809
                    hex = 0x8000000000000000
                    octal = 0o1000000000000000000000
                    binary_min = 0b1000000000000000000000000000000000000000000000000000000000000000
                    binary_minus_one = 0b1111111111111111111111111111111111111111111111111111111111111111
                    binary_wrapped = 0b10000000000000000000000000000000000000000000000000000000000000000
                ''"#
            ),
            br#"{"binary_min":-9223372036854775808,"binary_minus_one":-1,"binary_wrapped":0,"hex":9223372036854775807,"negative":-9223372036854775808,"octal":9223372036854775807,"positive":9223372036854775807}"#
        );
    assert_eq!(
        eval_json_bytes(
            r#"builtins.fromTOML ''
                    [9223372036854775808]
                    value = "key"
                ''"#
        ),
        br#"{"9223372036854775808":{"value":"key"}}"#
    );
    assert_eq!(
        eval_json_bytes(
            r#"builtins.fromTOML ''
                    positive = 1e999
                    positive_signed = +1e999
                    negative = -1e999
                    fraction = 1.0e999
                ''"#
        ),
        br#"{"fraction":null,"negative":null,"positive":null,"positive_signed":null}"#
    );
}

#[test]
fn from_toml_numeric_overflow_normalizer_skips_non_values() {
    let source = "9223372036854775808 = \"key\"\n\
                      s = \"9223372036854775808\"\n\
                      l = '9223372036854775808'\n\
                      # 9223372036854775808\n\
                      [9223372036854775808]\n\
                      value = \"key\"\n\
                      nested = [\n\
                        [9223372036854775808]\n\
                      ]\n\
                      bad_leading = 09223372036854775808\n\
                      bad_signed_hex = +0x8000000000000000\n\
                      float = 1e999\n\
                      signed_float = -1.0e999\n\
                      bad_float = 01e999\n\
                      bad_float_underscore = 1_e999\n\
                      v = 9223372036854775808\n";
    assert_eq!(
        normalize_toml_numeric_overflows(source),
        "9223372036854775808 = \"key\"\n\
                      s = \"9223372036854775808\"\n\
                      l = '9223372036854775808'\n\
                      # 9223372036854775808\n\
                      [9223372036854775808]\n\
                      value = \"key\"\n\
                      nested = [\n\
                        [9223372036854775807]\n\
                      ]\n\
                      bad_leading = 09223372036854775808\n\
                      bad_signed_hex = +0x8000000000000000\n\
                      float = inf\n\
                      signed_float = -inf\n\
                      bad_float = 01e999\n\
                      bad_float_underscore = 1_e999\n\
                      v = 9223372036854775807\n"
    );
}

#[test]
fn from_toml_primop_checks_argument_and_toml() {
    let ir = lower("builtins.fromTOML 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("fromTOML requires a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower(r#"builtins.fromTOML "a = null""#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("invalid TOML is rejected");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::TomlParse { id, .. } if id == argument
    ));
    assert_eq!(error.span(), argument_span);

    let ir = lower(r#"builtins.fromTOML "a = 1979-05-27T07:32:00Z""#);
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("TOML datetimes are rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::TomlUnsupportedValue {
            id: argument,
            kind: "datetime",
        }
    );
    assert_eq!(error.span(), argument_span);

    for source in [
        r#"builtins.fromTOML "a = 09223372036854775808""#,
        r#"builtins.fromTOML "a = -09223372036854775809""#,
        r#"builtins.fromTOML "a = 0_9223372036854775808""#,
        r#"builtins.fromTOML "a = +0x8000000000000000""#,
        r#"builtins.fromTOML "a = 01e999""#,
        r#"builtins.fromTOML "a = 1_e999""#,
        r#"builtins.fromTOML "a = +01e999""#,
    ] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("malformed TOML number is rejected");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::TomlParse { .. }),
            "expected TOML parse error for {source}, got {error:?}"
        );
    }
}

#[test]
fn from_toml_primop_rejects_string_context() {
    let ir = lower("builtins.fromTOML \"a = 1\"");
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
        .expect("fromTOML argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"a = 1".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let error = evaluator
        .eval_from_toml_primop(argument, argument_span, value)
        .expect_err("fromTOML rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "fromTOML",
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn compare_versions_primop_orders_components() {
    for (source, expected) in [
        ("builtins.compareVersions \"1.0\" \"1.0\"", 0),
        ("builtins.compareVersions \"1.0\" \"1.1\"", -1),
        ("builtins.compareVersions \"1.10\" \"1.2\"", 1),
        ("builtins.compareVersions \"1.0pre\" \"1.0\"", -1),
        ("builtins.compareVersions \"1.0\" \"1.0pre\"", 1),
        ("builtins.compareVersions \"1.0pre2\" \"1.0pre10\"", -1),
        ("builtins.compareVersions \"1.0\" \"1.0.0\"", -1),
        ("builtins.compareVersions \"01\" \"1\"", 0),
        ("builtins.compareVersions \"1a\" \"1.0\"", -1),
        ("builtins.compareVersions \"1.0+git\" \"1.0\"", 1),
    ] {
        assert_eq!(eval(source).as_int(), Ok(expected), "{source}");
    }
    assert_eq!(
            eval("let builtins = { compareVersions = left: right: 42; }; in builtins.compareVersions \"1.0\" \"1.1\"")
                .as_int(),
            Ok(42)
        );
}

#[test]
fn compare_versions_primop_checks_arguments_left_to_right() {
    let ir = lower("builtins.compareVersions 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let left = args[0];
    let left_span = ir.arena.node(left).expect("left argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("compareVersions type-checks left first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: left,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), left_span);

    let ir = lower("builtins.compareVersions \"1\" 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let right = args[1];
    let right_span = ir.arena.node(right).expect("right argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("compareVersions type-checks right second");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: right,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), right_span);
}

#[test]
fn compare_versions_primop_rejects_string_context() {
    let ir = lower("builtins.compareVersions \"1\" \"2\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let left = args[0];
    let right = args[1];
    let left_span = ir.arena.node(left).expect("left argument exists").span;
    let right_span = ir.arena.node(right).expect("right argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let left_value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"1".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");
    let right_value = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"2".to_vec()))
        .expect("context-free string allocates");

    let error = evaluator
        .eval_compare_versions_values(left, left_span, left_value, right, right_span, right_value)
        .expect_err("compareVersions rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: left,
            op: "compareVersions",
        }
    );
    assert_eq!(error.span(), left_span);
}

#[test]
fn base_name_and_dir_of_primops_force_and_coerce_arguments() {
    let ir = lower("builtins.baseNameOf (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("baseNameOf forces its argument");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: argument }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.dirOf 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("integer is not string-coercible here");

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
fn strict_unary_primops_force_arguments() {
    let ir = lower("builtins.isInt (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("predicate forces argument");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: argument }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn break_result_is_forced_when_explicitly_demanded() {
    let ir = lower("builtins.break (1 / 0)");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_root()
        .expect("break returns the argument thunk");

    assert!(value.is_thunk());

    let error = evaluator
        .force_value(ir.root, Span::new(0, 0), value)
        .expect_err("forcing the returned thunk demands the argument");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn break_thunks_can_be_forced_by_arithmetic_and_reused() {
    assert_eq!(
        eval("builtins.add (builtins.break (1 + 2)) 1").as_int(),
        Ok(4)
    );
    assert_eq!(
        eval("let add = builtins.add; in add (builtins.break (1 + 2)) 1").as_int(),
        Ok(4)
    );
    assert!(matches!(
        eval_whnf(&lower(
            "builtins.add (builtins.break (builtins.break (1 + 2))) 1"
        ))
        .expect_err("arithmetic demands through exactly one break wrapper")
        .kind(),
        TreeWalkErrorKind::Type {
            actual: ValueTag::Thunk,
            ..
        }
    ));
    assert_eq!(
        eval("builtins.isInt (builtins.break (1 + 2))").as_bool(),
        Ok(false)
    );
    assert_eq!(
        eval(
            "let x = builtins.break (1 + 2); y = builtins.add x 0; \
                 in y + (if builtins.isInt x then 1 else 2)"
        )
        .as_int(),
        Ok(4)
    );
    assert_eq!(
        eval("builtins.seq (builtins.break (1 / 0)) 7").as_int(),
        Ok(7)
    );
    assert_eq!(
        eval("builtins.deepSeq (builtins.break [ (1 / 0) ]) 7").as_int(),
        Ok(7)
    );
    assert_eq!(
        eval("let s = builtins.seq; in s (builtins.break (1 / 0)) 7").as_int(),
        Ok(7)
    );
    assert_eq!(
        eval("let x = builtins.break [ 1 2 ]; y = builtins.seq x 0; in y + builtins.length x")
            .as_int(),
        Ok(2)
    );
    assert_eq!(
        eval(
            "let x = builtins.break { a = 1; }; y = builtins.deepSeq x 0; \
                 in y + (if builtins.hasAttr \"a\" x then 1 else 2)"
        )
        .as_int(),
        Ok(1)
    );
    assert!(matches!(
        eval_whnf(&lower("(builtins.break { x = 1; }).x"))
            .expect_err("direct selection sees the break result as an unforced thunk")
            .kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Thunk,
            ..
        }
    ));
    assert_eq!(eval("(builtins.break { x = 1; }).x or 2").as_int(), Ok(2));
    assert_eq!(eval("(builtins.break (1 + 2)) == 3").as_bool(), Ok(true));
    assert_eq!(
        eval("(builtins.break (builtins.break (1 + 2))) == 3").as_bool(),
        Ok(false)
    );
    assert_eq!(eval("(builtins.break [ 1 ]) == [ 1 ]").as_bool(), Ok(true));
    assert_eq!(
        eval_string_bytes("builtins.break (\"a\" + \"b\") + \"c\""),
        b"abc"
    );
    assert!(matches!(
        eval_whnf(&lower("(builtins.break (1 + 2)) + 1"))
            .expect_err("operator + does not treat break like builtins.add")
            .kind(),
        TreeWalkErrorKind::Type { .. }
    ));
    assert_eq!(
        eval("builtins.length ((builtins.break ([ 1 ] ++ [ 2 ])) ++ [ 3 ])").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("let x = builtins.break (1 + 2); in -x").as_int(),
        Ok(-3)
    );
    assert!(matches!(
        eval_whnf(&lower("(builtins.break (x: x)) 1"))
            .expect_err("direct break lambda remains a thunk"),
        TreeWalkError {
            kind: TreeWalkErrorKind::Type {
                actual: ValueTag::Thunk,
                ..
            },
            ..
        }
    ));
    assert_eq!(
        eval("let f = builtins.break (x: x); in f 1").as_int(),
        Ok(1)
    );
    assert!(matches!(
        eval_whnf(&lower(
            "let f = builtins.break (builtins.break (x: x)); in f 1"
        ))
        .expect_err("double break lambda leaves one thunk"),
        TreeWalkError {
            kind: TreeWalkErrorKind::Type {
                actual: ValueTag::Thunk,
                ..
            },
            ..
        }
    ));
}

#[test]
fn break_preserves_path_arguments_as_paths() {
    let (_dir, path) = temp_file_with_bytes("break-path", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval(&format!("builtins.isPath (builtins.break {path})")).as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.typeOf (builtins.break {path})")),
        b"path"
    );
    assert_eq!(
        eval(&format!(
            "let f = builtins.break; in builtins.isPath (f {path})"
        ))
        .as_bool(),
        Ok(true)
    );
}

#[test]
fn get_env_primop_reads_configured_environment() {
    assert_eq!(eval_string_bytes("builtins.getEnv \"HOME\""), b"");
    assert_eq!(
        eval_string_bytes("builtins.typeOf (builtins.getEnv \"HOME\")"),
        b"string"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.getEnv \"HOME\"",
            TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec())
        ),
        b"/home/aos"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "let f = builtins.getEnv; in f \"HOME\"",
            TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec())
        ),
        b"/home/aos"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.getEnv \"MISSING\"",
            TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec())
        ),
        b""
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.getEnv \"HOME\"", {
            let mut options =
                TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec());
            options.set_eval_mode(EvalMode::Pure);
            options
        }),
        b""
    );
}

#[test]
fn get_env_primop_type_checks_argument() {
    let ir = lower("builtins.getEnv 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("getEnv requires a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure))
        .expect_err("pure getEnv still validates the argument before hiding env");
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
fn get_env_primop_rejects_context_bearing_names() {
    let ir = lower("builtins.getEnv \"HOME\"");
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
        .expect("getEnv argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut options = TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec());
    options.set_eval_mode(EvalMode::Pure);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"HOME".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let error = evaluator
        .eval_get_env_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("getEnv rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "getEnv",
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn read_file_primop_reads_file_contents() {
    let dir = unique_temp_dir("read-file");
    let path = dir.join("data.txt");
    let contents = b"hello\xff\n";
    fs::write(&path, contents).expect("file writes");
    let path = path_source(&path);
    let link = dir.join("link");
    std::os::unix::fs::symlink(&path, &link).expect("symlink creates");
    let link_path = path_source(&link);

    assert_eq!(
        eval_string_bytes(&format!("builtins.readFile {}", nix_string_literal(&path))),
        contents
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.readFile {path}")),
        contents
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.readFile {}",
            nix_string_literal(&link_path)
        )),
        contents
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let f = builtins.readFile; in f {}",
            nix_string_literal(&path)
        )),
        contents
    );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { readFile = path: \"local\"; }; in builtins.readFile \"relative.txt\""
        ),
        b"local"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_file_primop_returns_context_free_strings() {
    let (dir, path) = temp_file_with_bytes(
        "read-file-context-free",
        b"/nix/store/00000000000000000000000000000000-name\n",
    );
    let path = path_source(&path);

    assert_eq!(
        eval(&format!(
            "builtins.hasContext (builtins.readFile {})",
            nix_string_literal(&path)
        ))
        .as_bool(),
        Ok(false)
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_file_primop_rejects_relative_strings() {
    let ir = lower("builtins.readFile \"relative.txt\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let path = args[0];
    let path_span = ir.arena.node(path).expect("path exists").span;

    let error = eval_whnf_owned(&ir).expect_err("relative strings are rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathNotAbsolute {
            id: path,
            path: b"relative.txt".to_vec(),
        }
    );
    assert_eq!(error.span(), path_span);
}

#[test]
fn read_file_primop_rejects_context_bearing_path_strings() {
    let (dir, path) = temp_file_with_bytes("read-file-context-path", b"data");
    let path = path_source(&path);
    let ir = lower(&format!("builtins.readFile {}", nix_string_literal(&path)));
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
        .expect("readFile argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            path.as_bytes().to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing path allocates");

    let error = evaluator
        .eval_read_file_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("readFile rejects string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: argument,
            op: "readFile",
        }
    );
    assert_eq!(error.span(), argument_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_file_primop_is_strict_in_path_argument() {
    let ir = lower("builtins.readFile (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("readFile forces path argument");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: argument }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn read_file_primop_reports_file_read_errors() {
    let dir = unique_temp_dir("read-file-missing");
    let path = path_source(&dir.join("missing.txt"));
    let ir = lower(&format!("builtins.readFile {}", nix_string_literal(&path)));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let path_id = args[0];
    let path_span = ir.arena.node(path_id).expect("path exists").span;

    let error = eval_whnf_owned(&ir).expect_err("missing file is reported");

    match error.kind() {
        TreeWalkErrorKind::FileRead {
            id,
            path: actual,
            message,
        } => {
            assert_eq!(id, path_id);
            assert_eq!(actual.as_slice(), path.as_bytes());
            assert!(!message.is_empty());
        }
        other => panic!("expected file-read error, got {other:?}"),
    }
    assert_eq!(error.span(), path_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_file_primop_reports_directory_read_errors() {
    let dir = unique_temp_dir("read-file-directory");
    let path = path_source(&dir);
    let ir = lower(&format!("builtins.readFile {}", nix_string_literal(&path)));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let path_id = args[0];
    let path_span = ir.arena.node(path_id).expect("path exists").span;

    let error = eval_whnf_owned(&ir).expect_err("directory read is reported");

    match error.kind() {
        TreeWalkErrorKind::FileRead {
            id,
            path: actual,
            message,
        } => {
            assert_eq!(id, path_id);
            assert_eq!(actual.as_slice(), path.as_bytes());
            assert!(!message.is_empty());
        }
        other => panic!("expected file-read error, got {other:?}"),
    }
    assert_eq!(error.span(), path_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn read_file_primop_rejects_nul_bytes() {
    let (dir, path) = temp_file_with_bytes("read-file-nul", b"a\0b");
    let path = path_source(&path);
    let ir = lower(&format!("builtins.readFile {}", nix_string_literal(&path)));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let path_id = args[0];
    let path_span = ir.arena.node(path_id).expect("path exists").span;

    let error = eval_whnf_owned(&ir).expect_err("NUL bytes are rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::FileReadContainsNul {
            id: path_id,
            path: path.as_bytes().to_vec(),
        }
    );
    assert_eq!(error.span(), path_span);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn import_forces_argument_before_filesystem_access() {
    let ir = lower("builtins.import (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf(&ir).expect_err("import forces its argument");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: argument }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn import_reports_missing_path_stat_error() {
    let missing = "/tmp/aos-nix-missing-import.nix";
    let ir = lower(&format!("builtins.import {}", nix_string_literal(missing)));
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("missing import path rejects");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::PathStat {
            id: argument,
            path: missing.as_bytes().to_vec(),
            message: "No such file or directory (os error 2)".to_owned(),
        }
    );
    assert_eq!(error.span(), argument_span);
}

#[test]
fn interpolation_coerces_attrsets_with_to_string_before_out_path() {
    assert_eq!(
        eval_string_bytes("\"${{ __toString = self: self.name; name = \"custom\"; }}\""),
        b"custom"
    );
    assert_eq!(
        eval_string_bytes("\"pre-${{ outPath = \"store\"; }}-post\""),
        b"pre-store-post"
    );
    assert_eq!(
        eval_string_bytes("\"${{ __toString = self: \"hook\"; outPath = 1 / 0; }}\""),
        b"hook"
    );
    assert_eq!(
        eval_string_bytes("\"${{ __toString = self: { outPath = \"nested\"; }; }}\""),
        b"nested"
    );
    assert_eq!(
        eval_string_bytes("\"${{ outPath = { outPath = \"nested\"; }; }}\""),
        b"nested"
    );
}

#[test]
fn string_interpolation_evaluates_concatenates_and_unions_context() {
    assert_eq!(eval_string_bytes("let x = \"b\"; in \"a${x}c\""), b"abc");
    assert_eq!(eval_string_bytes("let x = \"b\"; in ''a${x}c''"), b"abc");
    assert_eq!(
        eval_string_bytes(r#"let e = "x"; in "${"a${e}b"}""#),
        b"axb"
    );
    assert_eq!(
            eval_json_bytes(
                r#"let
                     withCtx = text: path: builtins.appendContext text {
                       ${path} = { path = true; };
                     };
                     aPath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                     bPath = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
                     a = withCtx "a" aPath;
                     b = withCtx "b" bPath;
                   in {
                     double = builtins.getContext "${a}${b}";
                     indented = builtins.getContext ''${a}${b}'';
                   }"#
            ),
            br#"{"double":{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b":{"path":true}},"indented":{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b":{"path":true}}}"#.to_vec()
        );
}

#[test]
fn non_string_operations_do_not_fabricate_context() {
    assert_eq!(
        eval_json_bytes(
            r#"let
                     withCtx = text: path: builtins.appendContext text {
                       ${path} = { path = true; };
                     };
                     a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                     a2 = withCtx "a" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
                     b = withCtx "b" "/nix/store/cccccccccccccccccccccccccccccccc-c";
                     updated = { eq = a == a2; lt = a < b; } // { gt = b > a; };
                   in {
                     comparison = builtins.getContext (builtins.toJSON (a == a2));
                     ordering = builtins.getContext (builtins.toJSON (a < b));
                     update = builtins.getContext (builtins.toJSON updated);
                   }"#
        ),
        br#"{"comparison":{},"ordering":{},"update":{}}"#.to_vec()
    );
}

#[test]
fn substring_and_replace_strings_preserve_contexts() {
    assert_eq!(
            eval_json_bytes(
                r#"let
                     withCtx = text: path: builtins.appendContext text {
                       ${path} = { path = true; };
                     };
                     source = withCtx "abcabc" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
                     used = withCtx "X" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-used";
                     unused = withCtx "Z" "/nix/store/cccccccccccccccccccccccccccccccc-unused";
                     pattern = withCtx "a" "/nix/store/dddddddddddddddddddddddddddddddd-pattern";
                   in {
                     substring = builtins.getContext (builtins.substring 1 3 source);
                     substringEmpty = builtins.getContext (builtins.substring 99 1 source);
                     replaceUsed = builtins.getContext
                       (builtins.replaceStrings [ "a" "z" ] [ used unused ] source);
                     replacePattern = builtins.getContext
                       (builtins.replaceStrings [ pattern ] [ used ] source);
                   }"#
            ),
            br#"{"replacePattern":{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-used":{"path":true}},"replaceUsed":{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-used":{"path":true}},"substring":{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source":{"path":true}},"substringEmpty":{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source":{"path":true}}}"#.to_vec()
        );
}

#[test]
fn context_element_kinds_round_trip_through_reflection() {
    assert_eq!(
            eval_json_bytes(
                r#"builtins.getContext (
                     builtins.appendContext "x" (
                       builtins.getContext (
                         builtins.appendContext "x" {
                           "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                           "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = {
                             outputs = [ "out" "dev" ];
                           };
                           "/nix/store/cccccccccccccccccccccccccccccccc-deep.drv" = {
                             allOutputs = true;
                           };
                         }
                       )
                     )
                   )"#
            ),
            br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv":{"outputs":["dev","out"]},"/nix/store/cccccccccccccccccccccccccccccccc-deep.drv":{"allOutputs":true}}"#.to_vec()
        );
}

#[test]
fn unsafe_discard_string_context_clears_exactly() {
    assert_eq!(
            eval_json_bytes(
                r#"let
                     original = builtins.appendContext "payload" {
                       "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                       "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = {
                         outputs = [ "out" ];
                       };
                       "/nix/store/cccccccccccccccccccccccccccccccc-deep.drv" = {
                         allOutputs = true;
                       };
                     };
                     other = builtins.appendContext "tail" {
                       "/nix/store/dddddddddddddddddddddddddddddddd-other" = { path = true; };
                     };
                     discarded = builtins.unsafeDiscardStringContext original;
                   in {
                     value = discarded;
                     discardedContext = builtins.getContext discarded;
                     originalContext = builtins.getContext original;
                     concatContext = builtins.getContext (discarded + other);
                   }"#
            ),
            br#"{"concatContext":{"/nix/store/dddddddddddddddddddddddddddddddd-other":{"path":true}},"discardedContext":{},"originalContext":{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv":{"outputs":["out"]},"/nix/store/cccccccccccccccccccccccccccccccc-deep.drv":{"allOutputs":true}},"value":"payload"}"#.to_vec()
        );
}

#[test]
fn indented_string_interpolation_strips_literals_before_insertion() {
    assert_eq!(
        eval_string_bytes("let x = \"X\"; in ''\n  ${x}\n  text\n''"),
        b"X\ntext\n"
    );
    assert_eq!(
        eval_string_bytes("let x = \"  X\"; in ''\n    ${x}\n    y\n''"),
        b"  X\ny\n"
    );
}

#[test]
fn path_interpolation_evaluates_to_path_values() {
    assert_eq!(
        eval_string_bytes(r#"builtins.typeOf (/tmp/${"x"})"#),
        b"path"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.toString (/tmp/${"x"}/y)"#),
        b"/tmp/x/y"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.toString (/tmp/${/x}/y)"#),
        b"/tmp/x/y"
    );

    let ir = lower(
        r#"builtins.toString (/tmp/${builtins.appendContext "x" {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a" = { path = true; };
               }}/y)"#,
    );
    let error =
        eval_whnf_owned(&ir).expect_err("context-bearing strings cannot be appended to paths");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "path interpolation",
            ..
        }
    ));
}

#[test]
fn dynamic_attr_names_require_string_values() {
    assert_eq!(eval("{ ${\"name\"} = 7; }.name").as_int(), Ok(7));
    assert_eq!(
        eval("let name = \"value\"; in { value = 9; }.${name}").as_int(),
        Ok(9)
    );

    for (source, actual) in [
        ("{ ${ { outPath = \"name\"; } } = 7; }", ValueTag::Attrs),
        (
            "{ ${ { __toString = self: \"value\"; } } = 7; }",
            ValueTag::Attrs,
        ),
        ("{ ${/tmp/x} = 7; }", ValueTag::Path),
    ] {
        let ir = lower(source);
        let error =
            eval_whnf_owned(&ir).expect_err("dynamic attribute names do not coerce non-strings");

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
        r#"{ ${builtins.appendContext "name" {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source" = { path = true; };
               }} = 7; }"#,
    );
    let error = eval_whnf_owned(&context_key).expect_err("dynamic attribute names reject context");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "dynamic attribute name",
            ..
        }
    ));
}

#[test]
fn literal_interpolated_let_binding_names_evaluate_as_static_names() {
    assert_eq!(eval(r#"let ${"x"} = 1; in x"#).as_int(), Ok(1));
    assert_eq!(eval("let ${''x''} = 1; in x").as_int(), Ok(1));
    assert_eq!(eval(r#"let ${"a"}.b = 1; in a.b"#).as_int(), Ok(1));
}

#[test]
fn interpolation_rejects_non_coercible_values() {
    let cases = [
        ("\"${1}\"", ValueTag::Int),
        ("\"${1.25}\"", ValueTag::Float),
        ("\"${true}\"", ValueTag::Bool),
        ("\"${null}\"", ValueTag::Null),
        ("\"${[]}\"", ValueTag::List),
        ("\"${{}}\"", ValueTag::Attrs),
    ];

    for (source, actual) in cases {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("value is not interpolable");
        let TreeWalkErrorKind::Type {
            expected,
            actual: observed,
            ..
        } = error.kind()
        else {
            panic!("expected type error for {source}");
        };
        assert_eq!(expected, "string");
        assert_eq!(observed, actual);
    }
}

#[test]
fn interpolation_requires_to_string_results_to_be_strings() {
    let ir = lower("\"${{ __toString = self: 1; }}\"");
    let error = eval_whnf_owned(&ir).expect_err("__toString result must be a string");
    let TreeWalkErrorKind::Type {
        expected, actual, ..
    } = error.kind()
    else {
        panic!("expected type error for non-string __toString result");
    };
    assert_eq!(expected, "string");
    assert_eq!(actual, ValueTag::Int);

    let ir = lower("\"${{ __toString = \"bad\"; outPath = \"fallback\"; }}\"");
    let error = eval_whnf_owned(&ir).expect_err("__toString takes precedence over outPath");
    let TreeWalkErrorKind::Type {
        expected, actual, ..
    } = error.kind()
    else {
        panic!("expected type error for non-lambda __toString");
    };
    assert_eq!(expected, "lambda");
    assert_eq!(actual, ValueTag::String);

    let ir = lower("\"${{ __toString = self: {}; outPath = \"fallback\"; }}\"");
    let error = eval_whnf_owned(&ir).expect_err("bad __toString result does not fall back");
    let TreeWalkErrorKind::Type {
        expected, actual, ..
    } = error.kind()
    else {
        panic!("expected type error for non-coercible __toString result");
    };
    assert_eq!(expected, "string");
    assert_eq!(actual, ValueTag::Attrs);
}

#[test]
fn evaluates_empty_list_literals_with_owned_heap() {
    let ir = lower("[]");
    let outcome = eval_whnf_owned(&ir).expect("empty list evaluates");
    let value = outcome.value();

    assert_eq!(value.tag(), ValueTag::List);
    assert!(
        outcome
            .heap()
            .get_list(value)
            .expect("list is heap-owned")
            .is_empty()
    );
}

#[test]
fn evaluates_non_empty_list_literals_with_lazy_elements() {
    let ir = lower("[ true (1 / 0) \"s\" ]");
    let outcome = eval_whnf_owned(&ir).expect("non-empty list evaluates");
    let value = outcome.value();
    let heap = outcome.heap();
    let list = heap.get_list(value).expect("list is heap-owned");

    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(list.len(), 3);
    assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));

    let lazy_division = list.get(1).expect("second");
    assert_eq!(lazy_division.tag(), ValueTag::Thunk);
    let thunk = heap
        .get_thunk(lazy_division)
        .expect("list element thunk is heap-owned");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );

    let string = list.get(2).expect("third");
    assert_eq!(
        heap.get_string(string)
            .expect("string element is heap-owned")
            .bytes(),
        b"s"
    );
}

#[test]
fn list_element_thunks_capture_let_environments() {
    let ir = lower("let x = 1 + 2; in [ x ]");
    let outcome = eval_whnf_owned(&ir).expect("list evaluates");
    let heap = outcome.heap();
    let list = heap.get_list(outcome.value()).expect("list is heap-owned");
    let element = list.get(0).expect("first");
    let element_thunk = heap
        .get_thunk(element)
        .expect("list element thunk is heap-owned");

    assert_eq!(
        element_thunk.env().expect("node thunk env").frames().len(),
        1
    );
    let captured_x = element_thunk.env().expect("node thunk env").frames()[0]
        .get(0)
        .expect("captured frame slot exists");
    assert_eq!(captured_x.tag(), ValueTag::Thunk);
    let x_thunk = heap
        .get_thunk(captured_x)
        .expect("captured binding thunk is heap-owned");
    assert_eq!(x_thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(x_thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );
}

#[test]
fn list_concat_concatenates_empty_lists() {
    let ir = lower("[] ++ []");
    let outcome = eval_whnf_owned(&ir).expect("list concat evaluates");
    let value = outcome.value();

    assert_eq!(value.tag(), ValueTag::List);
    assert!(
        outcome
            .heap()
            .get_list(value)
            .expect("concat result is heap-owned")
            .is_empty()
    );
}

#[test]
fn list_concat_concatenates_non_empty_lists_without_forcing_elements() {
    let ir = lower("[ (1 / 0) ] ++ [ true ]");
    let outcome = eval_whnf_owned(&ir).expect("list concat evaluates");
    let heap = outcome.heap();
    let list = heap
        .get_list(outcome.value())
        .expect("concat result is heap-owned");

    assert_eq!(list.len(), 2);
    let lazy_division = list.get(0).expect("first");
    assert_eq!(lazy_division.tag(), ValueTag::Thunk);
    let thunk = heap
        .get_thunk(lazy_division)
        .expect("left element thunk is heap-owned");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        ir.arena
            .node(thunk.body().expect("thunk body exists"))
            .expect("thunk body exists")
            .kind,
        IrKind::BinOp
    );
    assert_eq!(list.get(1).expect("second").as_bool(), Ok(true));
}

#[test]
fn list_concat_preserves_spine_values_without_forcing_elements() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::new(&ir);
    let node = *ir.arena.node(ir.root).expect("root exists");
    let left_ptr = NonNull::new(8usize as *mut HeapObject).expect("non-null pointer");
    let right_ptr = NonNull::new(16usize as *mut HeapObject).expect("non-null pointer");
    let left_thunk = Value::thunk(left_ptr).expect("left thunk pointer is aligned");
    let right_thunk = Value::thunk(right_ptr).expect("right thunk pointer is aligned");
    let left = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1), left_thunk]))
        .expect("left list allocates");
    let right = evaluator
        .heap
        .alloc_list(NixList::new(vec![right_thunk, Value::bool(true)]))
        .expect("right list allocates");

    let result = evaluator
        .concat_lists(ir.root, &node, left, right)
        .expect("lists concatenate");
    let list = evaluator
        .heap
        .get_list(result)
        .expect("result list is heap-owned");

    assert_eq!(list.len(), 4);
    assert_eq!(list.get(0).expect("first").as_int(), Ok(1));
    assert!(list.get(1).expect("second").raw_eq(left_thunk));
    assert!(list.get(2).expect("third").raw_eq(right_thunk));
    assert_eq!(list.get(3).expect("fourth").as_bool(), Ok(true));
}

#[test]
fn attr_update_merges_shallowly_with_rhs_precedence() {
    assert_eq!(
        eval("let r = { a = 1; } // { b = 2; }; in r.a + r.b").as_int(),
        Ok(3)
    );
    assert_eq!(eval("(({ a = 1 / 0; } // { a = 2; }).a)").as_int(), Ok(2));
    assert_eq!(
        eval("(({ a = { x = 1; }; } // { a = { y = 2; }; }).a.x or 9)").as_int(),
        Ok(9)
    );
}

#[test]
fn attr_update_keeps_values_lazy() {
    assert_eq!(
        eval("let r = { a = 1; } // { b = 1 / 0; }; in r.a").as_int(),
        Ok(1)
    );

    let ir = lower("{ a = 1 / 0; } // { b = 2; }");
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let outcome = eval_whnf_owned(&ir).expect("attr update evaluates");
    let attrs = outcome
        .heap()
        .get_attrs(outcome.value())
        .expect("update result is heap-owned");

    assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(2));
    let lazy_division = attrs.get(a).expect("a exists");
    assert_eq!(lazy_division.tag(), ValueTag::Thunk);
    let thunk = outcome
        .heap()
        .get_thunk(lazy_division)
        .expect("left attr value stays lazy");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn attr_update_forces_ordinary_thunk_operands_to_whnf() {
    assert_eq!(
        eval(
            "let xs = [ { a = 1; } ]; ys = [ { b = 2; } ]; \
                 in ((builtins.elemAt xs 0) // (builtins.elemAt ys 0)).b"
        )
        .as_int(),
        Ok(2)
    );
}

#[test]
fn attr_update_rejects_break_identity_thunk_operands() {
    for source in [
        "(builtins.break { a = 1; }) // { b = 2; }",
        "{ a = 1; } // (builtins.break { b = 2; })",
    ] {
        assert!(matches!(
            eval_whnf_owned(&lower(source))
                .expect_err("break identity thunk is not a set update operand")
                .kind(),
            TreeWalkErrorKind::Type {
                expected: "attrs",
                actual: ValueTag::Thunk,
                ..
            }
        ));
    }
}

#[test]
fn evaluates_empty_attrsets_with_owned_heap() {
    let ir = lower("{}");
    let outcome = eval_whnf_owned(&ir).expect("empty attrset evaluates");
    let value = outcome.value();

    assert_eq!(value.tag(), ValueTag::Attrs);
    assert!(
        outcome
            .heap()
            .get_attrs(value)
            .expect("attrset is heap-owned")
            .is_empty()
    );
}

#[test]
fn evaluates_static_attrsets_with_lazy_values() {
    let ir = lower("{ a = 1; b = (1 / 0); }");
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let outcome = eval_whnf_owned(&ir).expect("static attrset evaluates");
    let heap = outcome.heap();
    let attrs = heap
        .get_attrs(outcome.value())
        .expect("attrset is heap-owned");

    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs.get(a).expect("a exists").as_int(), Ok(1));

    let lazy_division = attrs.get(b).expect("b exists");
    assert_eq!(lazy_division.tag(), ValueTag::Thunk);
    let thunk = heap
        .get_thunk(lazy_division)
        .expect("attr value thunk is heap-owned");
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
fn nested_static_attr_definitions_merge_like_pinned_nix() {
    assert_eq!(
        eval_json_bytes("{ a.b.c = 1; }"),
        br#"{"a":{"b":{"c":1}}}"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes("{ a.b = 1; a.c = 2; }"),
        br#"{"a":{"b":1,"c":2}}"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes("{ a.b.c = 1; a.b.d = 2; }"),
        br#"{"a":{"b":{"c":1,"d":2}}}"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes("{ a = { b = 1; }; a.c = 2; }"),
        br#"{"a":{"b":1,"c":2}}"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes("{ a.b = 1; a = { c = 2; }; }"),
        br#"{"a":{"b":1,"c":2}}"#.to_vec()
    );
}

#[test]
fn bare_inherit_copies_surrounding_lexical_values() {
    assert_eq!(
        eval_json_bytes(r#"let x = 1; y = "two"; in { inherit x y; }"#),
        br#"{"x":1,"y":"two"}"#.to_vec()
    );
    assert_eq!(
        eval("let x = 1; copied = { inherit x; }; in let x = 2; in copied.x").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let x = 1 / 0; in ({ inherit x; } ? x)").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let x = 1; in ({ inherit x; } == { x = x; })").as_bool(),
        Ok(true)
    );
}

#[test]
fn inherit_from_expression_uses_shared_lazy_source() {
    assert_eq!(
        eval_json_bytes("let src = { x = 1; y = 2; }; in { inherit (src) x y; }"),
        br#"{"x":1,"y":2}"#.to_vec()
    );

    let lazy_source = eval_owned(
        r#"let copied = { inherit (builtins.trace "source" { x = 1; }) x; };
               in copied ? x"#,
    );
    assert_eq!(lazy_source.value().as_bool(), Ok(true));
    assert!(lazy_source.trace_output().is_empty());

    assert_eq!(
        eval("let copied = { inherit ({}) x; }; in copied ? x").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let copied = { inherit ({ a = { b = 1; }; }) a; }; in copied.a.b").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval_json_bytes(
            "let f = src: { inherit (src) x y; };
                 in [ (f { x = 1; y = 2; }).x (f { x = 10; y = 20; }).y ]"
        ),
        br#"[1,20]"#.to_vec()
    );

    let shared_source = eval_owned(
        r#"let copied = {
                 inherit (builtins.trace "source" { x = 1; y = 2; }) x y;
               };
               in copied.x + copied.y"#,
    );
    assert_eq!(shared_source.value().as_int(), Ok(3));
    assert_eq!(shared_source.trace_output().len(), 1);
    assert_trace_output(
        shared_source
            .trace_output()
            .first()
            .expect("trace output exists"),
        EvalTraceKind::Trace,
        b"source",
    );
}

#[test]
fn let_inherit_bindings_use_normal_let_scope_and_sharing() {
    assert_eq!(
        eval("let x = 1; inherited = let inherit x; in x; in let x = 2; in inherited").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let x = 1 / 0; in let inherit x; in 42").as_int(),
        Ok(42)
    );
    assert_eq!(eval("with { x = 1; }; let inherit x; in x").as_int(), Ok(1));
    assert_eq!(
        eval("with { x = 1 / 0; }; let inherit x; in 42").as_int(),
        Ok(42)
    );
    assert_eq!(
        eval("let x = 1; f = let inherit x; in y: x + y; in let x = 10; in f 2").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("let src = { x = 1; y = 2; }; inherit (src) x y; in x + y").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("let inherit (src) x; src = { x = 5; }; in x").as_int(),
        Ok(5)
    );
    assert_eq!(eval("let inherit ({}) x; in 42").as_int(), Ok(42));

    let unused_source = eval_owned(r#"let inherit (builtins.trace "source" { x = 1; }) x; in 42"#);
    assert_eq!(unused_source.value().as_int(), Ok(42));
    assert!(unused_source.trace_output().is_empty());

    let shared_source = eval_owned(
        r#"let inherit (builtins.trace "source" { x = 1; y = 2; }) x y;
               in x + y"#,
    );
    assert_eq!(shared_source.value().as_int(), Ok(3));
    assert_eq!(shared_source.trace_output().len(), 1);
    assert_trace_output(
        shared_source
            .trace_output()
            .first()
            .expect("trace output exists"),
        EvalTraceKind::Trace,
        b"source",
    );
}

#[test]
fn evaluates_static_recursive_attrsets_with_lazy_self_scope() {
    assert_eq!(eval("(rec { a = 1; b = a + 2; }).b").as_int(), Ok(3));
    assert_eq!(eval("(rec { a = b; b = 1; }).a").as_int(), Ok(1));
    assert_eq!(eval("(rec { a = 1 / 0; }).b or 2").as_int(), Ok(2));
    assert_eq!(eval("rec { a = b; b = a; } ? a").as_bool(), Ok(true));
    assert_eq!(
        eval("let a = 10; in { a = 1; b = a + 1; }.b").as_int(),
        Ok(11)
    );
    assert_eq!(
        eval("let x = 1; in (rec { inherit x; y = x; }).y").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let z = 0; x = 1; in (rec { inherit x; y = x; }).y").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let x = 1 / 0; in (rec { inherit x; } ? x)").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("with { x = 1; }; (rec { inherit x; y = x; }).y").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("with { x = 1 / 0; }; (rec { inherit x; } ? x)").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let x = 1; in (rec { inherit x; f = y: x + y; }).f 2").as_int(),
        Ok(3)
    );

    let ir = lower("(rec { a = a; }).a");
    let error = eval_whnf(&ir).expect_err("recursive attr self-reference blackholes");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Force {
            source: ForceError::InfiniteRecursion,
            ..
        }
    ));

    let ir = lower("(rec { a = b; b = a; }).a");
    let error = eval_whnf(&ir).expect_err("mutual attr recursion blackholes");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Force {
            source: ForceError::InfiniteRecursion,
            ..
        }
    ));
}

#[test]
fn forcing_attr_value_thunks_memoizes_whnf_results() {
    let ir = lower("{ a = 1 + 2; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::new(&ir);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };

    assert_eq!(thunk_value.tag(), ValueTag::Thunk);
    assert_eq!(
        evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("thunk exists")
            .cell()
            .state(),
        Ok(ThunkState::Suspended)
    );

    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("thunk remains heap-owned");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Forced));
    let cached = thunk
        .cell()
        .cached_value()
        .expect("forced thunk has cached value")
        .expect("cached value exists");
    assert!(cached.raw_eq(Value::int(3)));

    let forced_again = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("forced thunk reuses cache");
    assert_eq!(forced_again.as_int(), Ok(3));
}

#[test]
fn shared_thunks_emit_trace_once_when_forced_repeatedly() {
    for (source, expected) in [
        (
            "let x = builtins.trace \"let\" 1; in x + x",
            &b"trace: let\n"[..],
        ),
        (
            "(x: x + x) (builtins.trace \"arg\" 1)",
            &b"trace: arg\n"[..],
        ),
        (
            "let xs = [ (builtins.trace \"list\" 1) ]; in (builtins.elemAt xs 0) + (builtins.elemAt xs 0)",
            &b"trace: list\n"[..],
        ),
        (
            "let set = { x = builtins.trace \"attr\" 1; }; in set.x + set.x",
            &b"trace: attr\n"[..],
        ),
    ] {
        let ir = lower(source);
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.capture_stderr();
        let value = evaluator
            .eval_root()
            .expect("shared thunk expression evaluates");
        assert_eq!(value.as_int(), Ok(2), "{source}");
        let stderr = evaluator.captured_stderr();
        assert_eq!(stderr, expected, "{source}");
    }
}

#[test]
fn failed_thunks_reset_and_are_retried() {
    let source = "let x = builtins.trace \"retry\" (builtins.throw \"boom\"); \
                      a = builtins.tryEval x; \
                      b = builtins.tryEval x; \
                      in if a.success == false && b.success == false then 1 else 0";
    let ir = lower(source);
    let mut evaluator = TreeWalk::new(&ir);
    evaluator.capture_stderr();
    let value = evaluator
        .eval_root()
        .expect("tryEval catches both failed thunk forces");
    assert_eq!(value.as_int(), Ok(1));
    let stderr = evaluator.captured_stderr();
    assert_eq!(stderr, b"trace: retry\ntrace: retry\n");
}

#[test]
fn strict_operand_evaluation_forces_direct_thunk_alloc_results() {
    let body = IrId::new(0);
    let lhs = IrId::new(1);
    let rhs = IrId::new(2);
    let root = IrId::new(3);
    let ir = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(IrKind::ThunkAlloc, Span::new(0, 1), IrData::Node(body)),
            pure_node(IrKind::Int, Span::new(4, 5), IrData::Int(2)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 5),
                IrData::Binary {
                    op: BinOpKind::Add,
                    lhs,
                    rhs,
                },
            ),
        ],
    );

    assert_eq!(
        eval_whnf(&ir)
            .expect("strict operand thunk is forced")
            .as_int(),
        Ok(3)
    );
}

#[test]
fn forcing_errors_reset_thunks_to_suspended() {
    let ir = lower("{ a = 1 / 0; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::new(&ir);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let error = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("division by zero remains a force error");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("thunk remains heap-owned");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert!(
        thunk
            .cell()
            .cached_value()
            .expect("suspended thunk has no invalid state")
            .is_none()
    );
}

#[test]
fn evaluates_dynamic_attrsets_with_string_keys_and_null_omission() {
    assert_eq!(
        eval("let name = \"a\"; in { ${name} = 1; }.${name}").as_int(),
        Ok(1)
    );
    assert_eq!(eval("({ ${\"a\" + \"b\"} = 3; }).ab").as_int(), Ok(3));
    assert_eq!(
        eval("rec { ${\"a\" + \"\"} = b; b = 2; }.a").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let a = 7; in rec { ${\"x\" + \"\"} = a; a = 1; }.x").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let x = \"x\"; y = \"outer\"; in rec { ${y} = 1; a = \"bar\"; b = \"baz\"; }.outer")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let a = \"outer\"; in rec { ${a} = 1; a = \"inner\"; }.inner").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval_string_bytes("let a = \"outer\"; in rec { ${a} = 1; a = \"inner\"; }.a"),
        b"inner".to_vec()
    );
    assert_eq!(
        eval("let name = \"dyn\"; dyn = 9; in rec { ${name} = 1; a = dyn; }.a").as_int(),
        Ok(9)
    );
    assert_eq!(
        eval("with { name = \"dyn\"; }; rec { ${name} = 1; }.dyn").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("with { name = \"dyn\"; dyn = 9; }; rec { ${name} = 1; a = dyn; }.a").as_int(),
        Ok(9)
    );
    assert_eq!(
        eval("with { name = \"outer\"; }; rec { name = \"inner\"; ${name} = 1; }.inner").as_int(),
        Ok(1)
    );
    assert_eq!(eval("{ ${null} = 1 / 0; a = 2; }.a").as_int(), Ok(2));

    let skipped = lower("{ ${null} = 1 / 0; }");
    let outcome = eval_whnf_owned(&skipped).expect("null dynamic key is skipped");
    assert!(
        outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("attrset is heap-owned")
            .is_empty()
    );
}

#[test]
fn dynamic_attrsets_report_duplicate_and_non_string_keys() {
    let duplicate = lower("{ ${\"a\" + \"\"} = 1; a = 2; }");
    let duplicate_symbol = symbol_for(&duplicate, b"a");
    let duplicate_error =
        eval_whnf_owned(&duplicate).expect_err("computed duplicate key is invalid");
    assert_eq!(
        duplicate_error.kind(),
        TreeWalkErrorKind::Attr {
            id: duplicate.root,
            source: AttrError::DuplicateKey {
                key: duplicate_symbol
            },
        }
    );

    let non_string = lower("{ ${1} = 1; }");
    let expression = non_string
        .arena
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.kind == IrKind::Int && node.data == IrData::Int(1))
        .map(|(index, _)| IrId::new(index as u32))
        .expect("dynamic key expression exists");
    let error = eval_whnf_owned(&non_string).expect_err("dynamic key must be string or null");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: expression,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(
        error.span(),
        non_string
            .arena
            .node(expression)
            .expect("dynamic key expression exists")
            .span
    );
}

#[test]
fn let_bindings_are_lazy_and_self_visible() {
    assert_eq!(eval("let x = 1 + 2; in x").as_int(), Ok(3));
    assert_eq!(eval("let a = 1; b = 2; in a + b").as_int(), Ok(3));
    assert_eq!(
        eval("let a = 1; b = 2; in let c = a + b; in c").as_int(),
        Ok(3)
    );
    assert_eq!(eval("let x = 1 / 0; in 7").as_int(), Ok(7));
    assert_eq!(eval("let p = ./foo; in 7").as_int(), Ok(7));

    let ir = lower("let x = x; in x");
    let error = eval_whnf(&ir).expect_err("self-recursive let blackholes");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Force {
            source: ForceError::InfiniteRecursion,
            ..
        }
    ));
}

#[test]
fn let_environment_captures_survive_escaping_thunks() {
    assert_eq!(eval("(let x = 1 + 2; in { a = x; }).a").as_int(), Ok(3));
    assert_eq!(eval("let x = 1; in let y = x + 2; in y").as_int(), Ok(3));
}

#[test]
fn simple_lambdas_apply_with_lazy_arguments() {
    assert_eq!(eval("(x: x + 1) 2").as_int(), Ok(3));
    assert_eq!(eval("let f = x: x; in f (1 + 2)").as_int(), Ok(3));
    assert_eq!(eval("let f = x: 7; in f (1 / 0)").as_int(), Ok(7));
    assert_eq!(eval("let x = 1; f = y: x + y; in f 2").as_int(), Ok(3));
    assert_eq!(
        eval("let x = 1; f = y: x + y; in let x = 10; in f x").as_int(),
        Ok(11)
    );
    assert_eq!(eval("let f = x: x; or = 2; in f or").as_int(), Ok(2));
    assert_eq!(eval("((x: y: x) (1 + 2)) 0").as_int(), Ok(3));
}

#[test]
fn lambda_application_respects_max_call_depth() {
    assert_eq!(
        eval_with_options("(x: x) 1", TreeWalkOptions::with_max_call_depth(0)).as_int(),
        Ok(1)
    );

    let nested = lower("(x: (y: y) 2) 1");
    let mut evaluator = TreeWalk::with_options(&nested, TreeWalkOptions::with_max_call_depth(0));
    let error = evaluator
        .eval_root()
        .expect_err("nested call exceeds max-call-depth 0");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MaxCallDepthExceeded {
            depth: 1,
            max: 0,
            ..
        }
    ));
    assert_eq!(evaluator.call_depth, 0);

    assert_eq!(
        eval_with_options("(x: (y: y) 2) 1", TreeWalkOptions::with_max_call_depth(1),).as_int(),
        Ok(2)
    );

    let nested = lower("(x: (y: (z: z) 3) 2) 1");
    let mut evaluator = TreeWalk::with_options(&nested, TreeWalkOptions::with_max_call_depth(1));
    let error = evaluator
        .eval_root()
        .expect_err("third nested call exceeds max-call-depth 1");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MaxCallDepthExceeded {
            depth: 2,
            max: 1,
            ..
        }
    ));
    assert_eq!(evaluator.call_depth, 0);

    assert_eq!(
        eval_with_options("builtins.add 1 2", TreeWalkOptions::with_max_call_depth(0),).as_int(),
        Ok(3)
    );

    let primop = lower("(x: builtins.add 1 2) 0");
    let mut evaluator = TreeWalk::with_options(&primop, TreeWalkOptions::with_max_call_depth(0));
    let error = evaluator
        .eval_root()
        .expect_err("nested primop call exceeds max-call-depth 0");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MaxCallDepthExceeded {
            depth: 1,
            max: 0,
            ..
        }
    ));
    assert_eq!(evaluator.call_depth, 0);

    assert_eq!(
        eval_cpp_json_bytes_with_options(
            "builtins.map (x: x) [ 1 ]",
            TreeWalkOptions::with_max_call_depth(0),
        ),
        b"[1]"
    );

    for source in [
        "builtins.all (x: true) [ 1 ]",
        "builtins.add ((x: x) 1) 2",
        "let add = builtins.add; in add ((x: x) 1) 2",
        "builtins.seq ((x: x) 1) 2",
        "builtins.map ((x: x) (y: y)) [ 1 ]",
        "builtins.trace ((x: x) \"m\") 1",
    ] {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::with_max_call_depth(0));
        let error = evaluator
            .eval_root()
            .expect_err("builtin call frame rejects nested call");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::MaxCallDepthExceeded {
                    depth: 1,
                    max: 0,
                    ..
                }
            ),
            "{source} produced {error:?}",
        );
        assert_eq!(evaluator.call_depth, 0);
    }
}

#[test]
fn attrset_functors_apply_like_functions() {
    assert_eq!(
        eval("({ __functor = self: x: x + self.offset; offset = 1; } 2)").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("let f = { __functor = self: x: x + 1; }; in f 1").as_int(),
        Ok(2)
    );
    assert_eq!(
            eval("let f = { __functor = self: { __functor = self2: x: x + self.offset; }; offset = 1; }; in f 1")
                .as_int(),
            Ok(2)
        );
    assert_eq!(
        eval("let f = { __functor = self: x: if x == 0 then 0 else self (x - 1) + 1; }; in f 3")
            .as_int(),
        Ok(3)
    );
}

#[test]
fn with_scopes_probe_dynamic_attrs_lazily() {
    assert_eq!(eval("with { a = 1; }; a").as_int(), Ok(1));
    assert_eq!(eval("with { f = x: x + 1; }; f 2").as_int(), Ok(3));
    assert_eq!(eval("with (1 / 0); 7").as_int(), Ok(7));
    assert_eq!(eval("with { a = 1 / 0; }; 7").as_int(), Ok(7));
    assert_eq!(eval("with { a = 1; }; with { a = 2; }; a").as_int(), Ok(2));
    assert_eq!(eval("let a = 3; in with { a = 1; }; a").as_int(), Ok(3));
    assert_eq!(eval("with { true = 1; }; true").as_bool(), Ok(true));
    assert_eq!(eval("with { false = 1; }; false").as_bool(), Ok(false));
    assert_eq!(eval("with { null = 1; }; null").tag(), ValueTag::Null);
    assert_eq!(
        eval("builtins.isAttrs (with { builtins = 1; }; builtins)").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("with { currentTime = 123; }; currentTime").as_int(),
        Ok(123)
    );
    assert_eq!(
        eval_string_bytes(r#"with { storeDir = "with"; }; storeDir"#),
        b"with"
    );
    assert_eq!(
        eval("with { langVersion = 9; }; langVersion").as_int(),
        Ok(9)
    );
    assert_eq!(
        eval("with { length = xs: 7; }; length [ 1 ]").as_int(),
        Ok(7)
    );
    assert_eq!(
        eval("with { concatMap = f: xs: 7; }; concatMap (x: [ x ]) [ 1 ]").as_int(),
        Ok(7)
    );
    assert_eq!(
        eval("builtins.elemAt (with { map = f: xs: 7; }; map (x: x) [ 1 ]) 0").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval_string_bytes(r#"with { toString = x: "with"; }; toString 1"#),
        b"1"
    );
    assert_eq!(eval("with {}; true").as_bool(), Ok(true));
    assert_eq!(eval("with {}; false").as_bool(), Ok(false));
    assert_eq!(eval("with {}; null").tag(), ValueTag::Null);
}

#[test]
fn with_scopes_capture_lexical_environments() {
    assert_eq!(
        eval("let x = 1; f = y: with { a = x + y; }; a; in let x = 10; in f x").as_int(),
        Ok(11)
    );
    assert_eq!(
        eval("let x = 1; scope = { a = x; }; f = y: with scope; a + y; in f 2").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("let f = with { a = 1; }; x: a + x; in f 2").as_int(),
        Ok(3)
    );
    assert_eq!(eval("(with { a = 1 + 2; }; { b = a; }).b").as_int(), Ok(3));
}

#[test]
fn with_lookup_reports_non_attr_scopes_and_missing_names() {
    let non_attr = lower("with 1; missing");
    let root = non_attr.arena.node(non_attr.root).expect("root exists");
    let IrData::Pair { first, .. } = root.data else {
        panic!("with root has pair payload");
    };
    let first_span = non_attr.arena.node(first).expect("scope exists").span;
    let error = eval_whnf(&non_attr).expect_err("non-attr with scope is invalid on lookup");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: first,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), first_span);

    let missing = lower("with {}; missing");
    let IrData::Pair {
        second: missing_var,
        ..
    } = missing
        .arena
        .node(missing.root)
        .expect("missing root exists")
        .data
    else {
        panic!("with root has pair payload");
    };
    let missing_symbol = symbol_for(&missing, b"missing");
    let error = eval_whnf(&missing).expect_err("missing with name remains unresolved");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnresolvedWithVar {
            id: missing_var,
            symbol: missing_symbol,
        }
    );
}

#[test]
fn formal_set_lambdas_bind_attrs_defaults_ellipsis_and_aliases() {
    assert_eq!(eval("({ x }: x) { x = 1; }").as_int(), Ok(1));
    assert_eq!(eval("({ x, y }: x + y) { x = 1; y = 2; }").as_int(), Ok(3));
    assert_eq!(
        eval("({ x, ... }: x) { x = 1; y = 1 / 0; }").as_int(),
        Ok(1)
    );
    assert_eq!(eval("({ x ? 1 + 2 }: x) {}").as_int(), Ok(3));
    assert_eq!(eval("({ x ? 1 / 0 }: 7) {}").as_int(), Ok(7));
    assert_eq!(eval("({ x ? 1 / 0 }: x) { x = 7; }").as_int(), Ok(7));
    assert_eq!(eval("({ a, b ? a + 1 }: b) { a = 2; }").as_int(), Ok(3));
    assert_eq!(
        eval("(args@{ x, ... }: args.x) { x = 1; y = 2; }").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("({ x, ... }@args: args.y) { x = 1; y = 2; }").as_int(),
        Ok(2)
    );
    assert_eq!(eval("({ x ? 1 }@args: args ? x) {}").as_bool(), Ok(false));
    assert_eq!(
        eval("({ x ? 1 }@args: args ? x) { x = 2; }").as_bool(),
        Ok(true)
    );
}

#[test]
fn formal_set_lambdas_report_match_errors() {
    let missing = lower("({ x }: x) {}");
    let missing_symbol = symbol_for(&missing, b"x");
    let error = eval_whnf(&missing).expect_err("required formal is missing");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingFormalAttribute {
            id: missing.root,
            symbol: missing_symbol,
        }
    );

    let extra = lower("({ x }: x) { x = 1; z = 2; a = 3; }");
    let extra_symbol = symbol_for(&extra, b"a");
    let error = eval_whnf(&extra).expect_err("extra attr without ellipsis is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnexpectedFormalAttribute {
            id: extra.root,
            symbol: extra_symbol,
        }
    );

    let non_attr = lower("({ x }: x) 1");
    let root = non_attr.arena.node(non_attr.root).expect("root exists");
    let IrData::Pair { second, .. } = root.data else {
        panic!("application root has pair payload");
    };
    let second_span = non_attr.arena.node(second).expect("argument exists").span;
    let error = eval_whnf(&non_attr).expect_err("formal-set argument must be attrs");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: second,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), second_span);
}

#[test]
fn function_application_rejects_non_callable_values() {
    let ir = lower("1 2");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Pair { first, .. } = root.data else {
        panic!("application root has pair payload");
    };
    let first_span = ir.arena.node(first).expect("function exists").span;
    let error = eval_whnf(&ir).expect_err("integer is not callable");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: first,
            expected: "lambda",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), first_span);

    let manual = manual_ir(
        IrId::new(1),
        vec![
            pure_node(IrKind::Int, first_span, IrData::Int(1)),
            pure_node(
                IrKind::Apply,
                Span::new(0, 4),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(99),
                },
            ),
        ],
    );
    let manual_error =
        eval_whnf(&manual).expect_err("function type wins before lazy argument lookup");

    assert_eq!(
        manual_error.kind(),
        TreeWalkErrorKind::Type {
            id: IrId::new(0),
            expected: "lambda",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(manual_error.span(), first_span);
}

#[test]
fn select_static_keys_force_lazy_values() {
    assert_eq!(eval("({ a = 1 + 2; }).a").as_int(), Ok(3));

    let ir = lower("({ a = 1 / 0; }).a");
    let error = eval_whnf_owned(&ir).expect_err("selected field thunk is forced");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn select_defaults_are_lazy_and_forced_when_missing() {
    assert_eq!(eval("({ a = 1; }).a or (1 / 0)").as_int(), Ok(1));
    assert_eq!(eval("({ a = { b = 1; }; }).a.b or (1 / 0)").as_int(), Ok(1));
    assert_eq!(eval("({ a = 1; }).b or (1 + 2)").as_int(), Ok(3));
    assert_eq!(eval("({ a = {}; }).a.b or 7").as_int(), Ok(7));
    assert_eq!(eval("({ a = {}; }).a.b.c or 7").as_int(), Ok(7));
    assert_eq!(eval("({}).a.b or 2").as_int(), Ok(2));
    assert_eq!(eval("({}).a.b.c or 7").as_int(), Ok(7));
    assert_eq!(eval("(1).a or 2").as_int(), Ok(2));
    assert_eq!(eval("({ a = 1; }).a.b or 2").as_int(), Ok(2));
    assert_eq!(eval("({ a = { b = 1; }; }).a.b.c or 7").as_int(), Ok(7));

    let ir = lower("({ a = 1; }).b or (1 / 0)");
    let error = eval_whnf_owned(&ir).expect_err("missing key forces default thunk");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let nested = lower("({ a = {}; }).a.b or (1 / 0)");
    let error = eval_whnf_owned(&nested).expect_err("nested miss forces default thunk");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let nested = lower("({ a = {}; }).a.b.c or (1 / 0)");
    let error =
        eval_whnf_owned(&nested).expect_err("missing intermediate component forces default thunk");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn missing_static_select_reports_attribute() {
    let ir = lower("({}).a");
    let symbol = symbol_for(&ir, b"a");
    let error = eval_whnf_owned(&ir).expect_err("missing key without default is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute {
            id: ir.root,
            symbol,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );

    let nested = lower("({ a = {}; }).a.b");
    let nested_symbol = symbol_for(&nested, b"b");
    let nested_error =
        eval_whnf_owned(&nested).expect_err("missing nested key without default is invalid");

    assert_eq!(
        nested_error.kind(),
        TreeWalkErrorKind::MissingAttribute {
            id: nested.root,
            symbol: nested_symbol,
        }
    );
    assert_eq!(
        nested_error.span(),
        nested.arena.node(nested.root).expect("root exists").span
    );

    let missing_intermediate = lower("({ a = {}; }).a.b.c");
    let intermediate_symbol = symbol_for(&missing_intermediate, b"b");
    let intermediate_error = eval_whnf_owned(&missing_intermediate)
        .expect_err("missing intermediate key without default is invalid");

    assert_eq!(
        intermediate_error.kind(),
        TreeWalkErrorKind::MissingAttribute {
            id: missing_intermediate.root,
            symbol: intermediate_symbol,
        }
    );
    assert_eq!(
        intermediate_error.span(),
        missing_intermediate
            .arena
            .node(missing_intermediate.root)
            .expect("root exists")
            .span
    );
}

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

#[test]
fn has_attr_detects_single_static_keys_without_forcing_values() {
    assert_eq!(eval("({ a = 1; } ? a)").as_bool(), Ok(true));
    assert_eq!(eval("({ a = 1; } ? z)").as_bool(), Ok(false));
    assert_eq!(eval("({ a = 1 / 0; } ? a)").as_bool(), Ok(true));
    assert_eq!(eval("({ a = 1 / 0; } ? z)").as_bool(), Ok(false));

    let receiver_error = lower("((1 / 0) ? a)");
    let error = eval_whnf_owned(&receiver_error).expect_err("has-attr forces the receiver first");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn has_attr_returns_false_for_non_attr_path_values() {
    assert_eq!(eval("(1 ? a)").as_bool(), Ok(false));
    assert_eq!(eval("({} ? a.b.c)").as_bool(), Ok(false));
    assert_eq!(eval("({ a = 1; } ? a.b)").as_bool(), Ok(false));
}

#[test]
fn has_attr_evaluates_nested_static_and_dynamic_paths() {
    assert_eq!(eval("({ a = { b = 1 / 0; }; } ? a.b)").as_bool(), Ok(true));
    assert_eq!(eval("({ a = {}; } ? a.b)").as_bool(), Ok(false));
    assert_eq!(eval("({ a = {}; } ? a.b.c)").as_bool(), Ok(false));
    assert_eq!(eval("({ a = 1; } ? ${\"a\"})").as_bool(), Ok(true));
    assert_eq!(eval("({ ab = 1; } ? ${\"a\" + \"b\"})").as_bool(), Ok(true));
    assert_eq!(eval("({} ? ${\"a\"}.${1 / 0})").as_bool(), Ok(false));
    assert_eq!(eval("(1 ? ${\"a\"})").as_bool(), Ok(false));

    let error_ir = lower("({ a = 1 / 0; } ? a.b)");
    let error = eval_whnf_owned(&error_ir).expect_err("intermediate thunk errors win");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let null_key = lower("({ a = 1; } ? ${null})");
    let null_node = null_key
        .arena
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.kind == IrKind::Null)
        .map(|(index, _)| IrId::new(index as u32))
        .expect("null key expression exists");
    let null_error = eval_whnf_owned(&null_key).expect_err("has-attr dynamic null key is invalid");

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
            "({ value = 9; } ? ${ { __toString = self: \"value\"; } })",
            ValueTag::Attrs,
        ),
        ("({ \"/tmp/x\" = 5; } ? ${/tmp/x})", ValueTag::Path),
    ] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("dynamic has-attr requires string keys");

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
        r#"({ name = 7; } ? ${builtins.appendContext "name" {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source" = { path = true; };
               }})"#,
    );
    let error = eval_whnf_owned(&context_key).expect_err("dynamic has-attr rejects string context");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "dynamic attribute name",
            ..
        }
    ));
}

#[test]
fn has_attr_evaluates_receiver_and_reached_dynamic_keys_in_order() {
    let ir = lower("((1 / 0) ? ${\"a\"})");
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

    let dynamic_error = lower("({} ? ${1 / 0})");
    let error =
        eval_whnf_owned(&dynamic_error).expect_err("first dynamic has-attr key is still evaluated");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn list_concat_type_checks_operands_left_to_right() {
    let lhs_ir = lower("1 ++ (1 / 0)");
    let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
    let IrData::Binary { lhs, .. } = root.data else {
        panic!("concat root has binary payload");
    };
    let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

    let error = eval_whnf_owned(&lhs_ir).expect_err("integer lhs is invalid before rhs");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: lhs,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), lhs_span);

    let rhs_ir = lower("[] ++ 1");
    let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("concat root has binary payload");
    };
    let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&rhs_ir).expect_err("integer rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), rhs_span);

    let rhs_error_ir = lower("[] ++ (1 / 0)");
    let root = rhs_error_ir
        .arena
        .node(rhs_error_ir.root)
        .expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("concat root has binary payload");
    };
    let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn attr_update_type_checks_operands_left_to_right() {
    let lhs_ir = lower("1 // (1 / 0)");
    let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
    let IrData::Binary { lhs, .. } = root.data else {
        panic!("update root has binary payload");
    };
    let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

    let error = eval_whnf_owned(&lhs_ir).expect_err("integer lhs is invalid before rhs");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: lhs,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), lhs_span);

    let rhs_ir = lower("{} // 1");
    let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("update root has binary payload");
    };
    let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&rhs_ir).expect_err("integer rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), rhs_span);

    let rhs_error_ir = lower("{} // (1 / 0)");
    let root = rhs_error_ir
        .arena
        .node(rhs_error_ir.root)
        .expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("update root has binary payload");
    };
    let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn non_owning_eval_rejects_list_concat_heap_values() {
    let ir = lower("[] ++ []");
    let error = eval_whnf(&ir).expect_err("list concat value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::List,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );
}

#[test]
fn non_owning_eval_rejects_attr_update_heap_values() {
    let ir = lower("{} // {}");
    let error = eval_whnf(&ir).expect_err("attr update value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::Attrs,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );
}

#[test]
fn string_add_concatenates_heap_strings() {
    let outcome = eval_whnf_owned(&lower("\"a\" + \"b\"")).expect("string add evaluates");
    let value = outcome.value();

    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        outcome
            .heap()
            .get_string(value)
            .expect("string add result is heap-owned")
            .bytes(),
        b"ab"
    );

    let escaped =
        eval_whnf_owned(&lower("\"a\\n\" + \"b\"")).expect("escaped string add evaluates");
    assert_eq!(
        escaped
            .heap()
            .get_string(escaped.value())
            .expect("escaped add result is heap-owned")
            .bytes(),
        b"a\nb"
    );
}

#[test]
fn string_add_store_coerces_path_rhs() {
    let (dir, path) = temp_file_with_bytes("string-add-path", b"abc");
    let path = path_source(&path);
    let store_path = "/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt";

    assert_eq!(
        eval_string_bytes(&format!("\"prefix-\" + {path}")),
        format!("prefix-{store_path}").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toJSON (builtins.getContext (\"prefix-\" + {path}))"
        )),
        br#"{"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt":{"path":true}}"#
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "\"prefix-\" + {{ __toString = self: {path}; outPath = 1 / 0; }}"
        )),
        format!("prefix-{store_path}").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("\"prefix-\" + {{ outPath = {path}; }}")),
        format!("prefix-{store_path}").as_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn string_add_rejects_missing_path_rhs() {
    let dir = unique_temp_dir("string-add-missing-path");
    let path = path_source(&dir.join("missing.txt"));
    let ir = lower(&format!("\"prefix-\" + {path}"));
    let error = eval_whnf_owned(&ir).expect_err("missing path rhs cannot be copied to store");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::SourcePathArchive { .. }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_add_concatenates_raw_paths_and_context_free_strings() {
    let dir = unique_temp_dir("path-add");
    let base = dir.join("base");
    fs::create_dir(&base).expect("base directory creates");
    let suffix = dir.join("suffix.txt");
    fs::write(&suffix, b"abc").expect("suffix file writes");
    let base = path_source(&base);
    let suffix = path_source(&suffix);

    assert_eq!(
        eval_string_bytes(&format!("builtins.typeOf ({base} + \"/child\")")),
        b"path"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString ({base} + \"/child\")")),
        format!("{base}/child").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString ({base} + \"child\")")),
        format!("{base}child").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString ({base} + \"/../sibling\")")),
        path_source(&dir.join("sibling")).as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString ({base} + {suffix})")),
        format!("{base}{suffix}").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.toString ({base} + {{ __toString = self: \"/hook\"; outPath = 1 / 0; }})"
        )),
        format!("{base}/hook").as_bytes()
    );

    let ir = lower(&format!(
        r#"{base} + (builtins.appendContext "/child" {{
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = {{ path = true; }};
            }})"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("path append rejects string context");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "path addition",
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn string_add_unions_contexts() {
    assert_eq!(
        eval(
            r#"let
                     withCtx = text: path: builtins.appendContext text {
                       ${path} = { path = true; };
                     };
                     aPath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                     bPath = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
                     result = withCtx "a" aPath + withCtx "b" bPath;
                     ctx = builtins.getContext result;
                   in result == "ab" && builtins.hasAttr aPath ctx && builtins.hasAttr bPath ctx"#
        )
        .as_bool(),
        Ok(true)
    );

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
            b"hello".to_vec(),
            StringContext::singleton(source.clone()).expect("source context allocates"),
        ))
        .expect("left string allocates");
    let right = evaluator
        .heap
        .alloc_string(NixString::new(
            b" world".to_vec(),
            StringContext::singleton(output.clone()).expect("output context allocates"),
        ))
        .expect("right string allocates");

    let result = evaluator
        .concat_strings(ir.root, &node, left, right)
        .expect("strings concatenate");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result string is heap-owned");

    assert_eq!(string.bytes(), b"hello world");
    assert_eq!(string.context().len(), 2);
    assert!(string.context().contains(&source));
    assert!(string.context().contains(&output));
}

#[test]
fn derivation_strict_returns_context_bearing_outputs() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
           in {
             drvContext = builtins.getContext d.drvPath;
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             out = d.out;
             outContext = builtins.getContext d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvContext":{"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv":{"allOutputs":true}},"drvPath":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","names":["drvPath","out"],"out":"/nix/store/ss8z7hsjimnxam6mx6z8znm64qrk08cn-x","outContext":{"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv":{"outputs":["out"]}}}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_returns_default_output_derivation_shape() {
    let source = r#"let
             d = derivation {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
           in {
             allLen = builtins.length d.all;
             drvAttrs = builtins.attrNames d.drvAttrs;
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             outNames = builtins.attrNames d.out;
             pathOut = d.outPath;
             outputName = d.outputName;
             rendered = "${d}";
             renderedContext = builtins.getContext "${d}";
             kind = d.type;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"allLen":1,"drvAttrs":["builder","name","system"],"drvPath":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","kind":"derivation","names":["all","builder","drvAttrs","drvPath","name","out","outPath","outputName","system","type"],"outNames":["all","builder","drvAttrs","drvPath","name","out","outPath","outputName","system","type"],"outputName":"out","pathOut":"/nix/store/ss8z7hsjimnxam6mx6z8znm64qrk08cn-x","rendered":"/nix/store/ss8z7hsjimnxam6mx6z8znm64qrk08cn-x","renderedContext":{"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv":{"outputs":["out"]}}}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_preserves_custom_outputs_and_recursive_aliases() {
    let source = r#"let
             d = derivation {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = [ "out" "dev" ];
             };
           in {
             allLen = builtins.length d.all;
             allOutputNames = builtins.map (x: x.outputName) d.all;
             devNested = d.dev.out.dev.dev.outPath;
             devOutPath = d.dev.outPath;
             drvAttrs = builtins.attrNames d.drvAttrs;
             names = builtins.attrNames d;
             outNested = d.out.dev.out.outPath;
             pathOut = d.outPath;
             outputs = d.outputs;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"allLen":2,"allOutputNames":["out","dev"],"devNested":"/nix/store/phkb0v7mn27i2c5y0qg9d18wvgch5x2w-x-dev","devOutPath":"/nix/store/phkb0v7mn27i2c5y0qg9d18wvgch5x2w-x-dev","drvAttrs":["builder","name","outputs","system"],"names":["all","builder","dev","drvAttrs","drvPath","name","out","outPath","outputName","outputs","system","type"],"outNested":"/nix/store/kpxa7fq9k2f03c5mn9ipsqjs09lnj1gj-x","outputs":["out","dev"],"pathOut":"/nix/store/kpxa7fq9k2f03c5mn9ipsqjs09lnj1gj-x"}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_supports_non_out_first_output() {
    let source = r#"let
             d = derivation {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = [ "dev" ];
             };
           in {
             allLen = builtins.length d.all;
             hasDev = builtins.hasAttr "dev" d;
             hasOut = builtins.hasAttr "out" d;
             names = builtins.attrNames d;
             pathOut = d.outPath;
             outputName = d.outputName;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"allLen":1,"hasDev":true,"hasOut":false,"names":["all","builder","dev","drvAttrs","drvPath","name","outPath","outputName","outputs","system","type"],"outputName":"dev","pathOut":"/nix/store/3igymyyr87hiw3y11n2jknh5fn06qkz4-x-dev"}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_first_class_values_call_builtin() {
    for source in [
        r#"let
                 f = derivation;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
        r#"let
                 f = builtins.derivation;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
        r#"let
                 d = builtins.derivation {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
        r#"with { derivation = x: x; }; let
                 f = derivation;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
    ] {
        assert_eq!(
            eval_string_bytes(source),
            b"/nix/store/ss8z7hsjimnxam6mx6z8znm64qrk08cn-x",
            "{source}"
        );
    }
}

#[test]
fn derivation_wrapper_is_exposed_as_reference_lambda() {
    let source = r#"let
             inspect = f: {
               args = builtins.functionArgs f;
               isFunction = builtins.isFunction f;
               type = builtins.typeOf f;
             };
           in {
             attr = inspect builtins.derivation;
             global = inspect derivation;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"attr":{"args":{"outputs":true},"isFunction":true,"type":"lambda"},"global":{"args":{"outputs":true},"isFunction":true,"type":"lambda"}}"#.to_vec()
        );
}

#[test]
fn derivation_wrapper_rejects_non_list_outputs_like_cpp_wrapper() {
    let error = eval_whnf_owned(&lower(
        r#"derivation {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = "out dev";
               }"#,
    ))
    .expect_err("derivation wrapper maps over outputs as a list");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::String,
            ..
        }
    ));
}

#[test]
fn derivation_strict_supports_custom_outputs() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = [ "out" "dev" ];
             };
           in {
             dev = d.dev;
             devContext = builtins.getContext d.dev;
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             out = d.out;
             outContext = builtins.getContext d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"dev":"/nix/store/phkb0v7mn27i2c5y0qg9d18wvgch5x2w-x-dev","devContext":{"/nix/store/w02nl2gwz0jsij58hzmg7m5f7m8d1404-x.drv":{"outputs":["dev"]}},"drvPath":"/nix/store/w02nl2gwz0jsij58hzmg7m5f7m8d1404-x.drv","names":["dev","drvPath","out"],"out":"/nix/store/kpxa7fq9k2f03c5mn9ipsqjs09lnj1gj-x","outContext":{"/nix/store/w02nl2gwz0jsij58hzmg7m5f7m8d1404-x.drv":{"outputs":["out"]}}}"#.to_vec()
        );
}

#[test]
fn derivation_strict_preserves_raw_outputs_env_string() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = "out  dev";
             };
           in {
             dev = d.dev;
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"dev":"/nix/store/n28wnzwh3wqjmhyz754raw70fhyg436p-x-dev","drvPath":"/nix/store/pgbcwn3hlyzz8y1bzijsdm0faai1bxvz-x.drv","out":"/nix/store/8slxvn562rwfh09l7bjcg4mdpg4lv8vp-x"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_structured_attrs() {
    let source = r#"let
             simple = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               foo = "bar";
             };
             explicitOut = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               outputs = [ "out" ];
             };
             nullValue = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __ignoreNulls = false;
               foo = null;
             };
             jsonKey = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __json = "foo";
               foo = "bar";
             };
           in {
             explicitOutDrv = explicitOut.drvPath;
             explicitOutOut = explicitOut.out;
             jsonKeyDrv = jsonKey.drvPath;
             jsonKeyOut = jsonKey.out;
             nullDrv = nullValue.drvPath;
             nullOut = nullValue.out;
             simpleDrv = simple.drvPath;
             simpleNames = builtins.attrNames simple;
             simpleOut = simple.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"explicitOutDrv":"/nix/store/ni8ck1jwld3qz4fkyb1xfh7kd0qmj5fk-foo.drv","explicitOutOut":"/nix/store/g6x8m6kvfidz7673x8xzkxcjabx4n6dp-foo","jsonKeyDrv":"/nix/store/98yvz8z0i6kzdcsv6zq8cv60dd784yxf-foo.drv","jsonKeyOut":"/nix/store/gw2i989kkschki96vpiz6y779ah7sblw-foo","nullDrv":"/nix/store/rldskjdcwa3p7x5bqy3r217va1jsbjsc-foo.drv","nullOut":"/nix/store/0xghxv8giy66afhkpwbsa2bjhq9j4w8s-foo","simpleDrv":"/nix/store/k6rlb4k10cb9iay283037ml1nv3xma2f-foo.drv","simpleNames":["drvPath","out"],"simpleOut":"/nix/store/6lmv3hyha1g4cb426iwjyifd7nrdv1xn-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_structured_attrs_accepts_reference_constraints() {
    let source = r#"let
             d = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               allowedReferences = [ "out" ];
             };
           in {
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/y83ql5w0pnjb1b5xwaxccgfxigkq51hz-foo.drv","names":["drvPath","out"],"out":"/nix/store/5434vg976sf8rj9ifi8nyil96mcnsgph-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_structured_attrs_observes_builder_context() {
    let source = r#"let
             d = derivationStrict {
               name = "foo";
               system = ":";
               builder = builtins.appendContext ":" {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
               };
               __structuredAttrs = true;
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/1ixzgybyjnapzwa82nb0pm9v2klbzkbw-foo.drv","out":"/nix/store/zxyyy7j9s7c6472nf9klhkhaw43npjlm-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_structured_attrs_requires_string_special_attrs() {
    for source in [
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = 1;
                 __structuredAttrs = true;
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = 1;
                 builder = ":";
                 __structuredAttrs = true;
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputHash = "";
                 outputHashAlgo = true;
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputs = [ 1 ];
               }"#,
    ] {
        let error =
            eval_whnf_owned(&lower(source)).expect_err("structured special attr must be a string");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::Type {
                    expected: "string",
                    ..
                }
            ),
            "{source}: {error:?}"
        );
    }

    for source in [
        r#"derivationStrict {
                 name = "foo";
                 system = builtins.appendContext ":" {
                   "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                 };
                 builder = ":";
                 __structuredAttrs = true;
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputHash = "";
                 outputHashAlgo = builtins.appendContext "sha256" {
                   "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                 };
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputs = [
                   (builtins.appendContext "out" {
                     "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                   })
                 ];
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source))
            .expect_err("structured special attr must not carry context");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::StringContextNotAllowed {
                    op: "derivationStrict",
                    ..
                }
            ),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_outputs_use_cpp_nix_whitespace_set() {
    for source in [
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = builtins.fromJSON "\"out\\fdev\"";
               }"#,
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = builtins.fromJSON "\"out\\u000bdev\"";
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source))
            .expect_err("form feed and vertical tab are not outputs separators");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::DerivationStrict { .. }),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_supports_reference_constraint_attrs() {
    let source = r#"let
             allowed = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               allowedReferences = [ "out" ];
             };
             combined = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               disallowedReferences = [ "out" ];
               allowedRequisites = [ "out" ];
               disallowedRequisites = [ "out" ];
             };
             graph = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               exportReferencesGraph = [ "foo" "bar" ];
             };
             integer = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               allowedReferences = 1;
             };
           in {
             allowedDrv = allowed.drvPath;
             allowedOut = allowed.out;
             combinedDrv = combined.drvPath;
             combinedOut = combined.out;
             graphDrv = graph.drvPath;
             graphOut = graph.out;
             integerDrv = integer.drvPath;
             integerOut = integer.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"allowedDrv":"/nix/store/mpqxk9x7ch6mhlxsl3l50hrfp8plpc2c-foo.drv","allowedOut":"/nix/store/sgc5h0s5r6lx51354xbrcy061qflsch2-foo","combinedDrv":"/nix/store/fbnc7w27pbca6vrmwqlik6a6jv753152-foo.drv","combinedOut":"/nix/store/qksvm54k9gdb59ksf3kc9d91yb7dzq4i-foo","graphDrv":"/nix/store/dfyfp6n0879bzpg67941va1pbby7qc3k-foo.drv","graphOut":"/nix/store/974srlr8l7zk8mqn73nsdq4vniyg3i35-foo","integerDrv":"/nix/store/jqzxf4g629r6d2jj5vl2xpjn5nza5pw9-foo.drv","integerOut":"/nix/store/hy5q2xh2q0lvhbkvww0f0cbywg87a5bk-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_ignore_nulls() {
    let source = r#"let
             default = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
             withNull = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               foo = null;
             };
             ignored = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               foo = null;
               __ignoreNulls = true;
             };
             explicitFalse = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               foo = null;
               __ignoreNulls = false;
             };
             capital = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               A = null;
               __ignoreNulls = true;
             };
             argsNull = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = null;
               __ignoreNulls = true;
             };
             structuredFalse = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               __structuredAttrs = false;
               foo = null;
               __ignoreNulls = true;
             };
             unsupportedNulls = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputHash = null;
               outputHashAlgo = null;
               outputHashMode = null;
               __contentAddressed = null;
               allowedReferences = null;
               disallowedReferences = null;
               allowedRequisites = null;
               disallowedRequisites = null;
               exportReferencesGraph = null;
               __ignoreNulls = true;
             };
           in {
             argsNull = argsNull.drvPath;
             capital = capital.drvPath;
             default = default.drvPath;
             explicitFalse = explicitFalse.drvPath;
             ignored = ignored.drvPath;
             structuredFalse = structuredFalse.drvPath;
             unsupportedNulls = unsupportedNulls.drvPath;
             withNull = withNull.drvPath;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"argsNull":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","capital":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","default":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","explicitFalse":"/nix/store/gbihbhvs2za69fzg3gl91x0f7zcq1ii9-x.drv","ignored":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","structuredFalse":"/nix/store/ch3c4m4ba4r554gq3z26r8v9h80sp119-x.drv","unsupportedNulls":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","withNull":"/nix/store/gbihbhvs2za69fzg3gl91x0f7zcq1ii9-x.drv"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_preserves_non_utf8_environment_values() {
    let source = b"let d = derivationStrict {\n  name = \"x\";\n  system = \"x86_64-linux\";\n  builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder\";\n  raw = \"raw-\xff-byte\";\n}; in d.drvPath";
    let outcome = eval_whnf_owned(&lower_bytes(source)).expect("raw env bytes evaluate");
    let aterm = outcome
        .derivations()
        .iter()
        .find_map(EvalDerivation::aterm_bytes)
        .expect("static derivation has ATerm bytes");

    assert!(
        aterm
            .windows(b"raw-\xff-byte".len())
            .any(|window| window == b"raw-\xff-byte"),
        "{aterm:?}"
    );
}

#[test]
fn derivation_strict_rejects_non_utf8_structural_fields() {
    for source in [
            b"derivationStrict {\n  name = \"x\";\n  system = \"x86_64-linux\";\n  builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-\xff-builder\";\n}"
                .as_slice(),
            b"derivationStrict {\n  name = \"x\";\n  system = \"x86_64-\xff-linux\";\n  builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder\";\n}"
                .as_slice(),
        ] {
            let error = eval_whnf_owned(&lower_bytes(source))
                .expect_err("structural derivation fields must stay UTF-8");
            assert!(
                matches!(
                    error.kind(),
                    TreeWalkErrorKind::DerivationStringUtf8 {
                        field: "environment value",
                        ..
                    }
                ),
                "{source:?}: {error:?}"
            );
        }
}

#[test]
fn derivation_strict_ignore_nulls_type_checks_flag_only() {
    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 __ignoreNulls = 1;
               }"#,
    ))
    .expect_err("ignoreNulls must be a bool");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = null;
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 __ignoreNulls = true;
               }"#,
    ))
    .expect_err("ignoreNulls does not skip the mandatory name attr");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = builtins.appendContext "x" {
                   "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                 };
                 system = "x86_64-linux";
                 builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
               }"#,
    ))
    .expect_err("derivation names cannot carry string context");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "derivationStrict",
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 __structuredAttrs = null;
                 __ignoreNulls = true;
               }"#,
    ))
    .expect_err("ignoreNulls does not skip structuredAttrs type checking");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Null,
            ..
        }
    ));
}

#[test]
fn derivation_strict_rejects_invalid_derivation_names_before_later_attrs() {
    let long_name = "a".repeat(DERIVATION_NAME_MAX_LEN + 1);
    let cases = [
        ("", "name must not be empty"),
        ("bad/name", "contains illegal character '/'"),
        (".", "name '.' is not valid"),
        (
            ".-component",
            "first dash-separated component must not be '.'",
        ),
        ("..", "name '..' is not valid"),
        (
            "..-component",
            "first dash-separated component must not be '..'",
        ),
        (long_name.as_str(), "must be no longer than 211 characters"),
    ];
    for (name, reason) in cases {
        let source = format!(
            r#"derivationStrict {{
                     name = {name:?};
                     system = builtins.throw "late";
                     builder = builtins.throw "late";
                   }}"#
        );
        let error = eval_whnf_owned(&lower(&source))
            .expect_err("invalid derivation name must be rejected before later attrs");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::DerivationStrict {
                    message,
                    ..
                } if message.contains("invalid derivation name")
                    && message.contains(reason)
            ),
            "{name:?}: {error:?}"
        );
    }

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = builtins.fromJSON "\"cafe\\u0301\"";
                 system = builtins.throw "late";
                 builder = builtins.throw "late";
               }"#,
    ))
    .expect_err("non-ASCII derivation name must be rejected before later attrs");
    assert!(
        matches!(
            error.kind(),
            TreeWalkErrorKind::DerivationStrict {
                message,
                ..
            } if message.contains("invalid derivation name")
                && message.contains("contains illegal character '\u{301}'")
        ),
        "{error:?}"
    );
}

#[test]
fn derivation_strict_rejects_supported_names_ending_in_drv() {
    for source in [
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __contentAddressed = true;
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __impure = true;
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 outputs = "bad/name";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputs = [ "bad/name" ];
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 outputHash = "not-a-hash";
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 outputHash = "";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __contentAddressed = true;
                 __impure = true;
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source))
            .expect_err("supported derivation forms reject names ending in .drv");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::DerivationStrict {
                    message,
                    ..
                } if message.contains("end in '.drv'")
            ),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_ignore_nulls_does_not_skip_args_elements() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               foo = null;
               __ignoreNulls = true;
               args = [ null ];
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/4ljrbgdg50gl74wbgr53yvv23ap9bfrz-x.drv","out":"/nix/store/j6kab8pd56kjnp4z2zsvwcsdm7fmn37f-x"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_fixed_output_derivations() {
    let source = r#"let
             mk = attrs: derivationStrict ({
               name = "foo";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             } // attrs);
             flat = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "sha256";
               outputHashMode = "flat";
             };
             recursive = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
             omittedMode = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "sha256";
             };
             omittedAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashMode = "recursive";
             };
             raw = mk {
               outputHash = "4374173a8cbe88de152b609f96f46e958bcf65762017474eec5a05ec2bd61530";
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
             emptyAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "";
               outputHashMode = "recursive";
             };
             bogusAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "bogus";
               outputHashMode = "recursive";
             };
             dashAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "sha-256";
               outputHashMode = "recursive";
             };
             upperAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "SHA256";
               outputHashMode = "recursive";
             };
             emptyHash = mk {
               outputHash = "";
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
           in {
             bogusAlgo = bogusAlgo.out;
             bogusAlgoDrv = bogusAlgo.drvPath;
             dashAlgo = dashAlgo.out;
             dashAlgoDrv = dashAlgo.drvPath;
             drvFlat = flat.drvPath;
             drvRecursive = recursive.drvPath;
             emptyAlgo = emptyAlgo.out;
             emptyAlgoDrv = emptyAlgo.drvPath;
             emptyHash = emptyHash.out;
             emptyHashDrv = emptyHash.drvPath;
             flat = flat.out;
             omittedAlgo = omittedAlgo.out;
             omittedMode = omittedMode.out;
             raw = raw.out;
             recursive = recursive.out;
             upperAlgo = upperAlgo.out;
             upperAlgoDrv = upperAlgo.drvPath;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"bogusAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","bogusAlgoDrv":"/nix/store/2y7fz2ii2r75dvrxsqc2z3px3v159lzq-foo.drv","dashAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","dashAlgoDrv":"/nix/store/lbpn865wvns79mxjz1nf532s61rxvpv3-foo.drv","drvFlat":"/nix/store/jl08sl0js08lghpzy0vr5lz64wyf4vny-foo.drv","drvRecursive":"/nix/store/yxkyw9zabh90wi2ak4j2f43xx44j35k6-foo.drv","emptyAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","emptyAlgoDrv":"/nix/store/18fky491dplc3n09l99491ji924jv02j-foo.drv","emptyHash":"/nix/store/1dcapabdb1anckxk8md1m0dpqx5jmm73-foo","emptyHashDrv":"/nix/store/35lwba14kzq02b5mvk01v2rh042rdagf-foo.drv","flat":"/nix/store/q4pkwkxdib797fhk22p0k3g1q32jmxvf-foo","omittedAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","omittedMode":"/nix/store/q4pkwkxdib797fhk22p0k3g1q32jmxvf-foo","raw":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","recursive":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","upperAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","upperAlgoDrv":"/nix/store/3jp0xvy6sw6wfz1p2i3ja8swb2bjaaak-foo.drv"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_recursive_sha1_fixed_output_derivations() {
    let bar = r#"derivationStrict {
             name = "bar";
             system = ":";
             builder = ":";
             outputHash = "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33";
             outputHashAlgo = "sha1";
             outputHashMode = "recursive";
           }"#;
    let source = format!("let d = {bar}; in {{ drvPath = d.drvPath; out = d.out; }}");

    assert_eq!(
            eval_json_bytes(&source),
            br#"{"drvPath":"/nix/store/ss2p4wmxijn652haqyd7dckxwl4c7hxx-bar.drv","out":"/nix/store/mp57d33657rf34lzvlbpfa1gjfv5gmpg-bar"}"#.to_vec()
        );

    let outcome = eval_whnf_owned(&lower(&format!("let d = {bar}; in d.drvPath")))
        .expect("recursive SHA-1 fixed-output derivation evaluates");
    let recorded = outcome
        .derivations()
        .iter()
        .find(|drv| drv.absolute_path() == "/nix/store/ss2p4wmxijn652haqyd7dckxwl4c7hxx-bar.drv")
        .expect("recursive SHA-1 fixed-output derivation records ATerm bytes");

    assert_eq!(
            recorded.aterm_bytes(),
            Some(
                br#"Derive([("out","/nix/store/mp57d33657rf34lzvlbpfa1gjfv5gmpg-bar","r:sha1","0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33")],[],[],":",":",[],[("builder",":"),("name","bar"),("out","/nix/store/mp57d33657rf34lzvlbpfa1gjfv5gmpg-bar"),("outputHash","0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"),("outputHashAlgo","sha1"),("outputHashMode","recursive"),("system",":")])"#.as_slice()
            )
        );

    let downstream = format!(
        r#"let
                 bar = {bar};
                 foo = derivationStrict {{
                   name = "foo";
                   system = ":";
                   builder = ":";
                   bar = bar.out;
                 }};
               in {{ drvPath = foo.drvPath; out = foo.out; }}"#
    );
    assert_eq!(
            eval_json_bytes(&downstream),
            br#"{"drvPath":"/nix/store/ch49594n9avinrf8ip0aslidkc4lxkqv-foo.drv","out":"/nix/store/fhaj6gmwns62s6ypkcldbaj2ybvkhx3p-foo"}"#.to_vec()
        );

    let downstream_drv_path = format!(
        r#"let
                 bar = {bar};
                 foo = derivationStrict {{
                   name = "foo";
                   system = ":";
                   builder = ":";
                   bar = bar.out;
                 }};
               in foo.drvPath"#
    );
    let outcome = eval_whnf_owned(&lower(&downstream_drv_path))
        .expect("downstream derivation depending on SHA-1 FOD evaluates");
    let downstream_recorded = outcome
        .derivations()
        .iter()
        .find(|drv| drv.absolute_path() == "/nix/store/ch49594n9avinrf8ip0aslidkc4lxkqv-foo.drv")
        .expect("downstream derivation records ATerm bytes");

    assert_eq!(
            downstream_recorded.aterm_bytes(),
            Some(
                br#"Derive([("out","/nix/store/fhaj6gmwns62s6ypkcldbaj2ybvkhx3p-foo","","")],[("/nix/store/ss2p4wmxijn652haqyd7dckxwl4c7hxx-bar.drv",["out"])],[],":",":",[],[("bar","/nix/store/mp57d33657rf34lzvlbpfa1gjfv5gmpg-bar"),("builder",":"),("name","foo"),("out","/nix/store/fhaj6gmwns62s6ypkcldbaj2ybvkhx3p-foo"),("system",":")])"#.as_slice()
            )
        );
}

#[test]
fn derivation_strict_supports_disabled_content_addressed_marker() {
    let source = r#"let
             d = derivationStrict {
               name = "foo";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               __contentAddressed = false;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
           in {
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/y73d5vkljj9wx7hxjpfswzv5m2cgz6xw-foo.drv","names":["drvPath","out"],"out":"/nix/store/i4v7l2ia22fdp6d1nfy4w836zbg3h6hv-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_disabled_impure_marker() {
    let source = r#"let
             explicitFalse = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = false;
             };
             structuredFalse = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __impure = false;
             };
             ignoredNull = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __impure = null;
               __ignoreNulls = true;
             };
           in {
             explicitFalseDrv = explicitFalse.drvPath;
             explicitFalseOut = explicitFalse.out;
             ignoredNullDrv = ignoredNull.drvPath;
             ignoredNullOut = ignoredNull.out;
             structuredFalseDrv = structuredFalse.drvPath;
             structuredFalseOut = structuredFalse.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"explicitFalseDrv":"/nix/store/byy6hf9vzifjqikj1wxh1dlz1k2mm55y-foo.drv","explicitFalseOut":"/nix/store/zyxk99gi89lp0n4acr3ingrdp8pwjqcp-foo","ignoredNullDrv":"/nix/store/qsg1hv3lkdblqrzknfz5hrwa2ylhqi7d-foo.drv","ignoredNullOut":"/nix/store/m1839r6ds9nkq40ndigls6fgmi6h4j6x-foo","structuredFalseDrv":"/nix/store/q0bwyr5jasf511qq3jzz93s31782kw17-foo.drv","structuredFalseOut":"/nix/store/9jld8vmqis8rk1n1vgcncxznx3s3v8yr-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_floating_content_addressed_derivations() {
    let source = r#"let
             recursive = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
             flat = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "flat";
             };
             defaulted = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
             };
             multi = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputs = [ "out" "dev" ];
             };
           in {
             defaultDrv = defaulted.drvPath;
             defaultOut = defaulted.out;
             flatDrv = flat.drvPath;
             flatOut = flat.out;
             multiDev = multi.dev;
             multiDrv = multi.drvPath;
             multiNames = builtins.attrNames multi;
             multiOut = multi.out;
             recursiveCtx = builtins.getContext recursive.out;
             recursiveDrv = recursive.drvPath;
             recursiveDrvCtx = builtins.getContext recursive.drvPath;
             recursiveNames = builtins.attrNames recursive;
             recursiveOut = recursive.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"defaultDrv":"/nix/store/asqvh5kd8syak2nap6qfby2kzhad93ln-foo.drv","defaultOut":"/0va4qp2ahx6mzdj5jv1rmd902hpfaiqqqiacifnckwnv2ab0356k","flatDrv":"/nix/store/h45pc0783njkplw61p57klqwk4rq88wd-foo.drv","flatOut":"/0dy829a8ha7khjxzv6pc5fv0xfsgby2mdgqavyj8cnr610fgi1sm","multiDev":"/1zcx5za1flqh9fnmak474592n4lr9b55ign6qry5ycc0n0j9rzgv","multiDrv":"/nix/store/mj5lbvmrbi0wak4g3scs801dbh5rvd5k-foo.drv","multiNames":["dev","drvPath","out"],"multiOut":"/0qwqpv6x549qb5amk1slwbswzjh03n435ddw392rs6n5h2wbglr4","recursiveCtx":{"/nix/store/5d4gn8jbm861c1pcharmm24yzacv5x4h-foo.drv":{"outputs":["out"]}},"recursiveDrv":"/nix/store/5d4gn8jbm861c1pcharmm24yzacv5x4h-foo.drv","recursiveDrvCtx":{"/nix/store/5d4gn8jbm861c1pcharmm24yzacv5x4h-foo.drv":{"allOutputs":true}},"recursiveNames":["drvPath","out"],"recursiveOut":"/1h9lmzdzqh6czk0m08hbfk343704ykhfwfwz3160xnamfgggfjws"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_floating_ca_matches_cpp_nix_hash_algo_and_mode_parsing() {
    let source = r#"let
             bogus = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "bogus";
               outputHashMode = "recursive";
             };
             empty = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "";
               outputHashMode = "recursive";
             };
             nar = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "nar";
             };
             upper = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "SHA256";
               outputHashMode = "recursive";
             };
           in {
             bogusDrv = bogus.drvPath;
             bogusOut = bogus.out;
             emptyDrv = empty.drvPath;
             emptyOut = empty.out;
             narDrv = nar.drvPath;
             narOut = nar.out;
             upperDrv = upper.drvPath;
             upperOut = upper.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"bogusDrv":"/nix/store/sfvbsz4716wchmgqccrbgyx82bwwp0bl-foo.drv","bogusOut":"/1qxz9i2h42krf58nihzbybdd0i4nfskc85ywjvg1z3k7slnl1a4p","emptyDrv":"/nix/store/9g7if9vq9c7zfigby235xgcla16n3s5h-foo.drv","emptyOut":"/0khcai9n321warx3azdv4c16573x8pnc05pndwikd8rbzkrwbqh6","narDrv":"/nix/store/6w7snr1mlr3kq48cq8lj22vqc7fjw19h-foo.drv","narOut":"/137j0hqh4klrf447lfyfzjv4x37fbzwz5kv1drk36jg225dc539k","upperDrv":"/nix/store/05p9rdwygprb3xw84ybssjh06m1yziry-foo.drv","upperOut":"/0ky0f7m9zhjvl1s8fc60mvaayb9rf1f7l73acq5293n9r3lz3780"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_content_addressed_marker_preserves_fixed_output_derivation() {
    let source = r#"let
             recursive = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
             nar = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "nar";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
           in {
             narDrv = nar.drvPath;
             narOut = nar.out;
             recursiveDrv = recursive.drvPath;
             recursiveOut = recursive.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"narDrv":"/nix/store/g72ixp5q1kzsm4nk85fazw8x5zdw92dx-foo.drv","narOut":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","recursiveDrv":"/nix/store/3yx7944f4sjjnh56pynw9i73mbmavwb9-foo.drv","recursiveOut":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_content_addressed_derivations_defer_downstream_outputs() {
    let source = r#"let
             base = derivationStrict {
               name = "base";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
             d = derivationStrict {
               name = "user";
               system = ":";
               builder = ":";
               input = base.out;
             };
           in {
             baseDrv = base.drvPath;
             baseOut = base.out;
             ctx = builtins.getContext d.out;
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/sycp28psd9pmlky6a4jpcb5lijdfjw6g-base.drv","baseOut":"/12b6k9m59nmk4z3mpbpi60a9626jbcihnxmydd980k8jvgwsb8ry","ctx":{"/nix/store/l6n89w9r2i5pn8p9asx7zkxpbqwwgi2y-user.drv":{"outputs":["out"]}},"drvPath":"/nix/store/l6n89w9r2i5pn8p9asx7zkxpbqwwgi2y-user.drv","out":"/0dgqgrnsrgzgjvxqfag1i449qjkl8fixagz9dlj6arf2py6m7mz5"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_deferred_derivation_paths_sort_and_dedupe_references() {
    let ir = lower("null");
    let eval = TreeWalk::new(&ir);
    let id = IrId::new(0);
    let span = Span::new(0, 0);
    let output = FloatingCaOutput {
        method: FloatingCaMethod::Recursive,
        hash_algo: nix_compat::nixhash::HashAlgo::Sha256,
    };
    let low_drv = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-low.drv",
    )
    .expect("low drv store path parses");
    let high_drv = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-high.drv",
    )
    .expect("high drv store path parses");
    let mut derivation = nix_compat::derivation::Derivation::default();
    derivation
        .outputs
        .insert("out".to_owned(), nix_compat::derivation::Output::default());
    derivation.input_sources.insert(high_drv.clone());
    derivation
        .input_derivations
        .insert(low_drv.clone(), BTreeSet::from(["out".to_owned()]));
    derivation
        .input_derivations
        .insert(high_drv.clone(), BTreeSet::from(["out".to_owned()]));
    let references = BTreeSet::from([low_drv.to_absolute_path(), high_drv.to_absolute_path()]);

    let static_aterm = eval.derivation_aterm_bytes(&derivation);
    let expected =
        nix_compat::store_path::build_text_path("mixed.drv", &static_aterm, references.clone())
            .expect("expected ordinary path builds");
    let actual = eval
        .calculate_derivation_path(id, span, "mixed", &derivation)
        .expect("ordinary path builds");
    assert_eq!(actual, expected);

    let floating_aterm = eval.floating_ca_derivation_aterm_bytes(&derivation, output, None);
    let expected =
        nix_compat::store_path::build_text_path("mixed.drv", &floating_aterm, references.clone())
            .expect("expected floating path builds");
    let actual = eval
        .calculate_floating_ca_derivation_path(id, span, "mixed", &derivation, output)
        .expect("floating path builds");
    assert_eq!(actual, expected);

    let impure_aterm = eval.impure_derivation_aterm_bytes(&derivation, output, None);
    let expected = nix_compat::store_path::build_text_path("mixed.drv", &impure_aterm, references)
        .expect("expected impure path builds");
    let actual = eval
        .calculate_impure_derivation_path(id, span, "mixed", &derivation, output)
        .expect("impure path builds");
    assert_eq!(actual, expected);
}

#[test]
fn derivation_strict_deferred_forms_use_configured_store_dir() {
    let store_dir = unique_temp_dir("derivation-strict-deferred-store");
    let store_root = path_source(&store_dir);
    let store_prefix = format!("{store_root}/");
    let src_path = format!("{store_root}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src");
    let options = TreeWalkOptions::with_store_dir(store_root.as_bytes().to_vec())
        .expect("temporary store root configures");
    let src_path_literal = nix_string_literal(&src_path);
    let source = format!(
        r#"let
                 opaque = builtins.appendContext "src" {{
                   {src_path_literal} = {{ path = true; }};
                 }};
                 floating = derivationStrict {{
                   name = "floating";
                   system = ":";
                   builder = ":";
                   __contentAddressed = true;
                   outputHashAlgo = "sha256";
                   outputHashMode = "recursive";
                   input = opaque;
                 }};
                 impure = derivationStrict {{
                   name = "impure";
                   system = ":";
                   builder = ":";
                   __impure = true;
                   input = opaque;
                 }};
                 downstream = derivationStrict {{
                   name = "user";
                   system = ":";
                   builder = ":";
                   input = floating.out;
                 }};
               in {{
                 downstreamCtx = builtins.getContext downstream.out;
                 downstreamDrv = downstream.drvPath;
                 floatingDrv = floating.drvPath;
                 impureDrv = impure.drvPath;
               }}"#
    );
    let outcome =
        eval_whnf_owned_with_options(&lower(&format!("builtins.toJSON ({source})")), options)
            .expect("custom-store deferred derivations evaluate");
    let json = outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is JSON string")
        .bytes()
        .to_vec();
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("custom-store result JSON parses");
    let floating_drv = value["floatingDrv"]
        .as_str()
        .expect("floating drv path is a string");
    let impure_drv = value["impureDrv"]
        .as_str()
        .expect("impure drv path is a string");
    let downstream_drv = value["downstreamDrv"]
        .as_str()
        .expect("downstream drv path is a string");

    for drv_path in [floating_drv, impure_drv, downstream_drv] {
        assert!(drv_path.starts_with(&store_prefix), "{drv_path}");
        assert!(drv_path.ends_with(".drv"), "{drv_path}");
        assert!(!drv_path.starts_with("/nix/store/"), "{drv_path}");
    }
    assert_eq!(
        value["downstreamCtx"][downstream_drv],
        serde_json::json!({ "outputs": ["out"] })
    );

    let floating_aterm = outcome
        .derivations()
        .iter()
        .find(|derivation| derivation.absolute_path() == floating_drv)
        .and_then(EvalDerivation::aterm_bytes)
        .expect("floating derivation has a materialized ATerm");
    let floating_aterm = std::str::from_utf8(floating_aterm).expect("floating ATerm is UTF-8");
    assert!(floating_aterm.contains(&src_path), "{floating_aterm}");
    assert!(!floating_aterm.contains("/nix/store"), "{floating_aterm}");

    let impure_aterm = outcome
        .derivations()
        .iter()
        .find(|derivation| derivation.absolute_path() == impure_drv)
        .and_then(EvalDerivation::aterm_bytes)
        .expect("impure derivation has a materialized ATerm");
    let impure_aterm = std::str::from_utf8(impure_aterm).expect("impure ATerm is UTF-8");
    assert!(impure_aterm.contains(&src_path), "{impure_aterm}");
    assert!(!impure_aterm.contains("/nix/store"), "{impure_aterm}");

    let downstream_aterm = outcome
        .derivations()
        .iter()
        .find(|derivation| derivation.absolute_path() == downstream_drv)
        .and_then(EvalDerivation::aterm_bytes)
        .expect("downstream derivation has a materialized ATerm");
    let downstream_aterm =
        std::str::from_utf8(downstream_aterm).expect("downstream ATerm is UTF-8");
    assert!(
        downstream_aterm.contains(floating_drv),
        "{downstream_aterm}"
    );
    assert!(
        !downstream_aterm.contains("/nix/store"),
        "{downstream_aterm}"
    );

    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn derivation_strict_unions_input_hash_replacement_outputs() {
    let first = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-first.drv",
    )
    .expect("first store path parses");
    let second = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-second.drv",
    )
    .expect("second store path parses");
    let missing = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"cccccccccccccccccccccccccccccccc-missing.drv",
    )
    .expect("missing store path parses");

    let mut derivation = nix_compat::derivation::Derivation::default();
    derivation
        .input_derivations
        .insert(first.clone(), BTreeSet::from(["out".to_owned()]));
    derivation
        .input_derivations
        .insert(second.clone(), BTreeSet::from(["dev".to_owned()]));
    derivation
        .input_derivations
        .insert(missing, BTreeSet::from(["ignored".to_owned()]));

    let shared_hash = [42_u8; 32];
    let mut input_hashes = BTreeMap::new();
    input_hashes.insert(first, shared_hash);
    input_hashes.insert(second, shared_hash);

    let replacements = TreeWalk::input_hash_replacements(&derivation, &input_hashes);
    assert_eq!(replacements.len(), 1);
    assert_eq!(
        replacements.get(&shared_hash),
        Some(&BTreeSet::from(["dev".to_owned(), "out".to_owned()]))
    );
}

#[test]
fn derivation_strict_supports_structured_floating_content_addressed_derivations() {
    let source = r#"let
             d = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/f0gabys2ih4l8v9npyar6bj5xsa8rj2k-foo.drv","out":"/1w3qgj09cidhvf61hmb2bzyxy64mkcbxzjm6n631m62yjpjhzzvg"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_rejects_invalid_content_addressed_marker() {
    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 __contentAddressed = 1;
               }"#,
    ))
    .expect_err("content-addressed marker must be a bool");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn derivation_strict_supports_impure_derivations() {
    let source = r#"let
             simple = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
             };
             flat = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
               outputHashAlgo = "sha256";
               outputHashMode = "flat";
             };
             structured = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __impure = true;
             };
             multi = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
               outputs = [ "out" "dev" ];
             };
             fixed = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
             base = derivationStrict {
               name = "base";
               system = ":";
               builder = ":";
               __impure = true;
             };
             user = derivationStrict {
               name = "user";
               system = ":";
               builder = ":";
               input = base.out;
             };
           in {
             baseDrv = base.drvPath;
             baseOut = base.out;
             fixedDrv = fixed.drvPath;
             fixedOut = fixed.out;
             flatDrv = flat.drvPath;
             flatOut = flat.out;
             multiDev = multi.dev;
             multiDrv = multi.drvPath;
             multiNames = builtins.attrNames multi;
             multiOut = multi.out;
             simpleCtx = builtins.getContext simple.out;
             simpleDrv = simple.drvPath;
             simpleDrvCtx = builtins.getContext simple.drvPath;
             simpleNames = builtins.attrNames simple;
             simpleOut = simple.out;
             structuredDrv = structured.drvPath;
             structuredOut = structured.out;
             userCtx = builtins.getContext user.out;
             userDrv = user.drvPath;
             userOut = user.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/a0by77ssxmlrqwa9dkfaf04pvbdxzqjg-base.drv","baseOut":"/034l5i2lm0zpg5g58qyq6d01rvazw3yqwzmqkqxl9gcq0z56r4m6","fixedDrv":"/nix/store/3yx7944f4sjjnh56pynw9i73mbmavwb9-foo.drv","fixedOut":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","flatDrv":"/nix/store/5c3xzfl0man0kdk45i398k3avzkk8wvy-foo.drv","flatOut":"/1jw26j2wrfih6x0hh9c6a966sirzvbn4hsnkin2s91s101z48rr7","multiDev":"/04afr1wv95cmfkd5dm12ndybypx7z8dxz06fiwkalm48risqvl10","multiDrv":"/nix/store/9b3swmf9xwz9jv8zh8pn8wplaw3wdqd0-foo.drv","multiNames":["dev","drvPath","out"],"multiOut":"/0c1mqws5832mvaqkx6v4203nf7jz51yn45b5v3pylm5r0j9yfb9m","simpleCtx":{"/nix/store/kxf0wsv4s2sq32qf8babggax9dvv970r-foo.drv":{"outputs":["out"]}},"simpleDrv":"/nix/store/kxf0wsv4s2sq32qf8babggax9dvv970r-foo.drv","simpleDrvCtx":{"/nix/store/kxf0wsv4s2sq32qf8babggax9dvv970r-foo.drv":{"allOutputs":true}},"simpleNames":["drvPath","out"],"simpleOut":"/0fdh6nchbj3w1s0dzdxb44b0cnypwzx7fz5lk4v46603phqkx69y","structuredDrv":"/nix/store/ymkzcxxfrrac7jbyqbxdrkmsic6cykpp-foo.drv","structuredOut":"/1i8lg293jg8xhica7znnava0a639bi5gfj01ymqrsrls5dliiwhf","userCtx":{"/nix/store/d9h67hj8bydbm3lncixzliv1kwl0nw89-user.drv":{"outputs":["out"]}},"userDrv":"/nix/store/d9h67hj8bydbm3lncixzliv1kwl0nw89-user.drv","userOut":"/09jldbl2zzha90yv0zs8jxkj1hm48xh7bxz45qfn45k5n8084k1w"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_impure_derivations_compose_with_other_output_types() {
    let source = r#"let
             impureBase = derivationStrict {
               name = "base";
               system = ":";
               builder = ":";
               __impure = true;
             };
             floatingCa = derivationStrict {
               name = "ca";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               input = impureBase.out;
             };
             downstream = derivationStrict {
               name = "user";
               system = ":";
               builder = ":";
               input = floatingCa.out;
             };
             fixedFromImpure = derivationStrict {
               name = "fixed";
               system = ":";
               builder = ":";
               input = impureBase.out;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
             fixedWithBothMarkers = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = true;
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
           in {
             baseDrv = impureBase.drvPath;
             baseOut = impureBase.out;
             downstreamCtx = builtins.getContext downstream.out;
             downstreamDrv = downstream.drvPath;
             downstreamOut = downstream.out;
             fixedCtx = builtins.getContext fixedFromImpure.out;
             fixedDrv = fixedFromImpure.drvPath;
             fixedOut = fixedFromImpure.out;
             floatingCaDrv = floatingCa.drvPath;
             floatingCaOut = floatingCa.out;
             markerFixedDrv = fixedWithBothMarkers.drvPath;
             markerFixedOut = fixedWithBothMarkers.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/a0by77ssxmlrqwa9dkfaf04pvbdxzqjg-base.drv","baseOut":"/034l5i2lm0zpg5g58qyq6d01rvazw3yqwzmqkqxl9gcq0z56r4m6","downstreamCtx":{"/nix/store/bqab1ykzfz4x076pcp4vq1jfq5c05a8n-user.drv":{"outputs":["out"]}},"downstreamDrv":"/nix/store/bqab1ykzfz4x076pcp4vq1jfq5c05a8n-user.drv","downstreamOut":"/036ba2igq8ix62kw8q0q11blslb8zrymdajg225m7xbampbi081q","fixedCtx":{"/nix/store/i8f1hl9v5jhk4f268acw73w8nymbwkha-fixed.drv":{"outputs":["out"]}},"fixedDrv":"/nix/store/i8f1hl9v5jhk4f268acw73w8nymbwkha-fixed.drv","fixedOut":"/nix/store/y2bmryv6a5lpk1z2k50b7mddffkf13j4-fixed","floatingCaDrv":"/nix/store/p672mcc8435xhc4bqcf4qf1kn88jzv75-ca.drv","floatingCaOut":"/01rrdjiwi1yd7v29i3981h3brdfnfw8y1wmhvs94m9zyjlh67c6b","markerFixedDrv":"/nix/store/3yx7944f4sjjnh56pynw9i73mbmavwb9-foo.drv","markerFixedOut":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_rejects_invalid_impure_derivations() {
    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __contentAddressed = true;
                 __impure = true;
               }"#,
    ))
    .expect_err("content-addressed impure derivation must be rejected");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DerivationStrict {
            message,
            ..
        } if message == "derivation cannot be both content-addressed and impure"
    ));

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "foo";
                 system = ":";
                 builder = ":";
                 __impure = 1;
               }"#,
    ))
    .expect_err("impure marker must be a bool");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn derivation_strict_rejects_invalid_fixed_output_derivations() {
    for source in [
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "";
                 outputHashAlgo = "";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "";
                 outputHashAlgo = "bogus";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "4374173a8cbe88de152b609f96f46e958bcf65762017474eec5a05ec2bd61530";
                 outputHashAlgo = "bogus";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "4374173a8cbe88de152b609f96f46e958bcf65762017474eec5a05ec2bd61530";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha256";
                 outputHashMode = "bad";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha1";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ "out" "dev" ];
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "foo";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ "dev" ];
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source))
            .expect_err("invalid fixed-output derivation is rejected");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::DerivationStrict { .. }),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_allows_drv_output_name_but_not_drv_path() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputs = [ "drv" ];
             };
           in {
             drv = d.drv;
             drvPath = d.drvPath;
             names = builtins.attrNames d;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drv":"/nix/store/bns120nfy7bm27fpsdf7jfkq1laf809f-x-drv","drvPath":"/nix/store/ki88ybnps5knx7lxvicz21x8n9spzhs7-x.drv","names":["drv","drvPath"]}"#.to_vec()
        );

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ "drvPath" ];
               }"#,
    ))
    .expect_err("drvPath is reserved for the derivation path attribute");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DerivationStrict { message, .. }
            if message.contains("invalid derivation output name")
    ));
}

#[test]
fn derivation_strict_rejects_empty_and_duplicate_outputs() {
    for source in [
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ ];
               }"#,
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = [ "out" "out" ];
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("invalid outputs must be rejected");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::DerivationStrict { .. }),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_allows_drv_path_as_input_output_name() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               input = builtins.appendContext "payload" {
                 "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-input.drv" = {
                   outputs = [ "drvPath" ];
                 };
               };
             };
           in d.drvPath"#;

    let error = eval_whnf_owned(&lower(source))
        .expect_err("unknown input drv should be reported after output-name validation");
    assert!(
        matches!(
            error.kind(),
            TreeWalkErrorKind::DerivationStrict { message, .. }
                if message.contains("is not known")
        ),
        "{error:?}"
    );
}

#[test]
fn derivation_strict_rejects_missing_known_input_output_name() {
    let source = r#"let
             base = derivationStrict {
               name = "base";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
               input = builtins.appendContext "payload" {
                 "/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv" = {
                   outputs = [ "drvPath" ];
                 };
               };
             };
           in builtins.seq base.drvPath d.drvPath"#;

    assert_eq!(
        eval_string_bytes(
            "let base = derivationStrict { name = \"base\"; system = \"x86_64-linux\"; builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder\"; }; in base.drvPath"
        ),
        b"/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv".to_vec()
    );

    let error = eval_whnf_owned(&lower(source))
        .expect_err("known input derivation does not provide drvPath output");
    assert!(
        matches!(
            error.kind(),
            TreeWalkErrorKind::DerivationStrict { message, .. }
                if message.contains("has no output")
        ),
        "{error:?}"
    );
}

#[test]
fn derivation_strict_supports_arguments() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ "a" "b c" 7 true false null ];
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/jd4xrrbkljw5cjzl1cl5aid034ax3r3r-x.drv","out":"/nix/store/wbpvl18k2swqk8m05048r544h4kxb3hc-x"}"#.to_vec()
        );

    let nested = r#"let
             simple = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ "a b" "c" ];
             };
             nested = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ [ "a" "b" ] "c" ];
             };
           in {
             nested = nested.drvPath;
             same = simple.drvPath == nested.drvPath;
             simple = simple.drvPath;
           }"#;

    assert_eq!(
            eval_json_bytes(nested),
            br#"{"nested":"/nix/store/5wq01zb7i3yxn0aj6l1snyflpzvc704g-x.drv","same":true,"simple":"/nix/store/5wq01zb7i3yxn0aj6l1snyflpzvc704g-x.drv"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_observes_argument_contexts_as_inputs() {
    let source = r#"let
             base = derivationStrict {
               name = "base";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
               args = [ "${base.out}" ];
             };
           in {
             baseDrv = base.drvPath;
             baseOut = base.out;
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv","baseOut":"/nix/store/c9hhy38jds9ffzzqwkb50vrv2pi8x614-base","drvPath":"/nix/store/jpaibv0aq71nimqkaa2zgzhyjx3jsdqm-x.drv","out":"/nix/store/v9psivi4r812mfl72k0y62b61r1f6gvb-x"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_first_class_values_call_builtin() {
    for source in [
        r#"let
                 f = derivationStrict;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in builtins.hasAttr "out" d"#,
        r#"let
                 f = builtins.derivationStrict;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in builtins.hasAttr "drvPath" d"#,
        r#"with { derivationStrict = x: x; }; let
                 f = derivationStrict;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in builtins.hasAttr "out" d"#,
    ] {
        assert_eq!(eval(source).as_bool(), Ok(true), "{source}");
    }

    let ir = lower("with { derivationStrict = x: x; }; let f = derivationStrict; in f 1");
    let error = eval_whnf_owned(&ir).expect_err("derivationStrict remains unshadowable");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn derivation_strict_observes_contexts_as_inputs() {
    let source = r#"let
             base = derivationStrict {
               name = "base";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
             opaque = builtins.appendContext "src" {
               "/nix/store/cccccccccccccccccccccccccccccccc-src" = { path = true; };
             };
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
               input = "${base.out}${opaque}";
             };
           in {
             baseDrv = base.drvPath;
             baseOut = base.out;
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv","baseOut":"/nix/store/c9hhy38jds9ffzzqwkb50vrv2pi8x614-base","drvPath":"/nix/store/g517w28ijkgqc1p2hqwrnjwh1lblnavz-x.drv","out":"/nix/store/7alc4f6hbky5mkzhqqsmyw7mk354i4mh-x"}"#.to_vec()
        );
}

#[test]
fn derivation_coercion_preserves_out_path_context() {
    assert_eq!(
        eval(
            r#"let
                     strict = derivationStrict {
                       name = "x";
                       system = "x86_64-linux";
                       builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                     };
                     drv = {
                       type = "derivation";
                       name = "x";
                       drvPath = strict.drvPath;
                       outPath = strict.out;
                     };
                     rendered = "${drv}";
                     ctx = builtins.getContext rendered;
                   in rendered == strict.out && builtins.hasAttr strict.drvPath ctx"#
        )
        .as_bool(),
        Ok(true)
    );
}

#[test]
fn string_add_rejects_non_string_rhs() {
    let ir = lower("\"a\" + 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("addition root has binary payload");
    };
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&ir).expect_err("integer rhs is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn string_add_evaluates_rhs_before_type_checking_it() {
    let ir = lower("\"a\" + (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("addition root has binary payload");
    };
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&ir).expect_err("rhs evaluation error wins");

    assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn numeric_add_rejects_string_rhs_as_non_numeric() {
    let ir = lower("1 + \"a\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::Binary { rhs, .. } = root.data else {
        panic!("addition root has binary payload");
    };
    let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

    let error = eval_whnf_owned(&ir).expect_err("string rhs is invalid for numeric add");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: rhs,
            expected: "number",
            actual: ValueTag::String,
        }
    );
    assert_eq!(error.span(), rhs_span);
}

#[test]
fn integer_literals_cover_i64_boundaries() {
    assert_eq!(eval("9223372036854775807").as_int(), Ok(i64::MAX));
    assert_eq!(
        eval("0 + (-9223372036854775807 - 1)").as_int(),
        Ok(i64::MIN)
    );
}

#[test]
fn addition_rejects_mismatched_operand_kinds() {
    for source in [
        "true + false",
        "null + null",
        "[ 1 ] + [ 2 ]",
        "{ a = 1; } + { b = 2; }",
        "(x: x) + (x: x)",
    ] {
        eval_whnf_owned(&lower(source)).expect_err("mismatched addition operands are invalid");
    }
}

#[test]
fn addition_coerces_left_attrsets_with_raw_string_rules() {
    let (dir, path) = temp_file_with_bytes("attrs-add-path", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_string_bytes(r#"{ __toString = self: "left"; } + "right""#),
        b"leftright"
    );
    assert_eq!(
        eval_string_bytes(r#"{ outPath = "left"; } + { outPath = "right"; }"#),
        b"leftright"
    );
    assert_eq!(
        eval_string_bytes(&format!("{{ __toString = self: {path}; }} + {path}")),
        format!("{path}{path}").as_bytes()
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "builtins.getContext ({{ __toString = self: {path}; }} + {path})"
        )),
        b"{}"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn addition_type_matrix_accepts_only_nix_legal_operand_pairs() {
    let (dir, operands) = add_operator_matrix_operands("add-matrix");

    for left in &operands {
        for right in &operands {
            let source = add_operator_matrix_source(left, right);
            if add_operator_matrix_cell_is_legal(left.kind, right.kind) {
                assert_eq!(
                    eval(&source).as_bool(),
                    Ok(true),
                    "{:?} + {:?} should be legal",
                    left.kind,
                    right.kind
                );
            } else {
                assert!(
                    eval_whnf_owned(&lower(&source)).is_err(),
                    "{:?} + {:?} should be illegal",
                    left.kind,
                    right.kind
                );
            }
        }
    }

    fs::remove_dir_all(dir).expect("matrix temp directory removes");
}

#[test]
fn non_owning_eval_rejects_string_add_heap_values() {
    let ir = lower("\"a\" + \"b\"");
    let error = eval_whnf(&ir).expect_err("string add value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::String,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );
}

#[test]
fn non_owning_eval_rejects_heap_values() {
    let ir = lower("\"hello\"");
    let error = eval_whnf(&ir).expect_err("string value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::String,
        }
    );
    assert_eq!(
        error.span(),
        ir.arena.node(ir.root).expect("root exists").span
    );

    let list_ir = lower("[]");
    let error = eval_whnf(&list_ir).expect_err("list value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: list_ir.root,
            tag: ValueTag::List,
        }
    );
    assert_eq!(
        error.span(),
        list_ir.arena.node(list_ir.root).expect("root exists").span
    );

    let non_empty_list_ir = lower("[ 1 ]");
    let error = eval_whnf(&non_empty_list_ir).expect_err("non-empty list needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: non_empty_list_ir.root,
            tag: ValueTag::List,
        }
    );
    assert_eq!(
        error.span(),
        non_empty_list_ir
            .arena
            .node(non_empty_list_ir.root)
            .expect("root exists")
            .span
    );

    let attrs_ir = lower("{}");
    let error = eval_whnf(&attrs_ir).expect_err("attrset value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: attrs_ir.root,
            tag: ValueTag::Attrs,
        }
    );
    assert_eq!(
        error.span(),
        attrs_ir
            .arena
            .node(attrs_ir.root)
            .expect("root exists")
            .span
    );

    let lambda_ir = lower("x: x");
    let error = eval_whnf(&lambda_ir).expect_err("lambda value needs owning heap");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: lambda_ir.root,
            tag: ValueTag::Lambda,
        }
    );
    assert_eq!(
        error.span(),
        lambda_ir
            .arena
            .node(lambda_ir.root)
            .expect("root exists")
            .span
    );
}

#[test]
fn invalid_expression_nodes_report_kind_and_span() {
    for (kind, data) in [
        (
            IrKind::FormalSet,
            IrData::FormalSet {
                formals: IrChildSlice::new(0, 0),
                ellipsis: false,
                alias: None,
            },
        ),
        (
            IrKind::Formal,
            IrData::Formal {
                name: Symbol::new(0),
                default: None,
            },
        ),
    ] {
        let root = IrId::new(0);
        let span = Span::new(0, 1);
        let ir = manual_ir(root, vec![pure_node(kind, span, data)]);
        let error = eval_whnf(&ir).expect_err("helper nodes are not directly evaluable");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidNodeKind { id: root, kind }
        );
        assert_eq!(error.span(), span);
    }
}

#[test]
fn pipe_operators_apply_functions() {
    let mut symbols = SymbolTable::new();
    let to_string = symbols.intern(b"toString").expect("symbol interns");

    let forward = manual_ir_with_symbols(
        IrId::new(2),
        vec![
            pure_node(IrKind::Int, Span::new(0, 2), IrData::Int(42)),
            pure_node(
                IrKind::GlobalVar,
                Span::new(6, 14),
                IrData::Symbol(to_string),
            ),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 14),
                IrData::Binary {
                    op: BinOpKind::PipeRight,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        symbols.clone(),
    );
    let forward = eval_whnf_owned(&forward).expect("forward pipe evaluates");
    assert_eq!(
        forward
            .heap()
            .get_string(forward.value())
            .expect("forward pipe returns a string")
            .bytes(),
        b"42",
    );

    let reverse = manual_ir_with_symbols(
        IrId::new(2),
        vec![
            pure_node(
                IrKind::GlobalVar,
                Span::new(0, 8),
                IrData::Symbol(to_string),
            ),
            pure_node(IrKind::Int, Span::new(12, 13), IrData::Int(7)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 13),
                IrData::Binary {
                    op: BinOpKind::PipeLeft,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        symbols,
    );
    let reverse = eval_whnf_owned(&reverse).expect("reverse pipe evaluates");
    assert_eq!(
        reverse
            .heap()
            .get_string(reverse.value())
            .expect("reverse pipe returns a string")
            .bytes(),
        b"7",
    );
}

#[test]
fn pipe_operators_pass_piped_operand_lazily() {
    let mut symbols = SymbolTable::new();
    let x = symbols.intern(b"x").expect("symbol interns");
    let frames = vec![FrameInfo {
        slot_count: 1,
        captures: Vec::new().into_boxed_slice(),
        rec: false,
        has_with: false,
    }];

    fn ignored_division_pipe(
        op: BinOpKind,
        x: Symbol,
        symbols: SymbolTable,
        frames: Vec<FrameInfo>,
    ) -> Ir {
        let (lhs, rhs) = match op {
            BinOpKind::PipeRight => (IrId::new(6), IrId::new(2)),
            BinOpKind::PipeLeft => (IrId::new(2), IrId::new(6)),
            _ => unreachable!("test helper only builds pipe operators"),
        };
        manual_ir_with_symbols_and_frames(
            IrId::new(7),
            vec![
                pure_node(
                    IrKind::Formal,
                    Span::new(0, 1),
                    IrData::Formal {
                        name: x,
                        default: None,
                    },
                ),
                pure_node(IrKind::Int, Span::new(3, 4), IrData::Int(5)),
                pure_node(
                    IrKind::Lambda,
                    Span::new(0, 4),
                    IrData::Lambda {
                        pattern: IrId::new(0),
                        body: IrId::new(1),
                        frame: Some(FrameId::new(0)),
                    },
                ),
                pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(1)),
                pure_node(IrKind::Int, Span::new(12, 13), IrData::Int(0)),
                pure_node(
                    IrKind::BinOp,
                    Span::new(8, 13),
                    IrData::Binary {
                        op: BinOpKind::Div,
                        lhs: IrId::new(3),
                        rhs: IrId::new(4),
                    },
                ),
                pure_node(
                    IrKind::ThunkAlloc,
                    Span::new(8, 13),
                    IrData::Node(IrId::new(5)),
                ),
                pure_node(
                    IrKind::BinOp,
                    Span::new(0, 18),
                    IrData::Binary { op, lhs, rhs },
                ),
            ],
            symbols,
            frames,
        )
    }

    for (op, label) in [
        (BinOpKind::PipeRight, "forward pipe"),
        (BinOpKind::PipeLeft, "reverse pipe"),
    ] {
        let ir = ignored_division_pipe(op, x, symbols.clone(), frames.clone());
        assert_eq!(
            eval_whnf(&ir)
                .unwrap_or_else(|_| panic!("{label} does not force ignored argument"))
                .as_int(),
            Ok(5),
            "{label}",
        );
    }
}

#[test]
fn pipe_operators_report_non_callable_function_side() {
    let function = IrId::new(0);
    let root = IrId::new(1);
    let function_span = Span::new(5, 6);
    let forward = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, function_span, IrData::Int(1)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 6),
                IrData::Binary {
                    op: BinOpKind::PipeRight,
                    lhs: IrId::new(99),
                    rhs: function,
                },
            ),
        ],
    );
    let error = eval_whnf(&forward).expect_err("forward pipe function must be callable");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "lambda",
            actual: ValueTag::Int,
        },
    );
    assert_eq!(error.span(), function_span);

    let function_span = Span::new(0, 1);
    let reverse = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, function_span, IrData::Int(1)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 6),
                IrData::Binary {
                    op: BinOpKind::PipeLeft,
                    lhs: function,
                    rhs: IrId::new(99),
                },
            ),
        ],
    );
    let error = eval_whnf(&reverse).expect_err("reverse pipe function must be callable");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "lambda",
            actual: ValueTag::Int,
        },
    );
    assert_eq!(error.span(), function_span);
}

#[test]
fn invalid_node_ids_are_reported() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::new(&ir);
    let missing = IrId::new(99);
    let error = evaluator
        .eval_node(missing)
        .expect_err("missing node is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidNodeId { id: missing }
    );
    assert_eq!(error.span(), Span::default());
}

#[test]
fn malformed_literal_payloads_are_reported() {
    let cases = [
        (IrKind::Int, IrData::None, "integer payload"),
        (IrKind::Float, IrData::None, "float payload"),
        (IrKind::Bool, IrData::None, "boolean payload"),
        (IrKind::Null, IrData::Bool(false), "empty payload"),
        (IrKind::Str, IrData::None, "string symbol payload"),
        (IrKind::List, IrData::None, "list children"),
        (IrKind::AttrSet, IrData::None, "attrset payload"),
    ];

    for (index, (kind, data, expected)) in cases.into_iter().enumerate() {
        let root = IrId::new(0);
        let span = Span::new(index as u32, index as u32 + 1);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(kind, span, EffectClass::Pure, data)],
            Vec::new(),
        );
        let ir = empty_ir(root, arena);
        let error = eval_whnf(&ir).expect_err("malformed literal is invalid");

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
fn malformed_variable_and_let_payloads_are_reported() {
    let cases = [
        (IrKind::LocalVar, "local payload"),
        (IrKind::UpvalVar, "upvalue payload"),
        (IrKind::Let, "let payload"),
        (IrKind::With, "with pair"),
        (IrKind::WithVar, "with-var payload"),
    ];

    for (index, (kind, expected)) in cases.into_iter().enumerate() {
        let root = IrId::new(0);
        let span = Span::new(10 + index as u32, 11 + index as u32);
        let ir = manual_ir(root, vec![pure_node(kind, span, IrData::None)]);
        let error = eval_whnf(&ir).expect_err("malformed variable or let is invalid");

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
fn malformed_function_payloads_are_reported() {
    let cases = [
        (IrKind::Lambda, "lambda payload"),
        (IrKind::Apply, "application pair"),
    ];

    for (index, (kind, expected)) in cases.into_iter().enumerate() {
        let root = IrId::new(0);
        let span = Span::new(20 + index as u32, 21 + index as u32);
        let ir = manual_ir(root, vec![pure_node(kind, span, IrData::None)]);
        let error = eval_whnf(&ir).expect_err("malformed function node is invalid");

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
fn invalid_with_chain_metadata_is_reported() {
    let mut symbols = SymbolTable::new();
    let missing = symbols.intern(b"missing").expect("symbol interns");
    let root = IrId::new(0);
    let span = Span::new(0, 7);
    let invalid_chain = manual_ir_with_with_chains(
        root,
        vec![pure_node(
            IrKind::WithVar,
            span,
            IrData::WithVar {
                symbol: missing,
                chain: 0,
            },
        )],
        symbols.clone(),
        Vec::new(),
    );
    let error = eval_whnf(&invalid_chain).expect_err("missing with chain is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidWithChain { id: root, chain: 0 }
    );
    assert_eq!(error.span(), span);

    let scope = IrId::new(1);
    let missing_scope = manual_ir_with_with_chains(
        root,
        vec![
            pure_node(
                IrKind::WithVar,
                span,
                IrData::WithVar {
                    symbol: missing,
                    chain: 0,
                },
            ),
            pure_node(IrKind::AttrSet, Span::new(10, 12), IrData::None),
        ],
        symbols,
        vec![IrWithChain::new(vec![scope].into_boxed_slice())],
    );
    let error = eval_whnf(&missing_scope).expect_err("inactive with scope is invalid");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingWithScope { id: root, scope }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_environment_accesses_are_reported() {
    let root = IrId::new(0);
    let span = Span::new(0, 1);
    let local_ir = manual_ir(
        root,
        vec![pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 })],
    );
    let local_error = eval_whnf(&local_ir).expect_err("local needs an environment");

    assert_eq!(
        local_error.kind(),
        TreeWalkErrorKind::MissingEnvironment { id: root }
    );
    assert_eq!(local_error.span(), span);

    let upval_ir = manual_ir(
        root,
        vec![pure_node(
            IrKind::UpvalVar,
            span,
            IrData::Upval { depth: 0, slot: 0 },
        )],
    );
    let upval_error = eval_whnf(&upval_ir).expect_err("upvalue needs an environment");

    assert_eq!(
        upval_error.kind(),
        TreeWalkErrorKind::InvalidUpvalueDepth {
            id: root,
            depth: 0,
            frames: 0,
        }
    );
    assert_eq!(upval_error.span(), span);
}

#[test]
fn invalid_let_frame_metadata_is_reported() {
    let root = IrId::new(0);
    let body = IrId::new(1);
    let span = Span::new(0, 10);
    let missing_frame = manual_ir(
        root,
        vec![
            pure_node(
                IrKind::Let,
                span,
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 0),
                    body,
                    frame: None,
                },
            ),
            pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
        ],
    );
    let missing_error = eval_whnf(&missing_frame).expect_err("let frame metadata must exist");

    assert_eq!(
        missing_error.kind(),
        TreeWalkErrorKind::MissingFrameMetadata { id: root }
    );
    assert_eq!(missing_error.span(), span);

    let frame = FrameId::new(0);
    let invalid_frame = manual_ir(
        root,
        vec![
            pure_node(
                IrKind::Let,
                span,
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 0),
                    body,
                    frame: Some(frame),
                },
            ),
            pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
        ],
    );
    let invalid_error = eval_whnf(&invalid_frame).expect_err("frame id must resolve");

    assert_eq!(
        invalid_error.kind(),
        TreeWalkErrorKind::InvalidFrameId {
            id: root,
            frame: frame.as_u32(),
        }
    );
    assert_eq!(invalid_error.span(), span);
}

#[test]
fn invalid_string_symbols_are_reported() {
    let root = IrId::new(0);
    let symbol = Symbol::new(99);
    let span = Span::new(3, 8);
    let ir = manual_ir(
        root,
        vec![pure_node(IrKind::Str, span, IrData::Symbol(symbol))],
    );
    let error = eval_whnf_owned(&ir).expect_err("string symbol must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_list_child_slices_are_reported() {
    let root = IrId::new(0);
    let slice = IrChildSlice::new(7, 1);
    let span = Span::new(0, 2);
    let ir = manual_ir(
        root,
        vec![pure_node(IrKind::List, span, IrData::Children(slice))],
    );
    let error = eval_whnf_owned(&ir).expect_err("list child slice must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidChildSlice { id: root, slice }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_has_attr_paths_are_reported() {
    let receiver = IrId::new(0);
    let root = IrId::new(1);
    let path = IrAttrPathId::new(2);
    let span = Span::new(0, 5);
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("symbol interns");
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(
                IrKind::HasAttr,
                span,
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(a)]), Box::new([])],
    );
    let error = eval_whnf_owned(&ir).expect_err("attr-path id must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidAttrPath { id: root, path }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_select_paths_are_reported() {
    let receiver = IrId::new(0);
    let root = IrId::new(1);
    let path = IrAttrPathId::new(2);
    let span = Span::new(0, 5);
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("symbol interns");
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(
                IrKind::Select,
                span,
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                    default: None,
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(a)]), Box::new([])],
    );
    let error = eval_whnf_owned(&ir).expect_err("attr-path id must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidAttrPath { id: root, path }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn empty_has_attr_paths_are_invalid_ir() {
    let receiver = IrId::new(2);
    let root = IrId::new(3);
    let path = IrAttrPathId::new(0);
    let span = Span::new(0, 5);
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(IrKind::Int, Span::new(4, 5), IrData::Int(0)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 5),
                IrData::Binary {
                    op: BinOpKind::Div,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
            pure_node(
                IrKind::HasAttr,
                span,
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                },
            ),
        ],
        SymbolTable::new(),
        vec![Box::new([])],
    );
    let error = eval_whnf_owned(&ir).expect_err("empty attr paths are malformed IR");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidAttrPath { id: root, path }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn empty_select_paths_are_invalid_ir() {
    let receiver = IrId::new(2);
    let root = IrId::new(3);
    let path = IrAttrPathId::new(0);
    let span = Span::new(0, 5);
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(IrKind::Int, Span::new(4, 5), IrData::Int(0)),
            pure_node(
                IrKind::BinOp,
                Span::new(0, 5),
                IrData::Binary {
                    op: BinOpKind::Div,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
            pure_node(
                IrKind::Select,
                span,
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                    default: None,
                },
            ),
        ],
        SymbolTable::new(),
        vec![Box::new([])],
    );
    let error = eval_whnf_owned(&ir).expect_err("empty attr paths are malformed IR");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidAttrPath { id: root, path }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_has_attr_static_symbols_are_reported() {
    let receiver = IrId::new(0);
    let root = IrId::new(1);
    let path = IrAttrPathId::new(0);
    let span = Span::new(0, 5);
    let symbol = Symbol::new(99);
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(
                IrKind::HasAttr,
                span,
                IrData::HasAttr {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                },
            ),
        ],
        SymbolTable::new(),
        vec![Box::new([IrAttrPathSegment::Static(symbol)])],
    );
    let error = eval_whnf_owned(&ir).expect_err("static path symbol must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_select_static_symbols_are_reported() {
    let receiver = IrId::new(0);
    let root = IrId::new(1);
    let path = IrAttrPathId::new(0);
    let span = Span::new(0, 5);
    let symbol = Symbol::new(99);
    let ir = manual_ir_with_attr_paths(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
            pure_node(
                IrKind::Select,
                span,
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver,
                    path,
                    default: None,
                },
            ),
        ],
        SymbolTable::new(),
        vec![Box::new([IrAttrPathSegment::Static(symbol)])],
    );
    let error = eval_whnf_owned(&ir).expect_err("static path symbol must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_attrset_binding_slices_are_reported() {
    let root = IrId::new(0);
    let slice = IrBindingSlice::new(7, 1);
    let span = Span::new(0, 2);
    let ir = manual_ir(
        root,
        vec![pure_node(
            IrKind::AttrSet,
            span,
            IrData::AttrSet {
                shape: IrShapeId::new(0),
                bindings: slice,
                recursive: false,
                has_dynamic: false,
                frame: None,
            },
        )],
    );
    let error = eval_whnf_owned(&ir).expect_err("attrset binding slice must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidBindingSlice { id: root, slice }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_attrset_shape_ids_are_reported() {
    let root = IrId::new(0);
    let shape = IrShapeId::new(0);
    let span = Span::new(0, 2);
    let ir = manual_ir(
        root,
        vec![pure_node(
            IrKind::AttrSet,
            span,
            IrData::AttrSet {
                shape,
                bindings: IrBindingSlice::new(0, 0),
                recursive: false,
                has_dynamic: false,
                frame: None,
            },
        )],
    );
    let error = eval_whnf_owned(&ir).expect_err("attrset shape must exist");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidShapeId { id: root, shape }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn invalid_recursive_attrset_frame_metadata_is_reported() {
    fn recursive_attrset_ir(frame: Option<FrameId>, frames: Vec<FrameInfo>) -> Ir {
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let value = IrId::new(0);
        let root = IrId::new(1);
        let mut ir = manual_ir_with_attr_tables(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(1)),
                pure_node(
                    IrKind::AttrSet,
                    Span::new(0, 10),
                    IrData::AttrSet {
                        shape: IrShapeId::new(0),
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: true,
                        has_dynamic: false,
                        frame,
                    },
                ),
            ],
            symbols,
            vec![IrBinding {
                key: IrAttrPathSegment::Static(a),
                position: None,
                value,
            }],
            vec![IrShape::new(vec![a].into_boxed_slice())],
        );
        ir.frames = frames.into_boxed_slice();
        ir
    }

    let missing_frame = recursive_attrset_ir(None, Vec::new());
    let missing_error =
        eval_whnf_owned(&missing_frame).expect_err("recursive attrset frame must exist");

    assert_eq!(
        missing_error.kind(),
        TreeWalkErrorKind::MissingFrameMetadata { id: IrId::new(1) }
    );
    assert_eq!(missing_error.span(), Span::new(0, 10));

    let frame = FrameId::new(0);
    let invalid_frame = recursive_attrset_ir(Some(frame), Vec::new());
    let invalid_error = eval_whnf_owned(&invalid_frame).expect_err("frame id must resolve");

    assert_eq!(
        invalid_error.kind(),
        TreeWalkErrorKind::InvalidFrameId {
            id: IrId::new(1),
            frame: frame.as_u32(),
        }
    );
    assert_eq!(invalid_error.span(), Span::new(0, 10));

    let mismatch = recursive_attrset_ir(
        Some(frame),
        vec![FrameInfo {
            slot_count: 2,
            captures: Vec::new().into_boxed_slice(),
            rec: true,
            has_with: false,
        }],
    );
    let mismatch_error = eval_whnf_owned(&mismatch).expect_err("frame slots must match bindings");

    assert_eq!(
        mismatch_error.kind(),
        TreeWalkErrorKind::AttrSetFrameSlotMismatch {
            id: IrId::new(1),
            frame_slots: 2,
            bindings: 1,
        }
    );
    assert_eq!(mismatch_error.span(), Span::new(0, 10));
}

#[test]
fn attrset_shape_length_mismatches_are_reported() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("symbol interns");
    let value = IrId::new(0);
    let root = IrId::new(1);
    let shape = IrShapeId::new(0);
    let span = Span::new(0, 8);
    let ir = manual_ir_with_attr_tables(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(6, 7), IrData::Int(1)),
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
            key: IrAttrPathSegment::Static(a),
            position: None,
            value,
        }],
        vec![IrShape::new(Vec::new().into_boxed_slice())],
    );
    let error = eval_whnf_owned(&ir).expect_err("attrset shape length must match bindings");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::AttrSetShapeLengthMismatch {
            id: root,
            shape,
            shape_keys: 0,
            binding_keys: 1,
        }
    );
    assert_eq!(error.span(), span);
}

#[test]
fn attrset_shape_key_mismatches_are_reported() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a symbol interns");
    let b = symbols.intern(b"b").expect("b symbol interns");
    let value = IrId::new(0);
    let root = IrId::new(1);
    let shape = IrShapeId::new(0);
    let span = Span::new(0, 8);
    let ir = manual_ir_with_attr_tables(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(6, 7), IrData::Int(1)),
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
            key: IrAttrPathSegment::Static(a),
            position: None,
            value,
        }],
        vec![IrShape::new(vec![b].into_boxed_slice())],
    );
    let error = eval_whnf_owned(&ir).expect_err("attrset shape keys must match bindings");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::AttrSetShapeKeyMismatch {
            id: root,
            shape,
            index: 0,
            expected: b,
            actual: a,
        }
    );
    assert_eq!(error.span(), span);
}

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
        TreeWalkErrorKind::InvalidNodeId { id: missing }
    );
    assert_eq!(error.span(), Span::default());
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
            EffectClass::Pure,
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
            vec![IrNode::new(kind, span, EffectClass::Pure, IrData::None)],
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
            vec![IrNode::new(kind, span, EffectClass::Pure, IrData::None)],
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
            EffectClass::Pure,
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
