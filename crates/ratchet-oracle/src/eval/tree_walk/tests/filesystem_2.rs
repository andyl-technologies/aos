//! Tree-walk evaluator tests: filesystem 2.

use super::*;

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
fn get_env_primop_records_impure_input_trace() {
    let outcome = eval_whnf_owned_with_options(
        &lower("builtins.getEnv \"HOME\""),
        TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec()),
    )
    .expect("source evaluates");
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is a string");
    let expected = vec![
        ImpureInputFingerprint::get_env(b"HOME", Some(b"/home/aos")).expect("fingerprint builds"),
    ];

    assert_eq!(string.bytes(), b"/home/aos");
    assert_eq!(outcome.impure_input_trace(), expected.as_slice());

    let pure_outcome = eval_whnf_owned_with_options(&lower("builtins.getEnv \"HOME\""), {
        let mut options = TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec());
        options.set_eval_mode(EvalMode::Pure);
        options
    })
    .expect("source evaluates");
    assert!(pure_outcome.impure_input_trace().is_empty());
    assert!(pure_outcome.impure_input_trace_complete());
}

#[test]
fn current_time_records_uncacheable_impure_input_trace() {
    let outcome = eval_whnf_owned_with_options(
        &lower("builtins.currentTime"),
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime configures"),
    )
    .expect("source evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1_700_000_000));
    assert_eq!(
        outcome.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );

    let mut cache = EvalCache::new();
    let observation = cache
        .observe_impure_inputs(&outcome)
        .expect("outcome trace observes");
    assert_eq!(
        observation.status(),
        ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
    );
    assert!(observation.leaves().is_empty());
    assert!(cache.is_empty());
}

#[test]
fn filesystem_import_records_impure_input_trace() {
    let dir = unique_temp_dir("import-trace");
    let path = dir.join("imported.nix");
    let source = b"{ value = 7; }";
    fs::write(&path, source).expect("import source writes");
    let canonical_path = path_source(&fs::canonicalize(&path).expect("path canonicalizes"));
    let path = path_source(&path);
    let outcome = eval_whnf_owned(&lower(&format!(
        "(import {}).value",
        nix_string_literal(&path)
    )))
    .expect("source evaluates");
    let expected = vec![
        ImpureInputFingerprint::import(canonical_path.as_bytes(), source)
            .expect("fingerprint builds"),
    ];

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert_eq!(outcome.impure_input_trace(), expected.as_slice());

    fs::remove_dir_all(dir).expect("temp directory removes");
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
fn read_file_primop_records_impure_input_trace() {
    let (dir, path) = temp_file_with_bytes("read-file-trace", b"trace-data");
    let path = path_source(&path);
    let outcome = eval_whnf_owned(&lower(&format!(
        "builtins.readFile {}",
        nix_string_literal(&path)
    )))
    .expect("source evaluates");
    let expected = vec![
        ImpureInputFingerprint::read_file(path.as_bytes(), b"trace-data")
            .expect("fingerprint builds"),
    ];

    assert_eq!(outcome.impure_input_trace(), expected.as_slice());

    let mut cache = EvalCache::new();
    let observation = cache
        .observe_impure_inputs(&outcome)
        .expect("outcome trace observes");
    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    assert_eq!(observation.leaves().len(), 1);
    assert_eq!(cache.len(), 1);

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn hash_file_primop_records_impure_input_trace() {
    let (dir, path) = temp_file_with_bytes("hash-file-trace", b"trace-data");
    let path = path_source(&path);
    let outcome = eval_whnf_owned(&lower(&format!(
        "builtins.hashFile \"sha256\" {}",
        nix_string_literal(&path)
    )))
    .expect("source evaluates");
    let hash = outcome
        .heap()
        .get_string(outcome.value())
        .expect("hashFile result is a string");
    let expected = vec![
        ImpureInputFingerprint::hash_file(path.as_bytes(), b"trace-data")
            .expect("fingerprint builds"),
    ];

    assert_eq!(
        hash.bytes(),
        b"6baf94804418a468e20bcb66b608e524d8a890da9b128f47aadaedeaeeec22f4"
    );
    assert_eq!(outcome.impure_input_trace(), expected.as_slice());

    let mut cache = EvalCache::new();
    let observation = cache
        .observe_impure_inputs(&outcome)
        .expect("outcome trace observes");
    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    assert_eq!(observation.leaves().len(), 1);
    assert_eq!(cache.len(), 1);

    let first_class_outcome = eval_whnf_owned(&lower(&format!(
        "let hash = builtins.hashFile \"sha256\"; in hash {}",
        nix_string_literal(&path)
    )))
    .expect("first-class hashFile evaluates");
    assert_eq!(
        first_class_outcome.impure_input_trace(),
        expected.as_slice()
    );

    let text_store_outcome = eval_whnf_owned(&lower(
        r#"builtins.hashFile "sha256" (builtins.toFile "x" "trace-data")"#,
    ))
    .expect("text-store hashFile evaluates");
    assert!(text_store_outcome.impure_input_trace().is_empty());
    assert!(text_store_outcome.impure_input_trace_complete());

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
    assert_eq!(eval_string_bytes(r"''''\${PORT}''"), b"${PORT}");
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
