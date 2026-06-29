//! Tree-walk test support: C++ Nix language-semantics oracle helpers (part 1).

use super::super::*;
use super::*;

pub(crate) fn assert_cpp_nix_trace_and_warn_stderr_match_tree_walk(oracle: &str) {
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
        let warning_reference = cpp_nix_eval_stderr(oracle, source);
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
        assert_eq!(
            stderr, warning_reference,
            "abort-on-warn warning stderr diverged for {source}"
        );
        assert!(
            reference.starts_with(&warning_reference),
            "abort-on-warn warning stderr prefix diverged for {source}: reference={:?}, warning={:?}",
            String::from_utf8_lossy(&reference),
            String::from_utf8_lossy(&warning_reference)
        );
        assert!(
            String::from_utf8_lossy(&reference)
                .contains("aborting to reveal stack trace of warning"),
            "C++ Nix abort-on-warn stderr did not include abort diagnostic for {source}: {}",
            String::from_utf8_lossy(&reference)
        );
    }
}

pub(crate) fn assert_cpp_nix_control_builtins_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_attrset_builtin_semantics_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_equality_semantics_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_comparison_semantics_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_function_semantics_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk(oracle: &str) {
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
