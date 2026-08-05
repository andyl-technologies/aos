//! Tree-walk test support: C++ Nix language-semantics oracle helpers (part 2).

use super::super::*;
use super::*;

pub(crate) fn assert_cpp_nix_numeric_and_ordering_builtins_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_language_operators_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_sort_and_less_than_builtins_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_laziness_and_evaluation_semantics_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_let_with_scoping_semantics_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_control_flow_and_error_semantics_match_tree_walk(oracle: &str) {
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

pub(crate) fn assert_cpp_nix_import_semantics_match_tree_walk(oracle: &str) {
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
