//! Tree-walk evaluator tests: strings 1.

use super::*;

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
        .eval_unsafe_discard_string_context_primop(
            ir.root,
            root.span,
            argument,
            argument_span,
            value,
        )
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
fn match_primop_rejects_pattern_context_but_discards_subject_context() {
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

    assert_eq!(
        eval_json_bytes(
            r#"let
              subject = builtins.appendContext "a" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
              };
              captures = builtins.match "(a)" subject;
            in {
              inherit captures;
              context = builtins.getContext (builtins.head captures);
            }"#,
        ),
        br#"{"captures":["a"],"context":{}}"#.to_vec()
    );
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
fn split_primop_rejects_pattern_context_but_discards_subject_context() {
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

    assert_eq!(
        eval_json_bytes(&format!(
            r#"let
              parts = builtins.split "(-)"
                (builtins.appendContext "a-b" {{ "{path}" = {{ path = true; }}; }});
            in {{
              inherit parts;
              firstContext = builtins.getContext (builtins.elemAt parts 0);
              captureContext =
                builtins.getContext (builtins.head (builtins.elemAt parts 1));
              lastContext = builtins.getContext (builtins.elemAt parts 2);
            }}"#
        )),
        br#"{"captureContext":{},"firstContext":{},"lastContext":{},"parts":["a",["-"],"b"]}"#
            .to_vec()
    );
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
