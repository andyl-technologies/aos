//! Tree-walk evaluator tests: toml.

use super::*;

// Baseline float/scalar ABI test; variant float path via scalars.rs + parity
// battery (cutover plan section 7).
#[cfg(not(feature = "candidate_c_value"))]
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
fn from_toml_primop_accepts_timestamps_when_experimental_feature_is_enabled() {
    let options = TreeWalkOptions::with_parse_toml_timestamps(true);

    assert!(options.parse_toml_timestamps());
    assert_eq!(
        eval_json_bytes_with_options(
            r#"builtins.fromTOML ''
                    date = 1979-05-27
                    local = 1979-05-27T07:32:00
                    offset = 1979-05-27T00:32:00-07:00
                    offset_fraction = 1979-05-27T00:32:00.999999-07:00
                    previous_day = 1979-05-27T00:32:00+02:00
                    space = 1979-05-27 07:32:00Z
                    time = 07:32:00
                ''"#,
            options,
        ),
        br#"{"date":{"_type":"timestamp","value":"1979-05-27"},"local":{"_type":"timestamp","value":"1979-05-27T07:32:00"},"offset":{"_type":"timestamp","value":"1979-05-27T00:32:00-07:00"},"offset_fraction":{"_type":"timestamp","value":"1979-05-27T00:32:00.999999-07:00"},"previous_day":{"_type":"timestamp","value":"1979-05-27T00:32:00+02:00"},"space":{"_type":"timestamp","value":"1979-05-27T07:32:00Z"},"time":{"_type":"timestamp","value":"07:32:00"}}"#
    );
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
