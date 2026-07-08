//! Tree-walk evaluator tests: coercion.

use super::*;

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
fn to_json_primop_rejects_non_utf8_strings() {
    let ir = lower_bytes(b"builtins.toJSON \"_invalid UTF-8: \xff_\"");
    let error = eval_whnf_owned(&ir).expect_err("toJSON rejects non-UTF-8 strings");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::JsonInvalidUtf8 {
            bytes,
            ..
        } if bytes == b"_invalid UTF-8: \xff_"
    ));
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
    // Grisu2 parity (eval-okay-fromTOML): nlohmann's printer is not always
    // shortest — 5e22 renders through its rounded digit generation.
    assert_eq!(
        eval_string_bytes("builtins.toJSON 5.0e22"),
        b"4.9999999999999996e+22"
    );
    // Fixed-point notation stops at digits10 (15) integral digits.
    assert_eq!(eval_string_bytes("builtins.toJSON 2.5e15"), b"2.5e+15");
    assert_eq!(eval_string_bytes("builtins.toJSON 100.0"), b"100.0");
    // Exponents always carry a sign and at least two digits.
    assert_eq!(eval_string_bytes("builtins.toJSON 1.0e-7"), b"1e-07");
    assert_eq!(eval_string_bytes("builtins.toJSON 0.0001"), b"0.0001");
    // A true IEEE negative zero keeps its sign (nlohmann uses signbit);
    // `-0.0` in Nix parses as `0 - 0.0`, which is positive zero.
    assert_eq!(
        eval_string_bytes("builtins.toJSON ((0.0 - 1.0) * 0.0)"),
        b"-0.0"
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
