//! Tree-walk evaluator tests: context 1.

use super::*;

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

// Baseline float/scalar ABI test; variant float path via scalars.rs + parity
// battery (cutover plan section 7).
#[cfg(not(feature = "candidate_c_value"))]
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

fn source_line_column(source: &str, needle: &str) -> (usize, usize) {
    let offset = source.find(needle).expect("needle exists in source");
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = prefix
        .bytes()
        .rposition(|byte| byte == b'\n')
        .map_or(0, |index| index + 1);
    (line, offset - line_start + 1)
}

#[test]
fn cur_pos_reports_source_position() {
    let source = "# Bla\nlet\n  x = __curPos;\n    y = __curPos;\nin builtins.toJSON [ x.line x.column y.line y.column ]";

    assert_eq!(
        eval_string_bytes_with_source(b"/source.nix", source),
        b"[3,7,4,9]"
    );
}

#[test]
fn cur_pos_ignores_lexical_shadowing() {
    let source = "let __curPos = { line = 99; column = 100; }; in builtins.toJSON [ __curPos.line __curPos.column ]";
    let (line, column) = source_line_column(source, "__curPos.column");
    let expected = format!("[{},{}]", line, column);

    assert_eq!(
        eval_string_bytes_with_source(b"/source.nix", source),
        expected.as_bytes()
    );
}

#[test]
fn cur_pos_ignores_with_shadowing() {
    let source = "with { __curPos = { line = 99; column = 100; }; }; builtins.toJSON [ __curPos.line __curPos.column ]";
    let (line, column) = source_line_column(source, "__curPos.column");
    let expected = format!("[{},{}]", line, column);

    assert_eq!(
        eval_string_bytes_with_source(b"/source.nix", source),
        expected.as_bytes()
    );
}

#[test]
fn unsafe_get_attr_pos_reports_function_args_positions() {
    let source = r#"builtins.toJSON (
  let
    fun = { foo }: {};
    pos = builtins.unsafeGetAttrPos "foo" (builtins.functionArgs fun);
  in [ pos.file pos.line pos.column ]
)"#;
    let (line, column) = source_line_column(source, "foo");
    let expected = format!(r#"["/source.nix",{},{}]"#, line, column);

    assert_eq!(
        eval_string_bytes_with_source(b"/source.nix", source),
        expected.as_bytes()
    );
}

#[test]
fn unsafe_get_attr_pos_reports_static_binding_positions() {
    let source = r#"builtins.toJSON (
  let p = builtins.unsafeGetAttrPos "a" { a = 1; };
  in [ p.file p.line p.column ]
)"#;
    let (line, column) = source_line_column(source, "a = 1");
    let expected = format!(r#"["/source.nix",{},{}]"#, line, column);

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
    let (_, column) = source_line_column(source, r#"${"a"}"#);
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
    let (_, a_column) = source_line_column(source, "a = 1");
    let (_, b_column) = source_line_column(source, "b = 2");
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
    let (_, name_column) = source_line_column(source, "name =");
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
    let (_, column) = source_line_column(source, "a = 1");
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
        r#"["{}",2,3]"#,
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
