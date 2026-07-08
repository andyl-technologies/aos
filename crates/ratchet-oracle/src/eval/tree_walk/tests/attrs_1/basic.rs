//! Basic attribute, list, and inheritance evaluator tests.

use super::*;
use crate::attrs::repr::AttrSetReprKind;

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
fn attr_update_preserves_old_tree_walk_source_order_metadata_for_overwrites() {
    let ir = lower("{ a = 1; b = 2; } // { a = 3; c = 4; }");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator.eval_root().expect("attr update evaluates");

    assert_source_order_attrset_ints(&evaluator, value, &[(b"b", 2), (b"a", 3), (b"c", 4)]);
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
    let metadata = heap
        .get_attrs_metadata(outcome.value())
        .expect("attr metadata exists");
    let attrs = heap
        .get_attrs(outcome.value())
        .expect("attrset is heap-owned");

    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
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
fn recursive_attrset_overrides_replace_self_scope_and_final_attrs() {
    assert_eq!(
        eval(
            "let overrides = { a = 2; b = 3; };
             in (rec {
               __overrides = overrides;
               x = a;
               a = 1;
             }).x"
        )
        .as_int(),
        Ok(2)
    );
    assert_eq!(
        eval_json_bytes(
            r#"rec {
                 "${"foo"}" = "bar";
                 __overrides = { bar = "qux"; };
               }"#
        ),
        br#"{"__overrides":{"bar":"qux"},"bar":"qux","foo":"bar"}"#.to_vec()
    );
    assert_eq!(
        eval_string_bytes(
            r#"(rec {
                 foo = "bar";
                 __overrides = builtins.foldl' (acc: _x: acc) { bar = "qux"; } [];
               }).bar"#
        ),
        b"qux"
    );
}

#[test]
fn recursive_attrset_overrides_must_be_attrs() {
    let error = eval_whnf_owned(&lower("rec { __overrides = 1; }"))
        .expect_err("__overrides must evaluate to an attrset");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));
    assert!(error.to_string().contains("__overrides"), "{error:?}");
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
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
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
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("forced thunk reuses cache");
    assert_eq!(forced_again.as_int(), Ok(3));
}

/// Evaluates `source` to a string with per-merge attr telemetry disabled,
/// driving the production `//` fast path instead of the telemetry path.
fn eval_string_bytes_without_attr_update_telemetry(source: &str) -> Vec<u8> {
    let ir = lower(source);
    let mut evaluator = TreeWalk::new(&ir);
    evaluator.set_attr_update_telemetry_enabled(false);
    let value = evaluator.eval_root().expect("source evaluates");
    let string = evaluator
        .heap
        .get_string(value)
        .expect("result is a heap-owned string");
    string.bytes().to_vec()
}

#[test]
fn attr_update_fast_path_matches_telemetry_path_bytes() {
    // Attr-heavy sweep: dynamic keys, rec, nested merges, overridden
    // positions, and a fold chain deep and wide enough that the telemetry
    // path projects a HAMT representation while the fast path stays flat.
    for source in [
        // Iteration order and right bias through toJSON (lexicographic).
        r#"builtins.toJSON ({ b = 1; ${"a"} = 2; z = 0; } // { c = 3; a = 4; })"#,
        // attrNames of a nested merge with interleaved dynamic keys.
        r#"builtins.concatStringsSep "," (builtins.attrNames
             (({ x = 1; ${"0z"} = 2; } // rec { a = 3; b = a + 1; }) // { ${"x"} = 9; }))"#,
        // Overridden keys take the right operand's position.
        r#"builtins.toJSON (builtins.unsafeGetAttrPos "a"
             ({ a = 1; } //
              { a = 2; }))"#,
        // Deep override chain over a wide accumulator: crosses both the
        // flat-attr threshold (64) and the override-chain threshold (4).
        r#"builtins.toJSON (builtins.foldl'
             (acc: i: acc // { "k${builtins.toString i}" = i * i; })
             {}
             (builtins.genList (i: i) 100))"#,
        // Merge results feed selects and nested merges.
        r#"let base = { a = { x = 1; }; b = 2; };
               merged = base // { a = base.a // { y = 2; }; c = 3; };
           in builtins.toJSON [ merged merged.a.y (builtins.attrNames merged) ]"#,
    ] {
        assert_eq!(
            eval_string_bytes_without_attr_update_telemetry(source),
            eval_string_bytes(source),
            "fast-path bytes diverge for {source}",
        );
    }
}
