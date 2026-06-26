//! Tree-walk evaluator tests: attrs 1.

use crate::cache::{
    PERSIST_NODE_METADATA_INDEX_ENTRY_LEN, PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN,
    PersistNodeTraceLogEntry,
};

use super::*;

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

fn force_attr_a(evaluator: &mut TreeWalk, ir: &Ir, a: Symbol) -> Value {
    force_attr(evaluator, ir, a, "a")
}

fn force_attr_a_string(evaluator: &mut TreeWalk, ir: &Ir, a: Symbol, expected: &[u8]) {
    let value = force_attr_a(evaluator, ir, a);
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("forced value is a string");
    assert_eq!(string.bytes(), expected);
}

fn force_attr_a_attrs_strings(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    a: Symbol,
    expected: &[(&[u8], &[u8])],
) {
    let value = force_attr_a(evaluator, ir, a);
    let symbols = expected
        .iter()
        .map(|(name, _)| evaluator.symbols.intern(name).expect("symbol interns"))
        .collect::<Vec<_>>();
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("forced value is an attrset");
    assert_eq!(attrs.len(), expected.len());
    for ((name, expected_value), symbol) in expected.iter().zip(symbols) {
        let value = attrs
            .get(symbol)
            .unwrap_or_else(|| panic!("{} exists", String::from_utf8_lossy(name)));
        let string = evaluator
            .heap()
            .get_string(value)
            .expect("attr value is a string");
        assert_eq!(string.bytes(), *expected_value);
    }
}

trait ForceAdmittedValue {
    fn force_admitted_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError>;
}

impl ForceAdmittedValue for TreeWalk {
    fn force_admitted_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let subject = {
            let thunk = self.heap().get_thunk(value).ok();
            thunk.and_then(|thunk| {
                self.force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, id), thunk)
            })
        };
        if let Some(subject) = subject {
            self.record_force_cache_memoization_demand(&subject);
            self.record_force_cache_memoization_demand(&subject);
        }
        TreeWalk::force_value(self, id, span, value)
    }
}

fn force_attr(evaluator: &mut TreeWalk, ir: &Ir, attr: Symbol, label: &str) -> Value {
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(attr).unwrap_or_else(|| panic!("{label} exists"))
    };
    evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds")
}

fn seed_prior_persistent_demand_for_attr(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    attr: Symbol,
    persist_root: &std::path::Path,
    label: &str,
) -> Value {
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(attr).unwrap_or_else(|| panic!("{label} exists"))
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .unwrap_or_else(|_| panic!("{label} remains a suspended thunk"));
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .unwrap_or_else(|| panic!("{label} force-cache subject builds"))
    };
    let identity = subject
        .metadata_identity
        .unwrap_or_else(|| panic!("{label} has persistent metadata identity"));
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    PersistCache::open(persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    thunk_value
}

#[test]
fn source_backed_forced_inline_thunks_update_shared_eval_cache() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for _ in 0..2 {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "expr.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    assert_eq!(
        cache.len(),
        1,
        "the same source hash and IR node should reuse one demand node"
    );
    let node = cache
        .graph()
        .node(crate::cache::DemandNodeId::new(0))
        .expect("forced expression node exists");
    assert_eq!(node.freshness(), crate::cache::NodeFreshness::Clean);
    assert!(node.value_hash().is_some());
}

#[test]
fn source_backed_forced_inline_thunks_record_memoization_policy_demand() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for expected_demands in 1..=2 {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "expr.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("a remains a suspended thunk");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("force-cache subject builds")
        };
        let identity = subject
            .lookup_identity
            .expect("node thunk has a lookup identity");
        {
            let runtime = cache.lock().expect("cache lock is valid");
            if expected_demands == 1 {
                assert!(
                    runtime.cache().expect("cache is enabled").is_empty(),
                    "building a force-cache subject must not allocate graph nodes"
                );
                assert_eq!(
                    runtime
                        .memoization_demand(
                            identity,
                            subject.free_var_value_hashes.iter().copied(),
                        )
                        .expect("demand reads"),
                    None,
                    "building a force-cache subject must not record demand"
                );
            }
        }

        let forced = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(evaluator.stats().force_cache_memoization_demands(), 1);
        assert_eq!(
            evaluator.stats().force_cache_memoization_bypasses(),
            u64::from(expected_demands == 1),
            "first observed thunk demand should bypass the conditional policy"
        );
        assert_eq!(
            evaluator.stats().force_cache_memoization_admits(),
            u64::from(expected_demands == 2),
            "second observed thunk demand should admit through the conditional policy"
        );
        assert_eq!(
            evaluator.stats().force_cache_misses(),
            u64::from(expected_demands == 2),
            "only an admitted conditional thunk should probe and miss"
        );
        assert_eq!(
            evaluator.stats().force_cache_probes(),
            u64::from(expected_demands == 2),
            "bypassed conditional thunks should not probe the force cache"
        );

        let runtime = cache.lock().expect("cache lock is valid");
        let demand = runtime
            .memoization_demand(identity, subject.free_var_value_hashes.iter().copied())
            .expect("demand reads")
            .expect("force records memoization demand");
        assert_eq!(demand.current_run_demands(), expected_demands);
        assert_eq!(
            runtime.cache().expect("cache is enabled").len(),
            usize::from(expected_demands == 2),
            "only admitted policy demand should allocate an expression node"
        );
    }
}

#[test]
fn source_backed_force_cache_creates_expression_node_only_on_force() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        evaluator.stats().thunks_allocated(),
        1,
        "evaluating the attrset allocates the lazy attr thunk"
    );
    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert!(
            runtime.cache().expect("cache is enabled").is_empty(),
            "allocating the thunk must not allocate an expression cache node"
        );
    }

    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(evaluator.stats().force_cache_memoization_bypasses(), 1);
    assert_eq!(evaluator.stats().cache_misses(), 0);
    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert_eq!(
            runtime.cache().expect("cache is enabled").len(),
            0,
            "the first conditional thunk demand bypasses expression node allocation"
        );
    }

    let mut admitted = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = admitted.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = admitted
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = admitted
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("admitted thunk force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(admitted.stats().force_cache_memoization_admits(), 1);
    assert_eq!(admitted.stats().cache_misses(), 1);
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "an admitted force creates the expression cache node on demand"
    );
}

#[test]
fn source_backed_forced_inline_thunks_hit_shared_eval_cache_without_body_eval() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = first.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = first
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("first force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(first.stats().thunks_forced(), 1);
    assert_eq!(first.stats().force_cache_memoization_bypasses(), 1);
    assert_eq!(first.stats().force_cache_hits(), 0);
    assert_eq!(first.stats().force_cache_misses(), 0);
    assert_eq!(first.stats().force_cache_probes(), 0);
    assert_eq!(first.stats().cache_misses(), 0);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = second.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = second
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = second
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("second force succeeds and populates cache");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(second.stats().thunks_forced(), 1);
    assert_eq!(second.stats().force_cache_memoization_admits(), 1);
    assert_eq!(second.stats().cache_hits(), 0);
    assert_eq!(second.stats().force_cache_hits(), 0);
    assert_eq!(second.stats().force_cache_misses(), 1);
    assert_eq!(second.stats().force_cache_probes(), 1);

    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = third.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = third.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = third
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("third force succeeds from cache");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        third.stats().thunks_forced(),
        0,
        "cache hits publish the scalar without evaluating the thunk body"
    );
    assert_eq!(third.stats().cache_hits(), 1);
    assert_eq!(third.stats().force_cache_hits(), 1);
    assert_eq!(third.stats().force_cache_misses(), 0);
    assert_eq!(third.stats().force_cache_probes(), 1);

    let thunk = third
        .heap()
        .get_thunk(thunk_value)
        .expect("thunk remains heap-owned");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Forced));
    let forced_again = third
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("published cache hit reuses thunk cell");
    assert_eq!(forced_again.as_int(), Ok(3));
    assert_eq!(third.stats().thunk_cache_hits(), 1);
}

#[test]
fn source_and_source_less_forced_inline_thunks_use_separate_cache_domains() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut source_backed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut source_backed, &ir, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(source_backed.stats().cache_misses(), 1);

    let mut source_less =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let forced = force_attr_a(&mut source_less, &ir, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        source_less.stats().cache_hits(),
        0,
        "source-less lowered-IR identity must not hit a source-backed node"
    );
    assert_eq!(source_less.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "source-backed and source-less domains should allocate separate demand nodes"
    );
}

#[test]
fn source_less_forced_inline_thunks_hit_shared_eval_cache_without_body_eval() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let root = first.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("first force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(first.stats().thunks_forced(), 1);
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let root = second.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = second
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("second force succeeds from lowered-IR cache identity");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "source-less cache hits publish the scalar without evaluating the thunk body"
    );
    assert_eq!(second.stats().cache_hits(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "the same lowered IR fingerprint and node should reuse one demand node"
    );
}

#[test]
fn source_less_forced_inline_thunks_include_lowered_ir_in_cache_identity() {
    let first_ir = lower("{ a = 1 + 2; }");
    let second_ir = lower("{ a = 1 + 3; }");
    let first_a = symbol_for(&first_ir, b"a");
    let second_a = symbol_for(&second_ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&first_ir, TreeWalkOptions::new(), cache.clone());
    let root = first.eval_root().expect("first attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(first_a).expect("a exists")
    };
    let forced = first
        .force_admitted_value(first_ir.root, Span::new(0, 0), thunk_value)
        .expect("first force succeeds");
    assert_eq!(forced.as_int(), Ok(3));

    let mut second =
        TreeWalk::with_options_and_eval_cache(&second_ir, TreeWalkOptions::new(), cache.clone());
    let root = second.eval_root().expect("second attrset evaluates");
    let thunk_value = {
        let attrs = second
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(second_a).expect("a exists")
    };
    let forced = second
        .force_admitted_value(second_ir.root, Span::new(0, 0), thunk_value)
        .expect("second force succeeds");
    assert_eq!(forced.as_int(), Ok(4));
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "different lowered IR artifacts must not reuse one cache entry"
    );
    assert_eq!(second.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different lowered IR fingerprints should allocate separate demand nodes"
    );
}

#[test]
fn source_less_forced_inline_thunks_include_path_base_in_cache_identity() {
    let root = unique_temp_dir("source-less-force-cache-path-base");
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir_all(&first_dir).expect("first dir exists");
    fs::create_dir_all(&second_dir).expect("second dir exists");
    let first_dir = fs::canonicalize(&first_dir).expect("first dir canonicalizes");
    let second_dir = fs::canonicalize(&second_dir).expect("second dir canonicalizes");
    let source = "{ a = ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for path_base in [&first_dir, &second_dir] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(path_base))
            .expect("path base is absolute");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(
            path_value_bytes(&evaluator, forced),
            path_bytes(&path_base.join("target"))
        );
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different path bases must not reuse a path payload"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR under different path bases must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_forced_inline_thunks_include_store_dir_in_cache_identity() {
    let root = unique_temp_dir("source-less-force-cache-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for store_dir in [&first_store, &second_store] {
        let mut options = TreeWalkOptions::new();
        options
            .set_store_dir(path_bytes(store_dir))
            .expect("store dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less store dirs must not reuse one demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR under different store dirs must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_forced_inline_thunks_include_home_dir_in_cache_identity() {
    let root = unique_temp_dir("source-less-force-cache-home-dir");
    let first_home = root.join("home-a");
    let second_home = root.join("home-b");
    fs::create_dir_all(&first_home).expect("first home exists");
    fs::create_dir_all(&second_home).expect("second home exists");
    fs::write(first_home.join("marker"), b"present").expect("first marker exists");
    let first_home = fs::canonicalize(&first_home).expect("first home canonicalizes");
    let second_home = fs::canonicalize(&second_home).expect("second home canonicalizes");
    let source = "{ a = builtins.pathExists ~/marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (home_dir, expected) in [(&first_home, true), (&second_home, false)] {
        let mut options = TreeWalkOptions::new();
        options
            .set_home_dir(path_bytes(home_dir))
            .expect("home dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(forced.as_bool(), Ok(expected));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less home dirs must not reuse one demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        4,
        "different source-less home dirs should produce separate expression and input nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_forced_inline_thunks_include_eval_mode_in_cache_identity() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for mode in [EvalMode::Impure, EvalMode::Pure] {
        let options = TreeWalkOptions::with_eval_mode(mode);
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less eval modes must not reuse one demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same lowered IR under different eval modes must not reuse one demand node"
    );
}

fn force_cache_identity_for_attr_a(ir: &Ir, source: &str) -> (CacheExprIdentity, IrId) {
    let a = symbol_for(ir, b"a");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        ir,
        TreeWalkOptions::new(),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is a thunk");
    let body = thunk.body().expect("a is a node thunk");
    let identity = evaluator
        .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
        .expect("force-cache subject builds")
        .metadata_identity
        .expect("node thunk has metadata identity");
    (identity, body)
}

#[test]
fn source_backed_force_cache_identities_include_node_span() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let (first_identity, body) = force_cache_identity_for_attr_a(&ir, source);

    let mut shifted = ir.clone();
    let mut nodes = shifted.arena.nodes().to_vec();
    nodes[body.index()].span = Span::new(100, 104);
    shifted.arena = IrArena::from_raw_parts(nodes, shifted.arena.child_pool().to_vec());
    let (shifted_identity, shifted_body) = force_cache_identity_for_attr_a(&shifted, source);

    assert_eq!(shifted_body, body);
    assert_ne!(
        shifted_identity, first_identity,
        "same source bytes and IR node id under a different node span must not reuse one demand node"
    );

    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &shifted,
        TreeWalkOptions::new(),
        "default.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &shifted, a);
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "same source bytes and IR node id under a different node span must miss"
    );
    assert_eq!(second.stats().thunks_forced(), 1);

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes and IR node id under different spans must allocate separate demand nodes"
    );
}

#[test]
fn source_backed_forced_inline_thunks_include_path_base_in_cache_identity() {
    let root = unique_temp_dir("force-cache-path-base");
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir_all(&first_dir).expect("first dir exists");
    fs::create_dir_all(&second_dir).expect("second dir exists");
    let first_dir = fs::canonicalize(&first_dir).expect("first dir canonicalizes");
    let second_dir = fs::canonicalize(&second_dir).expect("second dir canonicalizes");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for path_base in [&first_dir, &second_dir] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(path_base))
            .expect("path base is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes under different path bases must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_store_dir_in_cache_identity() {
    let root = unique_temp_dir("force-cache-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for store_dir in [&first_store, &second_store] {
        let mut options = TreeWalkOptions::new();
        options
            .set_store_dir(path_bytes(store_dir))
            .expect("store dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes under different store dirs must not reuse one demand node"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_home_dir_in_cache_identity() {
    let root = unique_temp_dir("force-cache-home-dir");
    let first_home = root.join("home-a");
    let second_home = root.join("home-b");
    fs::create_dir_all(&first_home).expect("first home exists");
    fs::create_dir_all(&second_home).expect("second home exists");
    fs::write(first_home.join("marker"), b"present").expect("first marker exists");
    let first_home = fs::canonicalize(&first_home).expect("first home canonicalizes");
    let second_home = fs::canonicalize(&second_home).expect("second home canonicalizes");
    let source = "{ a = builtins.pathExists ~/marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (home_dir, expected) in [(&first_home, true), (&second_home, false)] {
        let mut options = TreeWalkOptions::new();
        options
            .set_home_dir(path_bytes(home_dir))
            .expect("home dir is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_bool(), Ok(expected));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different home dirs must not reuse a prior resolved pathExists input"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        4,
        "same source bytes under different home dirs must not reuse demand nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_backed_forced_inline_thunks_include_eval_mode_in_cache_identity() {
    let source = "{ a = 1 + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for mode in [EvalMode::Impure, EvalMode::Pure] {
        let options = TreeWalkOptions::with_eval_mode(mode);
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "default.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same source bytes under different eval modes must not reuse one demand node"
    );
}

fn cache_nodes_with_dependencies(cache: &EvalCache) -> usize {
    (0..cache.len())
        .filter(|index| {
            let raw = u32::try_from(*index).expect("test graph has u32-addressable nodes");
            !cache
                .graph()
                .node(crate::cache::DemandNodeId::new(raw))
                .expect("node exists")
                .dependencies()
                .is_empty()
        })
        .count()
}

#[test]
fn effectful_forced_inline_thunks_revalidate_impure_edges_before_hits() {
    let root = unique_temp_dir("force-cache-effectful");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    {
        let runtime = cache.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        assert_eq!(
            cache.len(),
            2,
            "pathExists force results now create an expression node and input leaf"
        );
        assert_eq!(
            cache_nodes_with_dependencies(cache),
            1,
            "the expression node must depend on the observed pathExists leaf"
        );
    }

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_again = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("second force revalidates and hits");

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable effectful memo payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), true)
            .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must remain visible to enclosing force traces"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_effectful_forced_inline_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-effectful-changed");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("thunk force succeeds")
            .as_bool(),
        Ok(true)
    );

    fs::remove_file(root.join("marker")).expect("marker removed");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed force recomputes");

    assert_eq!(forced_changed.as_bool(), Ok(false));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn effectful_forced_inline_thunks_hit_from_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-hit");
    let root = unique_temp_dir("force-cache-persistent-effectful");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let shared_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        shared_runtime.clone(),
    );
    let forced_again = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_again.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "fresh runtimes should rehydrate stable effectful payloads from disk"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), true)
            .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "persistent hit revalidation must remain visible to enclosing force traces"
    );
    drop(second);

    {
        let runtime = shared_runtime.lock().expect("cache lock is valid");
        let cache = runtime.cache().expect("cache is enabled");
        assert_eq!(
            cache.len(),
            2,
            "persistent hits should seed the in-memory expression node and input leaf"
        );
        assert_eq!(
            cache_nodes_with_dependencies(cache),
            1,
            "the seeded expression node must keep its revalidated input edge"
        );
    }

    fs::remove_dir_all(&persist_root).expect("persistent temp tree removed");

    let mut third_options = TreeWalkOptions::with_eval_cache_enabled(true);
    third_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        third_options,
        "default.nix",
        source,
        shared_runtime,
    );
    let forced_from_memory = force_attr_a(&mut third, &ir, a);

    assert_eq!(forced_from_memory.as_bool(), Ok(true));
    assert_eq!(
        third.stats().thunks_forced(),
        0,
        "persistent-hit runtime seeding should allow later in-memory reuse"
    );
    assert_eq!(third.stats().cache_hits(), 1);
    assert_eq!(third.stats().cache_misses(), 0);
    assert_eq!(
        third.impure_input_trace(),
        expected_trace.as_slice(),
        "seeded runtime hits must still revalidate into the enclosing trace"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_effectful_forced_inline_thunks_miss_persistent_cache_after_revalidation() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-changed");
    let root = unique_temp_dir("force-cache-persistent-effectful-stale");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut first_options = TreeWalkOptions::with_eval_cache_enabled(true);
    first_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    first_options.set_persist_cache_root(&persist_root);
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let thunk_value = seed_prior_persistent_demand_for_attr(&mut first, &ir, a, &persist_root, "a");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("attr force succeeds");
    assert_eq!(forced.as_bool(), Ok(true));
    drop(first);

    fs::remove_file(root.join("marker")).expect("marker removed");

    let mut second_options = TreeWalkOptions::with_eval_cache_enabled(true);
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced_changed = force_attr_a(&mut second, &ir, a);

    assert_eq!(forced_changed.as_bool(), Ok(false));
    assert_eq!(
        second.stats().thunks_forced(),
        1,
        "stale persistent traces should fall back to ordinary forcing"
    );
    assert_eq!(second.stats().cache_hits(), 0);
    assert_eq!(second.stats().cache_misses(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::path_exists(&path_bytes(&root.join("marker")), false)
            .expect("fingerprint builds"),
    ];
    assert_eq!(second.impure_input_trace(), expected_trace.as_slice());

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn effectful_forced_inline_thunks_ignore_untraced_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-untraced");
    let root = unique_temp_dir("force-cache-persistent-effectful-untraced-source");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut seed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    seed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    seed_options.set_persist_cache_root(&persist_root);
    let mut seed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        seed_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let seed_root = seed.eval_root().expect("attrset evaluates");
    let seed_thunk_value = {
        let attrs = seed
            .heap()
            .get_attrs(seed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = seed
            .heap()
            .get_thunk(seed_thunk_value)
            .expect("a remains a suspended thunk");
        seed.force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("force-cache subject builds")
    };
    let identity = subject
        .metadata_identity
        .expect("effectful thunk has metadata identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let payload = CachedExpressionValue::immediate(Value::bool(true)).expect("payload builds");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("untraced payload materializes");
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("trace lookup succeeds"),
        None,
        "the seeded crash-window fixture intentionally has no trace"
    );
    drop(seed);
    drop(persist);

    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    options.set_persist_cache_root(&persist_root);
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced = force_attr_a(&mut eval, &ir, a);

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(
        eval.stats().thunks_forced(),
        1,
        "untraced impure persistent values must recompute"
    );
    assert_eq!(eval.stats().cache_hits(), 0);
    assert_eq!(eval.stats().cache_misses(), 1);

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn tombstoned_effectful_forced_inline_thunks_miss_persistent_cache() {
    let persist_root = unique_temp_dir("force-cache-persistent-effectful-tombstone");
    let root = unique_temp_dir("force-cache-persistent-effectful-tombstone-source");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.pathExists ./marker; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let mut seed_options = TreeWalkOptions::with_eval_cache_enabled(true);
    seed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    seed_options.set_persist_cache_root(&persist_root);
    let mut seed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        seed_options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let seed_root = seed.eval_root().expect("attrset evaluates");
    let seed_thunk_value = {
        let attrs = seed
            .heap()
            .get_attrs(seed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = seed
            .heap()
            .get_thunk(seed_thunk_value)
            .expect("a remains a suspended thunk");
        seed.force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("force-cache subject builds")
    };
    let identity = subject
        .metadata_identity
        .expect("effectful thunk has metadata identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let payload = CachedExpressionValue::immediate(Value::bool(true)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let marker_path = path_bytes(&root.join("marker"));
    let trace_payload = persistent_path_exists_trace_payload(&marker_path, true);
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    persist
        .record_node_trace(key, value_hash, &trace_payload)
        .expect("stale trace records");
    persist
        .record_node_trace_tombstone(key)
        .expect("trace tombstone records");
    drop(seed);
    drop(persist);

    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    options.set_persist_cache_root(&persist_root);
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced = force_attr_a(&mut eval, &ir, a);

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(
        eval.stats().thunks_forced(),
        1,
        "tombstoned impure persistent values must recompute"
    );
    assert_eq!(eval.stats().cache_hits(), 0);
    assert_eq!(eval.stats().cache_misses(), 1);

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn read_file_backed_inline_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-backed");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let target_path = path_bytes(&root.join("target"));
    fs::write(root.join("target"), &marker_path).expect("target path writes");
    let source = "{ a = builtins.pathExists (builtins.readFile ./target); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("readFile-backed force succeeds")
            .as_bool(),
        Ok(true)
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("readFile-backed force revalidates and hits");

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readFile-backed payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, &marker_path).expect("fingerprint builds"),
        ImpureInputFingerprint::path_exists(&marker_path, true).expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay readFile and dependent pathExists edges"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_read_file_backed_inline_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-backed-changed");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let marker_path = path_bytes(&root.join("marker"));
    let missing_path = path_bytes(&root.join("missing"));
    fs::write(root.join("target"), &marker_path).expect("target path writes");
    let source = "{ a = builtins.pathExists (builtins.readFile ./target); }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("readFile-backed force succeeds")
            .as_bool(),
        Ok(true)
    );

    fs::write(root.join("target"), &missing_path).expect("target path changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed readFile-backed force recomputes");

    assert_eq!(forced_changed.as_bool(), Ok(false));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn force_cache_recompute_same_value_counts_early_cutoff_after_trace_miss() {
    let root = unique_temp_dir("force-cache-read-file-same-value-cutoff");
    fs::write(root.join("target"), b"first").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = r#"{ a = let x = builtins.readFile ./target; in if x == "never" then 4 else 3; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile-backed force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(eval.stats().cache_hits(), 0);
    assert_eq!(eval.stats().cache_misses(), 0);
    assert!(eval.stats().force_cache_memoization_bypasses() > 0);
    assert_eq!(eval.stats().early_cutoffs(), 0);

    let mut admitted_options = TreeWalkOptions::new();
    admitted_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut admitted = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        admitted_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let admitted_root = admitted.eval_root().expect("attrset evaluates again");
    let admitted_thunk = {
        let attrs = admitted
            .heap()
            .get_attrs(admitted_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_admitted = admitted
        .force_value(ir.root, Span::new(0, 0), admitted_thunk)
        .expect("admitted readFile-backed force populates");
    assert_eq!(forced_admitted.as_int(), Ok(3));
    assert_eq!(admitted.stats().cache_hits(), 0);
    assert!(admitted.stats().cache_misses() > 0);
    assert_eq!(admitted.stats().early_cutoffs(), 0);

    fs::write(root.join("target"), b"second").expect("target changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed readFile-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(3));
    assert!(changed.stats().thunks_forced() > 0);
    assert_eq!(changed.stats().cache_hits(), 0);
    assert!(changed.stats().cache_misses() > 0);
    assert_eq!(changed.stats().early_cutoffs(), 1);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn read_file_string_payload_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-string-payload");
    fs::write(root.join("target"), b"payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile string payload force succeeds");
    assert_eq!(
        eval.heap()
            .get_string(forced)
            .expect("readFile result is a string")
            .bytes(),
        b"payload"
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let second_forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("readFile string payload revalidates and hits");
    let second_string = second
        .heap()
        .get_string(second_forced)
        .expect("cached string payload rehydrates into second heap");

    assert_eq!(second_string.bytes(), b"payload");
    assert!(!second_string.has_context());
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readFile string payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, b"payload").expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay readFile edges for string payloads"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_read_file_string_payload_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-string-payload-changed");
    fs::write(root.join("target"), b"payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile string payload force succeeds");
    assert_eq!(
        eval.heap()
            .get_string(forced)
            .expect("readFile result is a string")
            .bytes(),
        b"payload"
    );

    fs::write(root.join("target"), b"changed").expect("target changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed readFile string payload recomputes");
    let changed_string = changed
        .heap()
        .get_string(forced_changed)
        .expect("changed readFile result is a string");

    assert_eq!(changed_string.bytes(), b"changed");
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn get_env_string_payload_thunks_hit_and_miss_after_revalidation() {
    let source = r#"{ a = builtins.getEnv "AOS_FORCE_CACHE_TEST"; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let name = b"AOS_FORCE_CACHE_TEST";
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options.set_env_var(name.to_vec(), b"first".to_vec());
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut eval, &ir, a, b"first");

    let mut second_options = TreeWalkOptions::new();
    second_options.set_env_var(name.to_vec(), b"first".to_vec());
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut second, &ir, a, b"first");

    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable getEnv payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace =
        vec![ImpureInputFingerprint::get_env(name, Some(b"first")).expect("fingerprint builds")];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay getEnv edges"
    );

    let mut changed_options = TreeWalkOptions::new();
    changed_options.set_env_var(name.to_vec(), b"second".to_vec());
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut changed, &ir, a, b"second");

    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);
    assert!(changed.stats().cache_misses() > 0);
    let changed_trace =
        vec![ImpureInputFingerprint::get_env(name, Some(b"second")).expect("fingerprint builds")];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());
}

#[test]
fn read_dir_attrset_payload_thunks_hit_and_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-dir-list-payload");
    fs::create_dir(root.join("dir")).expect("directory creates");
    fs::write(root.join("dir").join("alpha"), b"data").expect("alpha writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dir_path = path_bytes(&root.join("dir"));
    let source = "{ a = builtins.readDir ./dir; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_attrs_strings(&mut eval, &ir, a, &[(b"alpha", b"regular")]);

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_attrs_strings(&mut second, &ir, a, &[(b"alpha", b"regular")]);

    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readDir payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [DirEntryInput::new(b"alpha", FileTypeForInput::Regular)],
        )
        .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay readDir edges"
    );

    fs::write(root.join("dir").join("beta"), b"data").expect("beta writes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_attrs_strings(
        &mut changed,
        &ir,
        a,
        &[(b"alpha", b"regular"), (b"beta", b"regular")],
    );

    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);
    assert!(changed.stats().cache_misses() > 0);
    let changed_trace = vec![
        ImpureInputFingerprint::read_dir(
            &dir_path,
            [
                DirEntryInput::new(b"alpha", FileTypeForInput::Regular),
                DirEntryInput::new(b"beta", FileTypeForInput::Regular),
            ],
        )
        .expect("fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    let mut fourth_options = TreeWalkOptions::new();
    fourth_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut fourth = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        fourth_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_attrs_strings(
        &mut fourth,
        &ir,
        a,
        &[(b"alpha", b"regular"), (b"beta", b"regular")],
    );

    assert_eq!(
        fourth.stats().thunks_forced(),
        0,
        "stable multi-entry readDir payloads should hit after recomputation"
    );
    assert_eq!(fourth.stats().cache_hits(), 1);
    assert_eq!(fourth.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn read_file_type_string_payload_thunks_hit_and_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-type-string-payload");
    fs::write(root.join("target"), b"data").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFileType ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut eval, &ir, a, b"regular");

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut second, &ir, a, b"regular");

    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readFileType payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Regular)
            .expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay readFileType edges"
    );

    fs::remove_file(root.join("target")).expect("target file removes");
    fs::create_dir(root.join("target")).expect("target directory creates");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    force_attr_a_string(&mut changed, &ir, a, b"directory");

    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);
    assert!(changed.stats().cache_misses() > 0);
    let changed_trace = vec![
        ImpureInputFingerprint::read_file_type(&target_path, FileTypeForInput::Directory)
            .expect("fingerprint builds"),
    ];
    assert_eq!(changed.impure_input_trace(), changed_trace.as_slice());

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_read_file_string_payload_thunks_hit_and_miss_after_revalidation() {
    let root = unique_temp_dir("source-less-force-cache-read-file-string-payload");
    fs::write(root.join("target"), b"payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let forced = force_attr_a(&mut eval, &ir, a);
    assert_eq!(
        eval.heap()
            .get_string(forced)
            .expect("readFile result is a string")
            .bytes(),
        b"payload"
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_eval_cache(&ir, second_options, cache.clone());
    let second_forced = force_attr_a(&mut second, &ir, a);
    let second_string = second
        .heap()
        .get_string(second_forced)
        .expect("cached string payload rehydrates into second heap");

    assert_eq!(second_string.bytes(), b"payload");
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable source-less readFile payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, b"payload").expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "source-less cache-hit revalidation must replay readFile edges"
    );

    fs::write(root.join("target"), b"changed").expect("target changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_eval_cache(&ir, changed_options, cache.clone());
    let changed_forced = force_attr_a(&mut changed, &ir, a);
    let changed_string = changed
        .heap()
        .get_string(changed_forced)
        .expect("changed readFile result is a string");

    assert_eq!(changed_string.bytes(), b"changed");
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn read_file_context_string_payload_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-context-string-payload");
    let referenced_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
    let contents = [
        b"prefix ".as_slice(),
        referenced_path,
        b"/suffix".as_slice(),
    ]
    .concat();
    fs::write(root.join("target"), &contents).expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let target_path = path_bytes(&root.join("target"));
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile context string payload force succeeds");
    let string = eval
        .heap()
        .get_string(forced)
        .expect("readFile result is a string");

    assert_eq!(string.bytes(), contents.as_slice());
    assert_eq!(
        string.context().elements(),
        &[ContextElement::opaque_path(referenced_path.to_vec()).expect("context path is valid")]
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let second_forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("readFile context string payload revalidates and hits");
    let second_string = second
        .heap()
        .get_string(second_forced)
        .expect("cached context string payload rehydrates into second heap");

    assert_eq!(second_string.bytes(), contents.as_slice());
    assert_eq!(
        second_string.context().elements(),
        &[ContextElement::opaque_path(referenced_path.to_vec()).expect("context path is valid")]
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable readFile context string payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::read_file(&target_path, &contents).expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay readFile edges for context string payloads"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_read_file_context_string_payload_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-read-file-context-string-payload-changed");
    let old_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
    let new_path = b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source";
    fs::write(root.join("target"), old_path).expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = builtins.readFile ./target; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("readFile context string payload force succeeds");
    let string = eval
        .heap()
        .get_string(forced)
        .expect("readFile result is a string");

    assert_eq!(
        string.context().elements(),
        &[ContextElement::opaque_path(old_path.to_vec()).expect("old context path is valid")]
    );

    fs::write(root.join("target"), new_path).expect("target changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let changed_forced = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed readFile context string payload recomputes");
    let changed_string = changed
        .heap()
        .get_string(changed_forced)
        .expect("changed readFile result is a string");

    assert_eq!(changed_string.bytes(), new_path);
    assert_eq!(
        changed_string.context().elements(),
        &[ContextElement::opaque_path(new_path.to_vec()).expect("new context path is valid")]
    );
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn import_backed_inline_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-import-backed");
    fs::write(root.join("dep.nix"), b"1").expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dep_path = path_bytes(&fs::canonicalize(root.join("dep.nix")).expect("dep canonicalizes"));
    let source = "{ a = import ./dep.nix; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("import-backed force succeeds")
            .as_int(),
        Ok(1)
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("import-backed force revalidates and hits");

    assert_eq!(forced.as_int(), Ok(1));
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable import-backed payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace =
        vec![ImpureInputFingerprint::import(&dep_path, b"1").expect("fingerprint builds")];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay the import source edge"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_import_backed_inline_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-import-backed-changed");
    fs::write(root.join("dep.nix"), b"1").expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = import ./dep.nix; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("import-backed force succeeds")
            .as_int(),
        Ok(1)
    );

    fs::write(root.join("dep.nix"), b"2").expect("import source changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed import-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn import_backed_path_payload_thunks_hit_after_revalidation() {
    let root = unique_temp_dir("force-cache-import-backed-path");
    let imported_source = br#"/tmp + "/imported-path""#;
    fs::write(root.join("dep.nix"), imported_source).expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let dep_path = path_bytes(&fs::canonicalize(root.join("dep.nix")).expect("dep canonicalizes"));
    let source = "{ a = import ./dep.nix; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let first = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("import-backed path force succeeds");
    let first_path = eval.heap().get_path(first).expect("first result is a path");
    assert_eq!(first_path.bytes(), b"/tmp/imported-path");

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        second_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let second_root = second.eval_root().expect("attrset evaluates again");
    let second_thunk = {
        let attrs = second
            .heap()
            .get_attrs(second_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = second
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("import-backed path force revalidates and hits");
    let path = second
        .heap()
        .get_path(forced)
        .expect("cached value is rehydrated into this evaluator heap");

    assert_eq!(path.bytes(), b"/tmp/imported-path");
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "stable import-backed path payloads should hit after input revalidation"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    let expected_trace = vec![
        ImpureInputFingerprint::import(&dep_path, imported_source).expect("fingerprint builds"),
    ];
    assert_eq!(
        second.impure_input_trace(),
        expected_trace.as_slice(),
        "cache-hit revalidation must replay the import source edge"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn changed_import_backed_path_payload_thunks_miss_after_revalidation() {
    let root = unique_temp_dir("force-cache-import-backed-path-changed");
    fs::write(root.join("dep.nix"), br#"/tmp + "/imported-path""#).expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = import ./dep.nix; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let first = eval
        .force_admitted_value(ir.root, Span::new(0, 0), thunk)
        .expect("import-backed path force succeeds");
    let first_path = eval.heap().get_path(first).expect("first result is a path");
    assert_eq!(first_path.bytes(), b"/tmp/imported-path");

    fs::write(root.join("dep.nix"), br#"/tmp + "/changed-path""#).expect("import source changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed import-backed path force recomputes");
    let changed_path = changed
        .heap()
        .get_path(forced_changed)
        .expect("changed result is a path");

    assert_eq!(changed_path.bytes(), b"/tmp/changed-path");
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn import_cache_hits_keep_force_cache_impure_edges() {
    let root = unique_temp_dir("force-cache-import-hit-backed");
    fs::write(root.join("dep.nix"), b"1").expect("import source writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ warm = import ./dep.nix; a = import ./dep.nix; }";
    let ir = lower(source);
    let warm = symbol_for(&ir, b"warm");
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let (warm_thunk, a_thunk) = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        (
            attrs.get(warm).expect("warm exists"),
            attrs.get(a).expect("a exists"),
        )
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), warm_thunk)
            .expect("warm import force succeeds")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), a_thunk)
            .expect("cached import force succeeds")
            .as_int(),
        Ok(1)
    );

    fs::write(root.join("dep.nix"), b"2").expect("import source changes");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("changed import-cache-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn symlinked_import_cache_hits_skip_force_cache_hits() {
    let root = unique_temp_dir("force-cache-import-cache-symlink-hit");
    fs::create_dir(root.join("real")).expect("real import directory creates");
    fs::create_dir(root.join("other")).expect("other import directory creates");
    fs::write(root.join("real").join("dep.nix"), b"1").expect("real import source writes");
    fs::write(root.join("other").join("dep.nix"), b"2").expect("other import source writes");
    std::os::unix::fs::symlink(root.join("real"), root.join("link"))
        .expect("import parent symlink creates");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ warm = import ./real/dep.nix; a = import ./link/dep.nix; }";
    let ir = lower(source);
    let warm = symbol_for(&ir, b"warm");
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let (warm_thunk, a_thunk) = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        (
            attrs.get(warm).expect("warm exists"),
            attrs.get(a).expect("a exists"),
        )
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), warm_thunk)
            .expect("safe import force succeeds")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), a_thunk)
            .expect("symlinked import-cache hit succeeds")
            .as_int(),
        Ok(1)
    );

    fs::remove_file(root.join("link")).expect("import parent symlink removes");
    std::os::unix::fs::symlink(root.join("other"), root.join("link"))
        .expect("import parent symlink retargets");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("retargeted symlink import-cache force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn symlinked_import_backed_inline_thunks_skip_force_cache_hits() {
    let root = unique_temp_dir("force-cache-import-symlink");
    fs::write(root.join("one.nix"), b"1").expect("first import source writes");
    fs::write(root.join("two.nix"), b"2").expect("second import source writes");
    std::os::unix::fs::symlink(root.join("one.nix"), root.join("dep.nix"))
        .expect("import symlink creates");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = import ./dep.nix; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("symlinked import-backed force succeeds")
            .as_int(),
        Ok(1)
    );

    fs::remove_file(root.join("dep.nix")).expect("import symlink removes");
    std::os::unix::fs::symlink(root.join("two.nix"), root.join("dep.nix"))
        .expect("import symlink retargets");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("retargeted symlink import-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn symlinked_import_parent_inline_thunks_skip_force_cache_hits() {
    let root = unique_temp_dir("force-cache-import-parent-symlink");
    fs::create_dir(root.join("one")).expect("first import directory creates");
    fs::create_dir(root.join("two")).expect("second import directory creates");
    fs::write(root.join("one").join("dep.nix"), b"1").expect("first import source writes");
    fs::write(root.join("two").join("dep.nix"), b"2").expect("second import source writes");
    std::os::unix::fs::symlink(root.join("one"), root.join("link"))
        .expect("import parent symlink creates");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = import ./link/dep.nix; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut eval = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = eval.eval_root().expect("attrset evaluates");
    let thunk = {
        let attrs = eval
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(
        eval.force_admitted_value(ir.root, Span::new(0, 0), thunk)
            .expect("parent-symlinked import-backed force succeeds")
            .as_int(),
        Ok(1)
    );

    fs::remove_file(root.join("link")).expect("import parent symlink removes");
    std::os::unix::fs::symlink(root.join("two"), root.join("link"))
        .expect("import parent symlink retargets");

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "default.nix",
        source,
        cache.clone(),
    );
    let changed_root = changed.eval_root().expect("attrset evaluates again");
    let changed_thunk = {
        let attrs = changed
            .heap()
            .get_attrs(changed_root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced_changed = changed
        .force_admitted_value(ir.root, Span::new(0, 0), changed_thunk)
        .expect("retargeted parent-symlinked import-backed force recomputes");

    assert_eq!(forced_changed.as_int(), Ok(2));
    assert_eq!(changed.stats().thunks_forced(), 1);
    assert_eq!(changed.stats().cache_hits(), 0);

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn effectful_descendant_forced_inline_thunks_record_impure_edges() {
    let root = unique_temp_dir("force-cache-effectful-descendant");
    fs::write(root.join("marker"), b"present").expect("marker exists");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = "{ a = if builtins.pathExists ./marker then 1 else 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base is absolute");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "default.nix",
        source,
        cache.clone(),
    );
    let root_value = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");

    assert_eq!(forced.as_int(), Ok(1));
    let runtime = cache.lock().expect("cache lock is valid");
    let cache = runtime.cache().expect("cache is enabled");
    assert_eq!(
        cache.len(),
        2,
        "effectful descendants now create an expression node and input leaf"
    );
    assert_eq!(
        cache_nodes_with_dependencies(cache),
        1,
        "the expression node must depend on the descendant pathExists leaf"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn ambient_current_system_forced_inline_thunks_hit_with_matching_option_salt() {
    let source = "{ a = builtins.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second =
        TreeWalk::with_options_and_source_and_eval_cache(&ir, options, "expr.nix", source, cache);
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "matching currentSystem option salt should permit a string payload hit"
    );
    assert_eq!(second.stats().cache_hits(), 1);
}

#[test]
fn ambient_current_system_forced_inline_thunks_include_current_system_in_cache_identity() {
    let source = "{ a = builtins.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (system, expected) in [
        (b"x86_64-linux".as_slice(), b"x86_64-linux".as_slice()),
        (b"aarch64-linux".as_slice(), b"aarch64-linux".as_slice()),
    ] {
        let options =
            TreeWalkOptions::with_current_system(system.to_vec()).expect("currentSystem is valid");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "expr.nix",
            source,
            cache.clone(),
        );
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(
            evaluator
                .heap()
                .get_string(forced)
                .expect("currentSystem result is a string")
                .bytes(),
            expected
        );
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different currentSystem values must not share one payload"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different currentSystem values should allocate separate expression nodes"
    );
}

#[test]
fn ambient_store_dir_forced_inline_thunks_hit_and_miss_by_store_dir_salt() {
    let root = unique_temp_dir("force-cache-ambient-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "{ a = builtins.storeDir; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_store_dir(path_bytes(&first_store))
        .expect("store dir is absolute");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options.clone(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("storeDir result is a string")
            .bytes(),
        path_bytes(&first_store).as_slice()
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached storeDir result rehydrates")
            .bytes(),
        path_bytes(&first_store).as_slice()
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "matching storeDir option salt should permit a string payload hit"
    );
    assert_eq!(second.stats().cache_hits(), 1);

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_store_dir(path_bytes(&second_store))
        .expect("store dir is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "expr.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(forced)
            .expect("changed storeDir result is a string")
            .bytes(),
        path_bytes(&second_store).as_slice()
    );
    assert_eq!(
        changed.stats().cache_hits(),
        0,
        "different storeDir values must not share one payload"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different storeDir values should allocate separate expression nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn source_less_current_system_thunks_hit_with_matching_option_salt() {
    let source = "{ a = builtins.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut first = TreeWalk::with_options_and_eval_cache(&ir, options.clone(), cache.clone());
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, options, cache);
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached source-less currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().thunks_forced(),
        0,
        "matching source-less currentSystem option salt should permit a string payload hit"
    );
    assert_eq!(second.stats().cache_hits(), 1);
}

#[test]
fn source_less_current_system_thunks_include_current_system_in_cache_identity() {
    let source = "{ a = builtins.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (system, expected) in [
        (b"x86_64-linux".as_slice(), b"x86_64-linux".as_slice()),
        (b"aarch64-linux".as_slice(), b"aarch64-linux".as_slice()),
    ] {
        let options =
            TreeWalkOptions::with_current_system(system.to_vec()).expect("currentSystem is valid");
        let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(
            evaluator
                .heap()
                .get_string(forced)
                .expect("currentSystem result is a string")
                .bytes(),
            expected
        );
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different source-less currentSystem values must not share one payload"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different source-less currentSystem values should allocate separate expression nodes"
    );
}

#[test]
fn ambient_current_time_forced_inline_thunks_record_uncacheable_trace_without_payload() {
    let source = "{ a = builtins.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");

    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "currentTime remains uncacheable even when the force body is observed"
    );
}

#[test]
fn source_less_current_time_thunks_record_uncacheable_trace_without_payload() {
    let source = "{ a = builtins.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let forced = force_attr_a(&mut evaluator, &ir, a);

    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "source-less currentTime remains uncacheable even when the force body is observed"
    );
}

#[test]
fn source_backed_current_time_tombstones_stale_persistent_payload() {
    let persist_root = unique_temp_dir("force-cache-persistent-stale-current-time-node");
    let source = "{ a = builtins.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let mut options =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_source(&ir, options, "expr.nix", source);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a suspended node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("currentTime node thunk has force-cache observation subject")
    };
    assert!(
        subject.lookup_identity.is_none() && subject.metadata_identity.is_none(),
        "currentTime node thunks must stay ineligible for hit selection and demand accounting"
    );
    let identity = subject
        .persistent_clear_identity
        .expect("currentTime node thunk has persistent clear identity");
    let key = PersistNodeMetadataKey::for_expression(
        identity,
        subject.free_var_value_hashes.iter().copied(),
    );
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload =
        persistent_path_exists_trace_payload(b"/tmp/aos-stale-current-time-node", true);
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("seed persistent demand records");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &stale_payload,
            MaterializationDecision::Materialize,
        )
        .expect("stale persistent payload materializes");
    persist
        .record_node_trace(key, stale_value_hash, &stale_trace_payload)
        .expect("stale persistent trace records");
    drop(persist);

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentTime force succeeds");
    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "source-backed currentTime must not replay stale persistent payloads"
    );
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(2, 3)),
        "uncacheable currentTime should clear stale values without recording demand"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "uncacheable currentTime clears the stale persistent value link"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .expect("persistent trace tombstone records")
            .payload()
            .is_tombstone(),
        "uncacheable currentTime tombstones stale persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn reified_builtins_current_time_entry_is_lazy() {
    let ir = lower("builtins");
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("builtins evaluates");

    assert!(
        evaluator.impure_input_trace().is_empty(),
        "constructing the builtins attrset must not read currentTime"
    );
    let current_time = evaluator
        .symbols
        .intern(b"currentTime")
        .expect("currentTime symbol interns");
    let attrs = evaluator
        .heap()
        .get_attrs(root)
        .expect("builtins evaluates to attrs");
    let value = attrs
        .get(current_time)
        .expect("currentTime is present when configured");
    let thunk = evaluator
        .heap()
        .get_thunk(value)
        .expect("currentTime remains a delayed builtin attr thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn synthetic_builtin_attr_current_system_thunks_hit_with_matching_option_salt() {
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached synthetic currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().cache_hits(),
        1,
        "the reified builtins constant should hit at the synthetic builtin thunk"
    );
    assert_eq!(
        second.stats().thunks_forced(),
        2,
        "the outer attr thunk and reified builtins attrset still evaluate"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching synthetic builtin constants should share one demand node"
    );
}

fn persistent_path_exists_trace_payload(path: &[u8], exists: bool) -> PersistNodeTracePayload {
    let input =
        ImpureInputFingerprint::path_exists(path, exists).expect("pathExists fingerprint builds");
    PersistNodeTracePayload::from_impure_trace([&input]).expect("trace payload builds")
}

fn persistent_empty_trace_payload() -> PersistNodeTracePayload {
    PersistNodeTracePayload::from_impure_trace(std::iter::empty::<&ImpureInputFingerprint>())
        .expect("empty trace payload builds")
}

#[test]
fn synthetic_builtin_attr_cold_force_records_demand_without_materializing() {
    let persist_root = unique_temp_dir("force-cache-persistent-demand");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        cache.clone(),
    );
    let root = first.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = first
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = first
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    let forced = first
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentSystem force succeeds");
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(0, 1)),
        "cold force records one current-run demand"
    );
    assert_eq!(
        persist
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        None,
        "cold force records demand without linking a persistent value payload"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload load succeeds"),
        None,
        "cold force keeps the value in memory until prior-run demand exists"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        None,
        "cold force skips the persistent trace when the value is not materialized"
    );
    drop(persist);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins.nix",
        source,
        cache,
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    drop(second);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(0, 2)),
        "admitted recomputation also records current-run demand"
    );
    assert_eq!(
        persist
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        None,
        "same-run demand does not predict cross-run reuse until run advancement"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn public_eval_advances_persistent_force_demand_run_boundary() {
    let persist_root = unique_temp_dir("force-cache-persistent-run-boundary");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let mut key_eval = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
            .expect("currentSystem is valid"),
        "synthetic-builtins.nix",
        source,
    );
    let root = key_eval.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = key_eval
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = key_eval
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = key_eval
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());

    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let attr_path = vec![b"a".to_vec()];
    let first = eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
        &ir,
        &attr_path,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        None,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    )
    .expect("first attr-path eval succeeds");
    assert_eq!(
        first
            .heap()
            .get_string(first.value())
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::from_previous_run(1)),
        "successful public eval advances cold current demand into prior-run history"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "the cold run still skips the durable value payload before prior demand exists"
    );
    drop(persist);

    let second = eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
        &ir,
        &attr_path,
        options,
        "synthetic-builtins.nix",
        source,
        None,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    )
    .expect("second attr-path eval succeeds");
    assert_eq!(
        second
            .heap()
            .get_string(second.value())
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );

    let expected_payload = CachedExpressionValue::context_free_string(b"x86_64-linux".to_vec());
    let expected_value_hash = expected_payload
        .value_hash()
        .expect("expected payload hashes");
    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::from_previous_run(2)),
        "second successful public eval advances the new demand observation too"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        Some(expected_payload),
        "prior-run demand lets the next run materialize the durable value payload"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            expected_value_hash,
            persistent_empty_trace_payload()
        )),
        "materialized public evals write the zero-input verifying trace"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn non_owning_public_eval_rejection_does_not_advance_persistent_force_demand() {
    let persist_root = unique_temp_dir("force-cache-persistent-rejected-boundary");
    let source = "let b = builtins; in { a = b.currentSystem; }.a";
    let ir = lower(source);

    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let error =
        eval_whnf_with_options(&ir, options).expect_err("non-owning eval rejects heap string");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::HeapValueRequiresOwner {
            id: ir.root,
            tag: ValueTag::String,
        }
    );

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    let entries = persist
        .node_metadata_index()
        .latest_entries()
        .expect("latest metadata entries load");
    let [entry] = entries.as_slice() else {
        panic!("expected one force-cache demand metadata entry, got {entries:?}");
    };
    assert_eq!(
        entry.value().materialization_reuse(),
        MaterializationReuse::new(0, 1),
        "the rejected public wrapper must not promote demand into prior-run history"
    );
    assert_eq!(
        entry.value().materialized_value_hash(),
        None,
        "the rejected public wrapper must not link a durable payload"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(entry.key())
            .expect("persistent payload lookup succeeds"),
        None,
        "the rejected public wrapper must not materialize a durable payload"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn public_eval_without_persistent_force_demand_does_not_open_persist_cache() {
    let persist_root = unique_temp_dir("force-cache-persistent-unused-boundary");
    let ir = lower("1 + 2");
    let mut options = TreeWalkOptions::default();
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let bytes = eval_number_raw_bytes_with_options(&ir, options).expect("number eval succeeds");
    assert_eq!(bytes, b"3");

    let entries = fs::read_dir(&persist_root)
        .expect("temp root is readable")
        .collect::<Result<Vec<_>, _>>()
        .expect("temp root entries read");
    assert!(
        entries.is_empty(),
        "successful public evals must not create persistent-cache state unless force-cache code opened it"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_hits_persistent_current_system_with_empty_trace() {
    let persist_root = unique_temp_dir("force-cache-persistent-current-system-hit");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = first.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = first
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = first
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let forced = first
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentSystem force succeeds");
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);
    drop(first);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            CachedExpressionValue::context_free_string(b"x86_64-linux".to_vec())
                .value_hash()
                .expect("expected payload hashes"),
            persistent_empty_trace_payload()
        )),
        "pure currentSystem payloads use a zero-input verifying trace"
    );
    drop(persist);

    let shared_runtime = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        shared_runtime.clone(),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("persistent currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
    drop(second);

    {
        let runtime = shared_runtime.lock().expect("cache lock is valid");
        assert_eq!(
            runtime.cache().expect("cache is enabled").len(),
            1,
            "pure persistent hits should seed an in-memory expression node"
        );
    }

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(1, 2)),
        "persistent pure hits also record current-run demand"
    );
    drop(persist);

    fs::remove_dir_all(&persist_root).expect("temp tree removed");

    let mut third_options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    third_options.set_eval_cache_enabled(true);
    let mut third = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        third_options,
        "synthetic-builtins.nix",
        source,
        shared_runtime,
    );
    let forced = force_attr_a(&mut third, &ir, a);
    assert_eq!(
        third
            .heap()
            .get_string(forced)
            .expect("seeded currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        third.stats().thunks_forced(),
        2,
        "the seeded pure hit should avoid forcing the reified builtin attr thunk"
    );
    assert_eq!(third.stats().cache_hits(), 1);
    assert_eq!(third.stats().cache_misses(), 0);
}

#[test]
fn disabled_eval_cache_skips_persistent_current_system_hit() {
    let persist_root = unique_temp_dir("force-cache-persistent-hit-disabled");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let mut key_eval = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
            .expect("currentSystem is valid"),
        "synthetic-builtins.nix",
        source,
    );
    let root = key_eval.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = key_eval
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = key_eval
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = key_eval
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    let payload = CachedExpressionValue::context_free_string(b"stale-disabled-hit".to_vec());
    let value_hash = payload.value_hash().expect("seed payload hashes");
    let trace_payload = persistent_empty_trace_payload();
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("seed persistent payload materializes");
    persist
        .record_node_trace(key, value_hash, &trace_payload)
        .expect("seed persistent trace records");
    drop(persist);

    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let forced = force_attr_a(&mut evaluator, &ir, a);
    assert_eq!(
        evaluator
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux",
        "disabled eval-cache observation must not rehydrate the seeded persistent payload"
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "disabled eval-cache observation must not count a persistent force hit"
    );
    assert_eq!(
        evaluator.stats().thunks_forced(),
        3,
        "disabled eval-cache observation must force the let binding, attr thunk, and builtin attr normally"
    );
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(0, 0)),
        "disabled eval-cache observation must not record fresh persistent demand"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        Some(payload),
        "disabled eval-cache observation must leave the seeded payload unchanged"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            value_hash,
            trace_payload
        )),
        "disabled eval-cache observation must leave the seeded trace unchanged"
    );
    assert_eq!(
        fs::metadata(persist.node_trace_log().path())
            .expect("node trace log metadata")
            .len(),
        PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN as u64
            + persistent_empty_trace_payload()
                .encode()
                .expect("empty trace payload encodes")
                .len() as u64,
        "disabled eval-cache observation must not append extra persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn rejected_force_observation_clears_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-clear-rejected");
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"persistent-force-node"),
        IrId::new(7),
    );
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload = persistent_path_exists_trace_payload(b"/tmp/stale-input", true);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                stale_payload.clone(),
            )
            .expect("stale runtime payload is seeded");
    }

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("reuse metadata records");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &stale_payload,
            MaterializationDecision::Materialize,
        )
        .expect("stale persistent payload materializes");
    persist
        .record_node_trace(key, stale_value_hash, &stale_trace_payload)
        .expect("stale persistent trace records");
    drop(persist);

    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        Value::int(456),
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: false,
        },
    );

    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert!(
            runtime
                .lookup_inline_expression_payload(
                    identity,
                    std::iter::empty::<DurableBlake3Hash>(),
                )
                .expect("runtime lookup succeeds")
                .is_none(),
            "rejected observation invalidates the stale runtime payload"
        );
    }
    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    let metadata = persist
        .lookup_node_metadata(key)
        .expect("metadata lookup succeeds")
        .expect("metadata remains present");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(2, 3),
        "clearing the value link preserves reuse counters"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "rejected observation clears the stale persistent value link"
    );
    let trace = persist
        .lookup_node_trace(key)
        .expect("persistent trace lookup succeeds")
        .expect("persistent trace tombstone records");
    assert_eq!(trace.key(), key);
    assert!(
        trace.payload().is_tombstone(),
        "rejected observations tombstone stale persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn cacheable_impure_force_observation_writes_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-impure-writeback");
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"persistent-force-impure"),
        IrId::new(9),
    );
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache);
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let trace_input = ImpureInputFingerprint::path_exists(b"/tmp/aos-cacheable-input", true)
        .expect("pathExists fingerprint builds");
    let expected_trace_payload =
        PersistNodeTracePayload::from_impure_trace([&trace_input]).expect("trace payload builds");
    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        Value::bool(true),
        ImpureInputTraceSegment {
            trace: vec![trace_input],
            complete: true,
        },
    );

    let expected_payload =
        CachedExpressionValue::immediate(Value::bool(true)).expect("bool payload is cacheable");
    let expected_value_hash = expected_payload
        .value_hash()
        .expect("expected payload hashes");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        Some(expected_payload),
        "cacheable impure observations write the persistent value payload"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            expected_value_hash,
            expected_trace_payload
        )),
        "cacheable impure observations write the value-associated persistent verifying trace"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn unprofitable_force_observation_skips_persistent_value_link_with_prior_demand() {
    let persist_root = unique_temp_dir("force-cache-persistent-unprofitable-writeback");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    options.set_force_cache_materialization_costs(MaterializationCosts::new(3, 1, 1, 1));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = evaluator
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentSystem force succeeds");
    assert_eq!(
        evaluator
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(1, 1)),
        "production forcing records current demand before the negative threshold skips writeback"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "unprofitable observations do not write persistent value payloads"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        None,
        "unprofitable observations do not write persistent verifying traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn unsupported_force_payload_clears_persistent_value_link() {
    let persist_root = unique_temp_dir("force-cache-persistent-clear-unsupported");
    let ir = lower("{ a = 1 / 0; }");
    let identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"persistent-force-unsupported"),
        IrId::new(11),
    );
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload = persistent_path_exists_trace_payload(b"/tmp/stale-input", true);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &stale_payload,
            MaterializationDecision::Materialize,
        )
        .expect("stale persistent payload materializes");
    persist
        .record_node_trace(key, stale_value_hash, &stale_trace_payload)
        .expect("stale persistent trace records");
    drop(persist);

    let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);
    let mut evaluator = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let unsupported = evaluator.eval_root().expect("attrset evaluates");
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        unsupported,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );

    {
        let runtime = cache.lock().expect("cache lock is valid");
        assert!(
            runtime
                .lookup_inline_expression_payload(
                    identity,
                    std::iter::empty::<DurableBlake3Hash>(),
                )
                .expect("runtime lookup succeeds")
                .is_none(),
            "the runtime starts without a node for the durable-only stale link"
        );
    }
    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "unsupported recomputation clears the stale persistent value link"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .expect("persistent trace tombstone records")
            .payload()
            .is_tombstone(),
        "unsupported recomputation tombstones stale persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn disabled_eval_cache_skips_persistent_current_demand() {
    let persist_root = unique_temp_dir("force-cache-persistent-demand-disabled");
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_system = symbol_for(&ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options.set_persist_cache_root(&persist_root);

    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = evaluator
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_node_materialization_reuse(key, MaterializationReuse::from_previous_run(1))
        .expect("prior-run demand records");
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentSystem force succeeds");
    assert_eq!(
        evaluator
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::from_previous_run(1)),
        "disabled eval-cache observation must not add current-run persistent demand counters"
    );
    assert_eq!(
        fs::metadata(persist.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        PERSIST_NODE_METADATA_INDEX_ENTRY_LEN as u64,
        "disabled eval-cache observation must not append extra persistent force metadata records"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "disabled eval-cache observation must not write persistent force value payloads"
    );
    assert_eq!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds"),
        None,
        "disabled eval-cache observation must not write persistent force traces"
    );
    assert_eq!(
        fs::metadata(persist.node_trace_log().path())
            .expect("node trace log metadata")
            .len(),
        0,
        "disabled eval-cache observation must not append any persistent force trace records"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn observation_only_current_time_skips_persistent_current_demand() {
    let persist_root = unique_temp_dir("force-cache-persistent-demand-current-time");
    let source = "let b = builtins; in { a = b.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_time = symbol_for(&ir, b"currentTime");
    let builtin = lookup_builtin(b"currentTime").expect("currentTime builtin is registered");
    let mut options =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut evaluator =
        TreeWalk::with_options_and_source(&ir, options, "synthetic-current-time.nix", source);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = evaluator
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_time,
            builtin,
        )
        .expect("synthetic currentTime observation identity builds");
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentTime force succeeds");
    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        None,
        "observation-only currentTime subjects must not write persistent demand counters"
    );
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "observation-only synthetic currentTime canary",
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn observation_only_current_time_tombstones_stale_persistent_payload() {
    let persist_root = unique_temp_dir("force-cache-persistent-stale-current-time");
    let source = "let b = builtins; in { a = b.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let current_time = symbol_for(&ir, b"currentTime");
    let builtin = lookup_builtin(b"currentTime").expect("currentTime builtin is registered");
    let mut options =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(&persist_root);

    let mut evaluator =
        TreeWalk::with_options_and_source(&ir, options, "synthetic-current-time.nix", source);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = evaluator
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_time,
            builtin,
        )
        .expect("synthetic currentTime observation identity builds");
    let key =
        PersistNodeMetadataKey::for_expression(identity, std::iter::empty::<DurableBlake3Hash>());
    let stale_payload = CachedExpressionValue::immediate(Value::int(123))
        .expect("stale scalar payload is cacheable");
    let stale_value_hash = stale_payload.value_hash().expect("stale payload hashes");
    let stale_trace_payload =
        persistent_path_exists_trace_payload(b"/tmp/aos-stale-current-time", true);

    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    persist
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("seed persistent demand records");
    persist
        .materialize_cached_expression_node_value_indexed(
            key,
            &stale_payload,
            MaterializationDecision::Materialize,
        )
        .expect("stale persistent payload materializes");
    persist
        .record_node_trace(key, stale_value_hash, &stale_trace_payload)
        .expect("stale persistent trace records");
    drop(persist);

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentTime force succeeds");
    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "observation-only currentTime must not replay stale persistent payloads"
    );
    drop(evaluator);

    let persist = PersistCache::open(&persist_root).expect("persistent cache reopens");
    assert_eq!(
        persist
            .lookup_node_materialization_reuse(key)
            .expect("metadata lookup succeeds"),
        Some(MaterializationReuse::new(2, 3)),
        "uncacheable currentTime should clear stale values without recording demand"
    );
    assert_eq!(
        persist
            .load_cached_expression_node_value_indexed(key)
            .expect("persistent payload lookup succeeds"),
        None,
        "uncacheable currentTime clears the stale persistent value link"
    );
    assert!(
        persist
            .lookup_node_trace(key)
            .expect("persistent trace lookup succeeds")
            .expect("persistent trace tombstone records")
            .payload()
            .is_tombstone(),
        "uncacheable currentTime tombstones stale persistent traces"
    );

    fs::remove_dir_all(persist_root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_current_system_thunks_include_current_system_in_cache_identity() {
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (system, expected) in [
        (b"x86_64-linux".as_slice(), b"x86_64-linux".as_slice()),
        (b"aarch64-linux".as_slice(), b"aarch64-linux".as_slice()),
    ] {
        let options =
            TreeWalkOptions::with_current_system(system.to_vec()).expect("currentSystem is valid");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "synthetic-builtins.nix",
            source,
            cache.clone(),
        );
        let forced = force_attr_a(&mut evaluator, &ir, a);
        assert_eq!(
            evaluator
                .heap()
                .get_string(forced)
                .expect("currentSystem result is a string")
                .bytes(),
            expected
        );
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "different currentSystem values must not share one synthetic payload"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different currentSystem salts should allocate separate synthetic nodes"
    );
}

fn synthetic_current_system_identity_for_attr_a(
    ir: &Ir,
    source: &str,
) -> (CacheExprIdentity, IrId) {
    let a = symbol_for(ir, b"a");
    let current_system = symbol_for(ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        ir,
        options,
        "synthetic-builtins.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let site = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = evaluator
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, site),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    (identity, site)
}

#[test]
fn synthetic_builtin_attr_force_identities_include_force_site_span() {
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let (first_identity, site) = synthetic_current_system_identity_for_attr_a(&ir, source);

    let mut shifted = ir.clone();
    let mut nodes = shifted.arena.nodes().to_vec();
    nodes[site.index()].span = Span::new(200, 214);
    shifted.arena = IrArena::from_raw_parts(nodes, shifted.arena.child_pool().to_vec());
    let (shifted_identity, shifted_site) =
        synthetic_current_system_identity_for_attr_a(&shifted, source);

    assert_eq!(shifted_site, site);
    assert_ne!(
        shifted_identity, first_identity,
        "same synthetic builtin force-site id under a different span must not reuse one node"
    );

    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options.clone(),
        "synthetic-builtins.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &shifted,
        options,
        "synthetic-builtins.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &shifted, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("shifted currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().cache_hits(),
        0,
        "same synthetic builtin force-site id under a different span must miss"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "same synthetic builtin force-site id under different spans must allocate separate nodes"
    );

    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut source_less_first =
        TreeWalk::with_options_and_eval_cache(&ir, options.clone(), cache.clone());
    let forced = force_attr_a(&mut source_less_first, &ir, a);
    assert_eq!(
        source_less_first
            .heap()
            .get_string(forced)
            .expect("source-less currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(source_less_first.stats().cache_misses(), 1);

    let mut source_less_second =
        TreeWalk::with_options_and_eval_cache(&shifted, options, cache.clone());
    let forced = force_attr_a(&mut source_less_second, &shifted, a);
    assert_eq!(
        source_less_second
            .heap()
            .get_string(forced)
            .expect("source-less shifted currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        source_less_second.stats().cache_hits(),
        0,
        "source-less synthetic builtin force-site span changes must miss"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "source-less synthetic builtin force-site span changes must allocate separate nodes"
    );
}

#[test]
fn source_less_synthetic_builtin_attr_current_system_thunks_hit_with_matching_option_salt() {
    let source = "let b = builtins; in { a = b.currentSystem; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");

    let mut first = TreeWalk::with_options_and_eval_cache(&ir, options.clone(), cache.clone());
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, options, cache.clone());
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached source-less synthetic currentSystem result rehydrates")
            .bytes(),
        b"x86_64-linux"
    );
    assert_eq!(
        second.stats().cache_hits(),
        1,
        "matching source-less synthetic builtin constants should hit"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching source-less synthetic builtin constants should share one node"
    );
}

#[test]
fn synthetic_builtin_attr_store_dir_thunks_hit_and_miss_by_store_dir_salt() {
    let root = unique_temp_dir("force-cache-synthetic-store-dir");
    let first_store = root.join("store-a");
    let second_store = root.join("store-b");
    let source = "let b = builtins; in { a = b.storeDir; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_store_dir(path_bytes(&first_store))
        .expect("store dir is absolute");
    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options.clone(),
        "synthetic-store-dir.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut first, &ir, a);
    assert_eq!(
        first
            .heap()
            .get_string(forced)
            .expect("storeDir result is a string")
            .bytes(),
        path_bytes(&first_store).as_slice()
    );
    assert_eq!(first.stats().cache_misses(), 1);

    let mut second = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        first_options,
        "synthetic-store-dir.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut second, &ir, a);
    assert_eq!(
        second
            .heap()
            .get_string(forced)
            .expect("cached synthetic storeDir result rehydrates")
            .bytes(),
        path_bytes(&first_store).as_slice()
    );
    assert_eq!(
        second.stats().cache_hits(),
        1,
        "matching storeDir option salt should permit a synthetic string payload hit"
    );

    let mut changed_options = TreeWalkOptions::new();
    changed_options
        .set_store_dir(path_bytes(&second_store))
        .expect("store dir is absolute");
    let mut changed = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        changed_options,
        "synthetic-store-dir.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut changed, &ir, a);
    assert_eq!(
        changed
            .heap()
            .get_string(forced)
            .expect("changed synthetic storeDir result is a string")
            .bytes(),
        path_bytes(&second_store).as_slice()
    );
    assert_eq!(
        changed.stats().cache_hits(),
        0,
        "different storeDir values must not share one synthetic payload"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different storeDir salts should allocate separate synthetic nodes"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_immediate_constants_force_from_reified_attrset() {
    let source = "let b = builtins; in { t = b.true; f = b.false; n = b.null; }";
    let ir = lower(source);
    let t = symbol_for(&ir, b"t");
    let f = symbol_for(&ir, b"f");
    let n = symbol_for(&ir, b"n");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "synthetic-immediates.nix",
        source,
        cache.clone(),
    );

    assert_eq!(force_attr(&mut evaluator, &ir, t, "t").as_bool(), Ok(true));
    assert_eq!(force_attr(&mut evaluator, &ir, f, "f").as_bool(), Ok(false));
    assert_eq!(force_attr(&mut evaluator, &ir, n, "n").as_null(), Ok(()));

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        3,
        "reified immediate constants should observe separate synthetic nodes"
    );
}

#[test]
fn synthetic_builtin_attr_dynamic_selection_keys_include_symbol() {
    let root = unique_temp_dir("force-cache-synthetic-builtin-symbol");
    let store_dir = root.join("store");
    let source = r#"let
      b = builtins;
      f = name: b.${name};
    in {
      sys = f "currentSystem";
      store = f "storeDir";
    }"#;
    let ir = lower(source);
    let sys = symbol_for(&ir, b"sys");
    let store = symbol_for(&ir, b"store");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    options
        .set_store_dir(path_bytes(&store_dir))
        .expect("store dir is absolute");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-builtins-dynamic.nix",
        source,
        cache.clone(),
    );

    let forced_sys = force_attr(&mut evaluator, &ir, sys, "sys");
    assert_eq!(
        evaluator
            .heap()
            .get_string(forced_sys)
            .expect("currentSystem result is a string")
            .bytes(),
        b"x86_64-linux"
    );
    let forced_store = force_attr(&mut evaluator, &ir, store, "store");
    assert_eq!(
        evaluator
            .heap()
            .get_string(forced_store)
            .expect("storeDir result is a string")
            .bytes(),
        path_bytes(&store_dir).as_slice()
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "different synthetic builtin symbols at one dynamic select site must miss"
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "the synthetic key must distinguish builtin symbols at one force site"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn synthetic_builtin_attr_current_time_records_uncacheable_trace_without_payload() {
    let source = "let b = builtins; in { a = b.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-current-time.nix",
        source,
        cache.clone(),
    );
    let forced = force_attr_a(&mut evaluator, &ir, a);

    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "synthetic currentTime remains uncacheable even when it is observed"
    );
}

#[test]
fn synthetic_builtin_attr_current_time_ignores_and_invalidates_stale_payload() {
    let source = "let b = builtins; in { a = b.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let options = TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "synthetic-current-time.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let select_id = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let current_time = symbol_for(&ir, b"currentTime");
    let builtin = lookup_builtin(b"currentTime").expect("currentTime builtin is registered");
    let identity = evaluator
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, select_id),
            current_time,
            builtin,
        )
        .expect("synthetic currentTime identity builds");

    {
        let mut runtime = cache.lock().expect("cache lock is valid");
        runtime
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                CachedExpressionValue::immediate(Value::int(123))
                    .expect("stale payload is cacheable"),
            )
            .expect("stale payload is seeded");
        assert!(
            runtime
                .lookup_inline_expression_payload(
                    identity,
                    std::iter::empty::<DurableBlake3Hash>(),
                )
                .expect("seeded payload lookup succeeds")
                .is_some(),
            "stale payload should be present before forcing currentTime"
        );
    }

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("currentTime force succeeds");
    assert_eq!(forced.as_int(), Ok(1_700_000_000));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "synthetic currentTime must not reuse stale payloads"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime
            .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("post-force lookup succeeds")
            .is_none(),
        "uncacheable currentTime observation should invalidate the stale payload"
    );
}

#[test]
fn search_path_forced_inline_thunks_wait_for_impure_input_edges() {
    let root = unique_temp_dir("force-cache-search-path");
    let target = root.join("target");
    fs::create_dir_all(&target).expect("target dir exists");
    let target = fs::canonicalize(&target).expect("target canonicalizes");
    let source = "{ a = <pkg> == <pkg>; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .add_nix_path_entry(b"pkg".to_vec(), path_bytes(&target))
        .expect("search-path entry is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "expr.nix",
        source,
        cache.clone(),
    );
    let root_value = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root_value)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "search-path literals need search-path/input keys before memoization"
    );

    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn pipe_forced_inline_thunks_wait_for_application_cache_keys() {
    let mut symbols = SymbolTable::new();
    let x = symbols.intern(b"x").expect("symbol interns");
    let frames = vec![FrameInfo {
        slot_count: 1,
        captures: Vec::new().into_boxed_slice(),
        rec: false,
        has_with: false,
    }];
    let ir = manual_ir_with_symbols_and_frames(
        IrId::new(5),
        vec![
            pure_node(
                IrKind::Formal,
                Span::new(0, 1),
                IrData::Formal {
                    name: x,
                    default: None,
                },
            ),
            pure_node(IrKind::Int, Span::new(3, 4), IrData::Int(3)),
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
            pure_node(
                IrKind::BinOp,
                Span::new(0, 9),
                IrData::Binary {
                    op: BinOpKind::PipeRight,
                    lhs: IrId::new(3),
                    rhs: IrId::new(2),
                },
            ),
            pure_node(
                IrKind::ThunkAlloc,
                Span::new(0, 9),
                IrData::Node(IrId::new(4)),
            ),
        ],
        symbols,
        frames,
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        "{ a = 1 |> f; }",
        cache.clone(),
    );
    let forced = evaluator
        .eval_root()
        .expect("thunked pipe root evaluates to weak head normal form");

    assert_eq!(forced.as_int(), Ok(3));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "pipe operators evaluate as application and need application cache keys"
    );
}

#[test]
fn context_free_string_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = "cached " + "string"; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "string-result.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("string thunk force succeeds");
        let string = evaluator
            .heap()
            .get_string(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert_eq!(string.bytes(), b"cached string");
        assert!(!string.has_context());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching context-free string results should share one demand node"
    );
}

#[test]
fn context_string_result_thunks_hit_after_heap_rehydration() {
    let root = unique_temp_dir("force-cache-context-string-result");
    fs::write(root.join("target"), b"payload").expect("target writes");
    let root = fs::canonicalize(&root).expect("root canonicalizes");
    let source = r#"{ a = "${./target}"; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(&root))
            .expect("path base is absolute");
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            options,
            "context-string-result.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("context string thunk force succeeds");
        let string = evaluator
            .heap()
            .get_string(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert!(string.has_context());
        assert_eq!(string.context().len(), 1);
        let element = &string.context().elements()[0];
        assert_eq!(element.kind(), ContextKind::OpaquePath);
        assert_eq!(element.path(), string.bytes());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching context-bearing string results should share one demand node"
    );
    fs::remove_dir_all(root).expect("temp tree removed");
}

#[test]
fn path_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = /tmp + "/cached-path"; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "path-result.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("path thunk force succeeds");
        let path = evaluator
            .heap()
            .get_path(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert_eq!(path.bytes(), b"/tmp/cached-path");
        assert!(!path.has_context());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching path results should share one demand node"
    );
}

#[test]
fn empty_list_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = [ ]; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "empty-list-result.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("empty list thunk force succeeds");
        let list = evaluator
            .heap()
            .get_list(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert!(list.is_empty());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching empty list results should share one demand node"
    );
}

#[test]
fn strict_list_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = [ 1 true null ]; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "strict-list-result.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("strict list thunk force succeeds");
        let list = evaluator
            .heap()
            .get_list(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert_eq!(list.len(), 3);
        assert_eq!(list.get(0).expect("first element exists").as_int(), Ok(1));
        assert_eq!(
            list.get(1).expect("second element exists").as_bool(),
            Ok(true)
        );
        assert_eq!(list.get(2).expect("third element exists").as_null(), Ok(()));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching strict list results should share one demand node"
    );
}

#[test]
fn strict_list_result_thunks_with_heap_elements_hit_after_heap_rehydration() {
    let source = r#"{ a = [ "x" "y" ]; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "strict-list-heap-result.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("strict heap-backed list thunk force succeeds");
        let list = evaluator
            .heap()
            .get_list(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert_eq!(list.len(), 2);
        let string = evaluator
            .heap()
            .get_string(list.get(0).expect("first element exists"))
            .expect("first element is a string");
        assert_eq!(string.bytes(), b"x");
        let second = evaluator
            .heap()
            .get_string(list.get(1).expect("second element exists"))
            .expect("second element is a string");
        assert_eq!(second.bytes(), b"y");
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching strict heap-backed list results should share one demand node"
    );
}

#[test]
fn non_empty_list_literals_with_lazy_elements_wait_for_element_payloads() {
    let source = r#"{ a = [ (1 / 0) ]; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for _ in 0..2 {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "lazy-list-result.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("lazy list thunk force succeeds");
        let list = evaluator
            .heap()
            .get_list(forced)
            .expect("list is heap-owned");

        assert_eq!(list.len(), 1);
        assert_eq!(list.get(0).expect("element exists").tag(), ValueTag::Thunk);
        assert_eq!(evaluator.stats().cache_hits(), 0);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "list literals with lazy elements need element payloads before observation"
    );
}

#[test]
fn empty_attrset_result_thunks_hit_after_heap_rehydration() {
    let source = r#"{ a = { }; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "empty-attrs-result.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("empty attrset thunk force succeeds");
        let attrs = evaluator
            .heap()
            .get_attrs(forced)
            .expect("cached value is rehydrated into this evaluator heap");

        assert!(attrs.is_empty());
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
        assert_eq!(
            evaluator.stats().thunks_forced(),
            if expected_hit { 0 } else { 1 }
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching empty attrset results should share one demand node"
    );
}

#[test]
fn strict_attrset_payloads_rehydrate_after_heap_lookup() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"force-strict-attrs-result"),
        IrId::new(14),
    );
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let b = first.symbols.intern(b"b").expect("b interns");
    let c = first.symbols.intern(b"c").expect("c interns");
    let string = first
        .heap
        .alloc_string(NixString::from_bytes(b"x".to_vec()))
        .expect("string allocates");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::new(b, Value::int(1)), AttrEntry::new(c, string)],
        &first.symbols,
    )
    .expect("attrs build");
    let value = first.heap.alloc_attrs(0, attrs).expect("attrs allocate");
    first.observe_forced_inline_expression_result(
        Some(subject.clone()),
        value,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );
    drop(first);

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache);
    let hit = second
        .lookup_forced_inline_expression_result(Some(subject))
        .expect("strict attrset payload hits");
    let b = second.symbols.intern(b"b").expect("b interns");
    let c = second.symbols.intern(b"c").expect("c interns");
    let attrs = second
        .heap()
        .get_attrs(hit)
        .expect("strict attrset rehydrates into this evaluator heap");
    assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(1));
    let string = second
        .heap()
        .get_string(attrs.get(c).expect("c exists"))
        .expect("c is a string");
    assert_eq!(string.bytes(), b"x");
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
}

#[test]
fn strict_attrset_payloads_skip_position_bearing_attrsets() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"force-position-attrs-result"),
        IrId::new(15),
    );
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            a,
            Value::int(1),
            AttrPosition::new(0, Span::new(0, 1)),
        )],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");

    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        value,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "position-bearing attrsets need position-aware payloads before observation"
    );
}

#[test]
fn strict_attrset_payloads_skip_noncanonical_source_order_attrsets() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"force-source-order-attrs-result"),
        IrId::new(16),
    );
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let c = evaluator.symbols.intern(b"c").expect("c interns");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(c, Value::int(2)),
            AttrEntry::new(b, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    assert_ne!(attrs.source_order(), attrs.iteration_order());
    let value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");

    evaluator.observe_forced_inline_expression_result(
        Some(subject),
        value,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );

    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "source-order-observable attrsets need source-order-aware payloads before observation"
    );
}

#[test]
fn non_empty_attrset_literals_with_lazy_bindings_wait_for_binding_payloads() {
    let source = r#"{ a = { b = (1 / 0); }; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for _ in 0..2 {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "lazy-attrs-result.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("lazy attrset thunk force succeeds");
        let attrs = evaluator
            .heap()
            .get_attrs(forced)
            .expect("attrset is heap-owned");

        assert_eq!(attrs.get(b).expect("b exists").tag(), ValueTag::Thunk);
        assert_eq!(evaluator.stats().cache_hits(), 0);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "attrset literals with lazy bindings need binding payloads before observation"
    );
}

#[test]
fn context_path_payloads_rehydrate_after_heap_lookup() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"force-context-path-result"),
        IrId::new(13),
    );
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let context = StringContext::singleton(
        ContextElement::opaque_path(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec())
            .expect("context path is valid"),
    )
    .expect("context allocates");

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let value = first
        .heap
        .alloc_path(NixString::new(
            b"/nix/store/context-path".to_vec(),
            context.clone(),
        ))
        .expect("context path allocates");
    first.observe_forced_inline_expression_result(
        Some(subject.clone()),
        value,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );
    drop(first);

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache);
    let hit = second
        .lookup_forced_inline_expression_result(Some(subject))
        .expect("context path payload hits");
    let path = second
        .heap()
        .get_path(hit)
        .expect("context path rehydrates into this evaluator heap");

    assert_eq!(path.bytes(), b"/nix/store/context-path");
    assert_eq!(path.context(), &context);
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
}

#[test]
fn captured_context_free_let_string_thunks_use_free_variable_hashes() {
    let source = r#"let x = "s"; in { a = x == x; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "captured context-free let strings should create a demand node"
    );
}

fn opaque_capture_context(path: &[u8]) -> StringContext {
    StringContext::singleton(
        ContextElement::opaque_path(path.to_vec()).expect("opaque context path is valid"),
    )
    .expect("context allocates")
}

#[test]
fn captured_context_free_string_thunks_use_free_variable_hashes() {
    let source = r#"let f = x: { a = x == "s"; }; in [ (f "s").a (f "t").a ]"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "string-captures.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured string attr force succeeds");
    assert_eq!(first.as_bool(), Ok(true));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured string attr force succeeds");

    assert_eq!(second.as_bool(), Ok(false));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "different captured string values must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different captured strings should create distinct demand nodes"
    );
}

#[test]
fn captured_context_free_string_thunks_hit_when_hashes_match() {
    let source = r#"let f = x: { a = x == "s"; }; in { a = (f "s").a; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "string-captures.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured string force succeeds");
        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching captured string hashes should share one demand node"
    );
}

#[test]
fn captured_path_thunks_use_free_variable_hashes() {
    let source = r#"let f = x: { a = x == /tmp/a; }; in [ (f /tmp/a).a (f /tmp/b).a ]"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "path-captures.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured path attr force succeeds");
    assert_eq!(first.as_bool(), Ok(true));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured path attr force succeeds");

    assert_eq!(second.as_bool(), Ok(false));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "different captured path values must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different captured paths should create distinct demand nodes"
    );
}

#[test]
fn captured_path_thunks_hit_when_hashes_match() {
    let source = r#"let f = x: { a = x == /tmp/a; }; in { a = (f /tmp/a).a; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "path-captures.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured path force succeeds");
        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching captured path hashes should share one demand node"
    );
}

#[test]
fn captured_string_and_path_values_do_not_share_free_variable_hashes() {
    let source = r#"let f = x: { a = x == x; }; in [ (f "/tmp/a").a (f /tmp/a).a ]"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "string-path-captures.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("captured string attr force succeeds");
    assert_eq!(first.as_bool(), Ok(true));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("captured path attr force succeeds");

    assert_eq!(second.as_bool(), Ok(true));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "captured strings and paths with identical bytes must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "captured string and path values should create distinct demand nodes"
    );
}

#[test]
fn captured_unsupported_heap_values_wait_for_canonical_value_hashes() {
    let source = "let f = x: { a = builtins.length x == 1; }; in { a = (f [ (1 / 0) ]).a; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "unsupported-captures.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured unsupported heap value force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "captured lazy-element lists need element payloads before observation"
    );
}

#[test]
fn captured_suspended_computed_thunks_do_not_build_force_cache_subjects() {
    let source = "let x = 1 + 2; in { a = x == 3; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-suspended-computed.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let captured_x = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let env = thunk.env().expect("a captures x");
        env.frames()[0].get(0).expect("x capture exists")
    };
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture is a thunk");
    assert_eq!(x_thunk.cell().state(), Ok(ThunkState::Suspended));

    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "captured suspended computed thunks must not be hashed into demand keys"
    );
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture remains a thunk");
    assert_eq!(
        x_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "probing the captured force-cache subject must not force captured thunks"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured suspended computed force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "subjects with captured suspended computed thunks wait for canonical value hashes"
    );
}

#[test]
fn dynamic_with_scoped_thunks_do_not_build_force_cache_subjects() {
    let source = "with { x = 1; }; { a = x + 2; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "with-scoped-force-cache.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        assert!(
            !thunk
                .with_scope_env()
                .expect("a captures dynamic with scopes")
                .scopes()
                .is_empty(),
            "fixture must exercise a captured dynamic with scope"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "dynamic with-scoped thunks must not be hashed into demand keys"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("with-scoped attr force succeeds");

    assert_eq!(forced.as_int(), Ok(3));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "with-scoped thunk subjects should skip expression node allocation"
    );
}

#[test]
fn scoped_import_global_thunks_do_not_build_force_cache_subjects() {
    let root = fs::canonicalize(unique_temp_dir("force-cache-scoped-import-subject"))
        .expect("temp directory canonicalizes");
    fs::write(root.join("scoped.nix"), b"{ a = x + 1; }").expect("scoped import source writes");
    let source = "builtins.scopedImport { x = 2; } ./scoped.nix";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(path_bytes(&root))
        .expect("path base configures");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        options,
        "scoped-import-force-cache.nix",
        source,
        cache.clone(),
    );
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let imported = evaluator.eval_root().expect("scoped import evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(imported)
            .expect("import result is an attrset");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        assert!(
            !thunk
                .scoped_global_env()
                .expect("a captures scoped-import globals")
                .scopes()
                .is_empty(),
            "fixture must exercise scoped-import globals"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "scoped-import global thunks must not be hashed into demand keys"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("scoped-import attr force succeeds");

    assert_eq!(forced.as_int(), Ok(3));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "scoped-import global thunk subjects should skip expression node allocation"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn captured_empty_lists_use_free_variable_hashes() {
    let source = "let f = x: { a = x == x; }; in { a = (f []).a; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "empty-list-captures.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured empty list force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        !runtime.cache().expect("cache is enabled").is_empty(),
        "captured empty lists should create a demand node"
    );
}

#[test]
fn captured_replayable_lists_hit_when_hashes_match() {
    let source = "let f = x: { a = x == x; }; in { a = (f [ 1 true null ]).a; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "list-captures.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured list force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }
}

#[test]
fn captured_free_variable_thunks_admit_on_first_raw_force() {
    let source = r#"let f = x: { a = x == "value"; }; in { a = (f "value").a; }"#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-first-demand.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };

    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured attr force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    assert_eq!(
        evaluator.stats().force_cache_memoization_bypasses(),
        0,
        "captured free-variable subjects should not need helper pre-admission"
    );
    assert!(
        evaluator.stats().force_cache_memoization_admits() > 0,
        "captured free-variable subjects should admit on first raw force"
    );
    assert!(
        evaluator.stats().force_cache_misses() > 0,
        "first raw force should probe and populate the selected captured subject"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        !runtime.cache().expect("cache is enabled").is_empty(),
        "first raw force should allocate a captured expression node"
    );
}

#[test]
fn closed_composite_literal_thunks_admit_on_first_raw_force() {
    let source = "{ a = [ 1 true null ]; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "composite-first-demand.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };

    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("composite literal force succeeds");

    assert_eq!(
        evaluator
            .heap()
            .get_list(forced)
            .expect("forced value is a list")
            .len(),
        3
    );
    assert_eq!(evaluator.stats().force_cache_memoization_bypasses(), 0);
    assert_eq!(
        evaluator.stats().force_cache_memoization_admits(),
        1,
        "closed replayable composite literals should admit on first raw force"
    );
    assert_eq!(evaluator.stats().force_cache_misses(), 1);
    assert_eq!(evaluator.stats().force_cache_probes(), 1);
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "first raw force should allocate the closed composite expression node"
    );
}

#[test]
fn captured_replayable_lists_miss_when_hashes_differ() {
    let source = r#"
let f = x: { a = builtins.elemAt x 0 == 1; };
in [ (f [ 1 ]).a (f [ 2 ]).a ]
"#;
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "list-captures.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured list attr force succeeds");
    assert_eq!(first.as_bool(), Ok(true));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured list attr force succeeds");

    assert_eq!(second.as_bool(), Ok(false));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "different captured list values must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").len() >= 2,
        "different captured lists should create distinct demand nodes"
    );
}

#[test]
fn captured_empty_attrsets_use_free_variable_hashes() {
    let source = "let f = x: { a = x == x; }; in { a = (f {}).a; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "empty-attrs-captures.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured empty attrset force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        !runtime.cache().expect("cache is enabled").is_empty(),
        "captured empty attrsets should create a demand node"
    );
}

#[test]
fn materialized_replayable_attrset_capture_hashes_key_runtime_payloads() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        DurableBlake3Hash::for_bytes(b"force-captured-attrs-result"),
        IrId::new(17),
    );
    let subject_for = |hash| ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: vec![hash],
        memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let a = first.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(1))], &first.symbols)
        .expect("attrs build");
    let attrs = first.heap.alloc_attrs(0, attrs).expect("attrs allocate");
    let first_hash = first
        .force_cache_free_var_value_hash(attrs)
        .expect("replayable attrset hashes");
    first.observe_forced_inline_expression_result(
        Some(subject_for(first_hash)),
        Value::bool(true),
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );
    drop(first);

    let mut second =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let a = second.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(1))], &second.symbols)
        .expect("attrs build");
    let attrs = second.heap.alloc_attrs(0, attrs).expect("attrs allocate");
    let same_hash = second
        .force_cache_free_var_value_hash(attrs)
        .expect("matching replayable attrset hashes");
    assert_eq!(same_hash, first_hash);
    let hit = second
        .lookup_forced_inline_expression_result(Some(subject_for(same_hash)))
        .expect("matching captured attrset hash hits");
    assert_eq!(hit.as_bool(), Ok(true));
    assert_eq!(second.stats().cache_hits(), 1);
    drop(second);

    let mut changed = TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache);
    let a = changed.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(2))], &changed.symbols)
        .expect("attrs build");
    let attrs = changed.heap.alloc_attrs(0, attrs).expect("attrs allocate");
    let changed_hash = changed
        .force_cache_free_var_value_hash(attrs)
        .expect("changed replayable attrset hashes");
    assert_ne!(changed_hash, first_hash);
    assert!(
        changed
            .lookup_forced_inline_expression_result(Some(subject_for(changed_hash)))
            .is_none(),
        "different captured attrset hashes must miss"
    );
}

#[test]
fn materialized_empty_attrsets_are_free_variable_hashable() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let attrs = evaluator
        .heap
        .alloc_attrs(0, FlatAttrs::empty())
        .expect("empty attrset allocates");

    assert!(evaluator.force_cache_free_var_value_hash(attrs).is_some());
}

#[test]
fn materialized_non_empty_attrsets_are_free_variable_hashable() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(a, Value::int(1))], &evaluator.symbols)
        .expect("attrs build");
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrset allocates");

    assert!(evaluator.force_cache_free_var_value_hash(attrs).is_some());
}

#[test]
fn materialized_position_bearing_attrsets_are_not_free_variable_hashable_yet() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            a,
            Value::int(1),
            AttrPosition::new(0, Span::new(0, 1)),
        )],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrset allocates");

    assert_eq!(evaluator.force_cache_free_var_value_hash(attrs), None);
}

#[test]
fn materialized_source_order_attrsets_are_not_free_variable_hashable_yet() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let b = evaluator.symbols.intern(b"b").expect("b interns");
    let c = evaluator.symbols.intern(b"c").expect("c interns");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(c, Value::int(2)),
            AttrEntry::new(b, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    assert_ne!(attrs.source_order(), attrs.iteration_order());
    let attrs = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrset allocates");

    assert_eq!(evaluator.force_cache_free_var_value_hash(attrs), None);
}

#[test]
fn materialized_non_empty_lists_are_free_variable_hashable() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let list = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("list allocates");

    assert!(evaluator.force_cache_free_var_value_hash(list).is_some());
}

#[test]
fn suspended_computed_thunk_cells_are_not_free_variable_hashable() {
    let ir = lower("{ a = 1 + 2; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is a thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));

    assert_eq!(evaluator.force_cache_free_var_value_hash(thunk_value), None);
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is still a thunk");
    assert_eq!(
        thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "hashing a captured suspended thunk cell must not force it"
    );
}

#[test]
fn suspended_closed_literal_thunk_cells_are_free_variable_hashable_without_forcing() {
    let ir = lower("{ a = [ 1 true null ]; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is a thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));

    assert!(
        evaluator
            .force_cache_free_var_value_hash(thunk_value)
            .is_some()
    );
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is still a thunk");
    assert_eq!(
        thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "hashing a suspended closed literal thunk cell must not force it"
    );
}

#[test]
fn fulfilled_thunk_cells_use_cached_free_variable_hashes() {
    let ir = lower("{ a = 1 + 2; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    assert_eq!(forced.as_int(), Ok(3));

    assert_eq!(
        evaluator.force_cache_free_var_value_hash(thunk_value),
        evaluator.force_cache_free_var_value_hash(forced)
    );
}

#[test]
fn fulfilled_replayable_attrset_thunk_cells_use_cached_free_variable_hashes() {
    let ir = lower(r#"{ a = builtins.fromJSON ''{"a":1,"b":[true,null]}''; }"#);
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    assert_eq!(forced.tag(), ValueTag::Attrs);

    assert_eq!(
        evaluator
            .force_cache_free_var_value_hash(thunk_value)
            .expect("fulfilled attrset thunk cell hashes"),
        evaluator
            .force_cache_free_var_value_hash(forced)
            .expect("forced replayable attrset hashes")
    );
}

#[test]
fn materialized_context_bearing_string_captures_use_canonical_free_variable_hashes() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let source =
        ContextElement::opaque_path(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec())
            .expect("opaque context builds");
    let output = ContextElement::single_output(
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg.drv".to_vec(),
        b"out".to_vec(),
    )
    .expect("output context builds");
    let first_context = StringContext::new(vec![output.clone(), source.clone(), output.clone()]);
    let same_context = StringContext::new(vec![source, output]);
    let different_context =
        opaque_capture_context(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-other");
    let first = evaluator
        .heap
        .alloc_string(NixString::new(b"s".to_vec(), first_context))
        .expect("first context string allocates");
    let same = evaluator
        .heap
        .alloc_string(NixString::new(b"s".to_vec(), same_context))
        .expect("same context string allocates");
    let different = evaluator
        .heap
        .alloc_string(NixString::new(b"s".to_vec(), different_context))
        .expect("different context string allocates");
    let context_free = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"s".to_vec()))
        .expect("context-free string allocates");
    let hash = evaluator
        .force_cache_free_var_value_hash(first)
        .expect("context-bearing string hashes");

    assert_eq!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(same)
            .expect("same context-bearing string hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(different)
            .expect("different context-bearing string hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(context_free)
            .expect("context-free string hashes")
    );
}

#[test]
fn materialized_context_bearing_path_captures_use_canonical_free_variable_hashes() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let context = opaque_capture_context(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source");
    let different_context =
        opaque_capture_context(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-other");
    let first = evaluator
        .heap
        .alloc_path(NixString::new(b"/tmp/seed".to_vec(), context.clone()))
        .expect("first context path allocates");
    let same = evaluator
        .heap
        .alloc_path(NixString::new(b"/tmp/seed".to_vec(), context.clone()))
        .expect("same context path allocates");
    let different = evaluator
        .heap
        .alloc_path(NixString::new(b"/tmp/seed".to_vec(), different_context))
        .expect("different context path allocates");
    let context_free = evaluator
        .heap
        .alloc_path(NixString::from_bytes(b"/tmp/seed".to_vec()))
        .expect("context-free path allocates");
    let context_string = evaluator
        .heap
        .alloc_string(NixString::new(b"/tmp/seed".to_vec(), context))
        .expect("context string allocates");
    let hash = evaluator
        .force_cache_free_var_value_hash(first)
        .expect("context-bearing path hashes");

    assert_eq!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(same)
            .expect("same context-bearing path hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(different)
            .expect("different context-bearing path hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(context_free)
            .expect("context-free path hashes")
    );
    assert_ne!(
        hash,
        evaluator
            .force_cache_free_var_value_hash(context_string)
            .expect("context-bearing string hashes")
    );
}

#[test]
fn captured_preforced_computed_context_bearing_string_thunks_use_materialized_capture_keys() {
    let source = r#"
      let s = builtins.appendContext "s" {
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source" = { path = true; };
      };
      in builtins.seq s { a = s == s; }
    "#;
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "context-string-captures.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let hits_before = evaluator.stats().cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("captured context-bearing string force succeeds");

        assert_eq!(forced.as_bool(), Ok(true));
        assert_eq!(
            evaluator.stats().cache_hits() > hits_before,
            expected_hit,
            "captured preforced context-bearing strings should hash through the fulfilled thunk cell"
        );
    }
}

#[test]
fn lowered_captured_inline_forced_thunks_use_free_variable_hashes() {
    let source = "let f = x: { a = x + 2; }; in [ (f 1).a (f 5).a ]";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "lambda.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured attr force succeeds");
    assert_eq!(first.as_int(), Ok(3));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured attr force succeeds");

    assert_eq!(second.as_int(), Ok(7));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "same lowered attr body with different lambda arguments must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different inline lambda arguments should create distinct demand nodes"
    );
}

#[test]
fn source_less_lowered_captured_inline_forced_thunks_use_free_variable_hashes() {
    let source = "let f = x: { a = x + 2; }; in [ (f 1).a (f 5).a ]";
    let ir = lower(source);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let root = evaluator.eval_root().expect("list evaluates");
    let elements = {
        let list = evaluator
            .heap()
            .get_list(root)
            .expect("root list is heap-owned");
        [
            list.get(0).expect("first result exists"),
            list.get(1).expect("second result exists"),
        ]
    };

    let first = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[0])
        .expect("first captured attr force succeeds");
    assert_eq!(first.as_int(), Ok(3));
    let second = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), elements[1])
        .expect("second captured attr force succeeds");

    assert_eq!(second.as_int(), Ok(7));
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "source-less lowered attr bodies with different lambda arguments must not cache hit"
    );
    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different source-less inline lambda arguments should create distinct demand nodes"
    );
}

fn manual_inline_capture_force_ir(captured: i64) -> Ir {
    let mut symbols = SymbolTable::new();
    let x = symbols.intern(b"x").expect("symbol interns");
    let frame = FrameId::new(0);
    Ir {
        root: IrId::new(5),
        arena: IrArena::from_raw_parts(
            vec![
                pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(captured)),
                pure_node(
                    IrKind::LocalVar,
                    Span::new(18, 19),
                    IrData::Local { slot: 0 },
                ),
                pure_node(IrKind::Int, Span::new(22, 23), IrData::Int(2)),
                pure_node(
                    IrKind::BinOp,
                    Span::new(18, 23),
                    IrData::Binary {
                        op: BinOpKind::Add,
                        lhs: IrId::new(1),
                        rhs: IrId::new(2),
                    },
                ),
                pure_node(
                    IrKind::ThunkAlloc,
                    Span::new(18, 23),
                    IrData::Node(IrId::new(3)),
                ),
                pure_node(
                    IrKind::Let,
                    Span::new(0, 23),
                    IrData::Let {
                        bindings: IrBindingSlice::new(0, 1),
                        body: IrId::new(4),
                        frame: Some(frame),
                    },
                ),
            ],
            Vec::new(),
        ),
        symbols,
        frames: vec![FrameInfo {
            slot_count: 1,
            captures: Vec::new().into_boxed_slice(),
            rec: false,
            has_with: false,
        }]
        .into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: vec![IrBinding {
            key: IrAttrPathSegment::Static(x),
            position: None,
            value: IrId::new(0),
        }]
        .into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    }
}

#[test]
fn captured_inline_forced_thunks_hit_when_free_variable_hashes_match() {
    let source = "let x = <inline>; in x + 2";
    let ir = manual_inline_capture_force_ir(1);
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "manual.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("manual let yields a thunk");
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 23), root)
            .expect("manual captured thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        1,
        "matching inline free-variable hashes should share one demand node"
    );
}

#[test]
fn captured_inline_forced_thunks_include_free_variable_hashes_in_cache_key() {
    let source = "let x = <inline>; in x + 2";
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    for (captured, expected) in [(1, 3), (5, 7)] {
        let ir = manual_inline_capture_force_ir(captured);
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "manual.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("manual let yields a thunk");
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 23), root)
            .expect("manual captured thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(expected));
        assert_eq!(
            evaluator.stats().cache_hits(),
            0,
            "changed inline free-variable values must not hit an old demand node"
        );
    }

    let runtime = cache.lock().expect("cache lock is valid");
    assert_eq!(
        runtime.cache().expect("cache is enabled").len(),
        2,
        "different inline free-variable hashes should create distinct demand nodes"
    );
}
