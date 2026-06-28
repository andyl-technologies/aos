//! Tree-walk evaluator tests: attrs 2.

use super::*;

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

fn first_thunk_alloc_id(ir: &Ir) -> IrId {
    ir.arena
        .nodes()
        .iter()
        .position(|node| node.kind == IrKind::ThunkAlloc)
        .map(|index| IrId::new(u32::try_from(index).expect("test IR node id fits in u32")))
        .expect("test IR contains a thunk allocation")
}

fn first_inherit_select_thunk_alloc_id(ir: &Ir) -> IrId {
    ir.arena
        .nodes()
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            let IrData::Node(body) = node.data else {
                return None;
            };
            let body = ir.arena.node(body)?;
            (node.kind == IrKind::ThunkAlloc && body.kind == IrKind::Select)
                .then(|| IrId::new(u32::try_from(index).expect("test IR node id fits in u32")))
        })
        .expect("test IR contains an inherited select thunk")
}

fn mark_all_thunk_allocs_strict(ir: &mut Ir) {
    let thunk_ids: Vec<IrId> = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            (node.kind == IrKind::ThunkAlloc)
                .then(|| IrId::new(u32::try_from(index).expect("test IR node id fits in u32")))
        })
        .collect();
    for id in thunk_ids {
        *ir.facts.get_mut(id).expect("thunk fact exists") = crate::compile::ExprFacts {
            strictness: crate::compile::Strictness::Strict,
            cardinality: crate::compile::Cardinality::Many,
            escape: crate::compile::Escape::Escapes,
        };
    }
}

#[test]
fn conservative_thunk_alloc_facts_keep_lazy_thunks() {
    let ir = lower("[ (1 + 6) ]");

    let outcome = eval_whnf_owned(&ir).expect("conservative thunk alloc evaluates");
    let element = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("root is a heap-owned list");
        list.get(0).expect("element exists")
    };

    assert_eq!(element.tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.stats().thunks_elided(), 0);
    let thunk = outcome
        .heap()
        .get_thunk(element)
        .expect("element is a heap-owned thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn strict_thunk_alloc_facts_evaluate_eagerly() {
    for (escape, label) in [
        (crate::compile::Escape::Escapes, "eager"),
        (crate::compile::Escape::NoEscape, "scalar"),
    ] {
        let mut ir = lower("[ (1 + 6) ]");
        let thunk_alloc = first_thunk_alloc_id(&ir);
        *ir.facts.get_mut(thunk_alloc).expect("thunk fact exists") = crate::compile::ExprFacts {
            strictness: crate::compile::Strictness::Strict,
            cardinality: crate::compile::Cardinality::Many,
            escape,
        };

        let outcome = eval_whnf_owned(&ir).expect("strict thunk alloc evaluates");
        let element = {
            let list = outcome
                .heap()
                .get_list(outcome.value())
                .expect("root is a heap-owned list");
            list.get(0).expect("element exists")
        };

        assert_eq!(element.as_int(), Ok(7), "{label}");
        assert_eq!(outcome.stats().thunks_allocated(), 0, "{label}");
        assert_eq!(outcome.stats().thunks_elided(), 1, "{label}");
    }
}

#[test]
fn strict_attr_binding_facts_do_not_preempt_dynamic_attr_name_errors() {
    let mut ir = lower(r#"({ a = builtins.throw "value"; ${builtins.throw "key"} = 1; }).a"#);
    mark_all_thunk_allocs_strict(&mut ir);

    let error = eval_whnf_owned(&ir).expect_err("dynamic key error wins");

    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown dynamic key error");
    };
    assert_eq!(message, b"key");
}

#[test]
fn strict_thunk_alloc_facts_do_not_elide_during_let_frame_initialization() {
    let mut ir = lower("let x = y; y = 7; in x");
    mark_all_thunk_allocs_strict(&mut ir);

    let outcome = eval_whnf_owned(&ir).expect("forward let reference evaluates");

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert_eq!(outcome.stats().thunks_elided(), 0);
}

#[test]
fn strict_thunk_alloc_facts_do_not_elide_during_recursive_attr_frame_initialization() {
    let mut ir = lower("(rec { a = b; b = 7; }).a");
    mark_all_thunk_allocs_strict(&mut ir);

    let outcome = eval_whnf_owned(&ir).expect("forward rec attr reference evaluates");

    assert_eq!(outcome.value().as_int(), Ok(7));
}

#[test]
fn strict_thunk_alloc_facts_do_not_elide_during_formal_default_initialization() {
    let mut ir = lower("({ a ? b, b }: a) { b = 2; }");
    mark_all_thunk_allocs_strict(&mut ir);

    let outcome = eval_whnf_owned(&ir).expect("forward formal default evaluates");

    assert_eq!(outcome.value().as_int(), Ok(2));
}

#[test]
fn strict_inherited_select_binding_facts_stay_lazy_during_attrset_assembly() {
    let mut ir = lower("{ inherit ({ a = 1 + 6; }) a; }");
    let a = symbol_for(&ir, b"a");
    let inherited_select = first_inherit_select_thunk_alloc_id(&ir);
    *ir.facts
        .get_mut(inherited_select)
        .expect("inherited select fact exists") = crate::compile::ExprFacts {
        strictness: crate::compile::Strictness::Strict,
        cardinality: crate::compile::Cardinality::Many,
        escape: crate::compile::Escape::Escapes,
    };

    let outcome = eval_whnf_owned(&ir).expect("strict inherited select evaluates");
    let attr_value = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root is a heap-owned attrset");
        attrs.get(a).expect("a exists")
    };

    assert_eq!(attr_value.tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_elided(), 0);
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
