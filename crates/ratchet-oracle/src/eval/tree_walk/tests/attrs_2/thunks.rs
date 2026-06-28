//! Thunk and strictness tests for tree-walk attr evaluation.

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
fn strictness_analysis_elides_direct_lambda_argument_thunk() {
    let mut ir = lower("(x: x + 1) (1 + 2)");
    crate::compile::annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    let outcome = eval_whnf_owned(&ir).expect("annotated direct lambda evaluates");

    assert_eq!(outcome.value().as_int(), Ok(4));
    assert_eq!(outcome.stats().thunks_allocated(), 0);
    assert_eq!(outcome.stats().thunks_elided(), 1);
}

#[test]
fn strictness_analysis_keeps_foldl_empty_initial_accumulator_lazy() {
    let mut ir = lower(r#"builtins.foldl' (acc: x: acc + x) (builtins.throw "initial") []"#);
    crate::compile::annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    let outcome = eval_whnf_owned(&ir).expect("annotated empty foldl' evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.stats().thunks_elided(), 0);
}

#[test]
fn strictness_analysis_preserves_unreached_dynamic_attr_path_ordering() {
    let mut select_ir = lower("({}).${\"a\"}.${1 / 0} or 2");
    crate::compile::annotate_strictness(&mut select_ir).expect("strictness analysis succeeds");
    let select = eval_whnf_owned(&select_ir).expect("unreached dynamic select key stays lazy");
    assert_eq!(select.value().as_int(), Ok(2));

    let mut has_attr_ir = lower("({} ? missing.${1 / 0})");
    crate::compile::annotate_strictness(&mut has_attr_ir).expect("strictness analysis succeeds");
    let has_attr = eval_whnf_owned(&has_attr_ir).expect("unreached dynamic hasAttr key stays lazy");
    assert_eq!(has_attr.value().as_bool(), Ok(false));
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
