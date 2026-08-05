//! Strictness analysis tests.

use super::*;

#[test]
fn strictness_rejects_fact_table_length_mismatches() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let mut overlong = Ir {
        root: IrId::new(0),
        arena: arena.clone(),
        facts: IrFacts::conservative(2),
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    overlong
        .facts
        .get_mut(IrId::new(1))
        .expect("stale fact exists")
        .strictness = Strictness::DemandedBeforeEffect;

    let error = annotate_strictness(&mut overlong).expect_err("overlong fact table rejects");

    assert_eq!(
        error,
        StrictnessAnalysisError::InvalidFactTableLength {
            expected: 1,
            actual: 2,
        }
    );
    assert_eq!(
        strictness(&overlong, IrId::new(1)),
        Strictness::DemandedBeforeEffect
    );

    let mut short = Ir {
        root: IrId::new(0),
        arena,
        facts: IrFacts::conservative(0),
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = annotate_strictness(&mut short).expect_err("short fact table rejects");

    assert_eq!(
        error,
        StrictnessAnalysisError::InvalidFactTableLength {
            expected: 1,
            actual: 0,
        }
    );
}

#[test]
fn strictness_rejects_malformed_payloads_before_marking_facts() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Null,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::None,
            ),
        ],
        Vec::new(),
    );
    let mut ir = Ir {
        root: IrId::new(0),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = annotate_strictness(&mut ir).expect_err("invalid payload rejects");

    assert!(matches!(
        error,
        StrictnessAnalysisError::InvalidPayload {
            id,
            kind: IrKind::LocalVar,
            expected: "local slot payload",
        } if id == IrId::new(1)
    ));
    assert_eq!(strictness(&ir, ir.root), Strictness::Unknown);
}

#[test]
fn strictness_marks_root_and_guaranteed_strict_children_only() {
    let ir = annotate("if 1 == 1 then [ (1 / 0) ] else 0");
    let root = ir.root;
    assert_eq!(strictness(&ir, root), Strictness::DemandedBeforeEffect);
    let IrData::Triple {
        first: condition,
        second: then_branch,
        third: else_branch,
    } = node(&ir, root).data
    else {
        panic!("if payload expected");
    };

    assert_eq!(strictness(&ir, condition), Strictness::DemandedBeforeEffect);
    // Per-execution semantics: a branch is only evaluated on its own path,
    // and when it is, the `if`'s consumer forces its value immediately, so
    // the branch inherits the root's forced position.
    assert_eq!(
        strictness(&ir, then_branch),
        Strictness::DemandedBeforeEffect
    );
    assert_eq!(
        strictness(&ir, else_branch),
        Strictness::DemandedBeforeEffect
    );

    // Lazy list elements stay unproven under WHNF list demand.
    let elements = list_elements(&ir, then_branch);
    assert_eq!(strictness(&ir, elements[0]), Strictness::Unknown);
}

#[test]
fn strictness_keeps_lazy_list_elements_unknown_under_whnf_list_demand() {
    let ir = annotate("builtins.length [ (1 / 0) ]");
    let args = primop_args(&ir, ir.root);
    let list = args[0];
    assert_eq!(strictness(&ir, list), Strictness::DemandedBeforeEffect);

    let elements = list_elements(&ir, list);
    assert_eq!(node(&ir, elements[0]).kind, IrKind::ThunkAlloc);
    assert_eq!(strictness(&ir, elements[0]), Strictness::Unknown);
}

#[test]
fn strictness_skips_higher_order_callbacks_that_empty_inputs_can_avoid() {
    let map_ir = annotate("builtins.map (builtins.throw \"function\") []");
    let map_args = primop_args(&map_ir, map_ir.root);
    assert_eq!(strictness(&map_ir, map_args[0]), Strictness::Unknown);
    assert_eq!(
        strictness(&map_ir, map_args[1]),
        Strictness::DemandedBeforeEffect
    );

    let sort_ir = annotate("builtins.sort (builtins.throw \"comparator\") []");
    let sort_args = primop_args(&sort_ir, sort_ir.root);
    assert_eq!(strictness(&sort_ir, sort_args[0]), Strictness::Unknown);
    assert_eq!(
        strictness(&sort_ir, sort_args[1]),
        Strictness::DemandedBeforeEffect
    );
}

#[test]
fn strictness_keeps_option_dependent_trace_verbose_message_unknown() {
    let trace_ir = annotate("builtins.trace (builtins.throw \"message\") 1");
    let trace_args = primop_args(&trace_ir, trace_ir.root);
    assert_eq!(
        strictness(&trace_ir, trace_args[0]),
        Strictness::DemandedBeforeEffect
    );
    // The value position is trace's own result: at this root call the
    // consumer forces it right after trace returns, so the position
    // inherits the call's forced position. The trace output stays ordered
    // because the value is evaluated only after the message is emitted.
    assert_eq!(
        strictness(&trace_ir, trace_args[1]),
        Strictness::DemandedBeforeEffect
    );

    let verbose_ir = annotate("builtins.traceVerbose (builtins.throw \"message\") 1");
    let verbose_args = primop_args(&verbose_ir, verbose_ir.root);
    // The verbose message is only forced when verbose tracing is enabled.
    assert_eq!(
        strictness(&verbose_ir, verbose_args[0]),
        Strictness::Unknown
    );
    assert_eq!(
        strictness(&verbose_ir, verbose_args[1]),
        Strictness::DemandedBeforeEffect
    );
}

#[test]
fn strictness_keeps_foldl_empty_initial_accumulator_lazy() {
    let ir = annotate("builtins.foldl' (builtins.throw \"op\") (builtins.throw \"initial\") []");
    let args = primop_args(&ir, ir.root);

    assert_eq!(strictness(&ir, args[0]), Strictness::DemandedBeforeEffect);
    assert_eq!(strictness(&ir, args[1]), Strictness::Unknown);
    assert_eq!(strictness(&ir, args[2]), Strictness::DemandedBeforeEffect);
}

#[test]
fn strictness_does_not_mark_assert_body_as_unconditionally_demanded() {
    let ir = annotate("assert false; builtins.throw \"body\"");
    let IrData::Pair {
        first: condition,
        second: body,
    } = node(&ir, ir.root).data
    else {
        panic!("assert payload expected");
    };

    assert_eq!(strictness(&ir, condition), Strictness::DemandedBeforeEffect);
    // Per-execution semantics: the body only evaluates after the condition
    // held, at which point the assert's consumer forces its value, so the
    // body inherits the root's forced position. A failing assertion never
    // reaches the body at all.
    assert_eq!(strictness(&ir, body), Strictness::DemandedBeforeEffect);
}

#[test]
fn strictness_marks_dynamic_attr_keys_but_not_attr_values() {
    let ir = annotate("({ ${builtins.throw \"key\"} = 1 / 0; }).a");
    let IrData::Select { receiver, .. } = node(&ir, ir.root).data else {
        panic!("select payload expected");
    };
    let IrData::AttrSet { bindings, .. } = node(&ir, receiver).data else {
        panic!("attrset payload expected");
    };
    let binding = ir.bindings[bindings.start as usize];
    let IrAttrPathSegment::Dynamic(key) = binding.key else {
        panic!("dynamic binding key expected");
    };

    assert_eq!(strictness(&ir, key), Strictness::DemandedBeforeEffect);
    assert_eq!(strictness(&ir, binding.value), Strictness::Unknown);
}

#[test]
fn strictness_marks_only_leading_dynamic_select_segments() {
    let leading_ir = annotate(r#"({ a = 1; }).${builtins.throw "key"}"#);
    let IrData::Select {
        path: leading_path, ..
    } = node(&leading_ir, leading_ir.root).data
    else {
        panic!("select payload expected");
    };
    let leading_segments = attr_path_segments(&leading_ir, leading_path);
    let IrAttrPathSegment::Dynamic(leading_key) = leading_segments[0] else {
        panic!("leading dynamic select segment expected");
    };
    assert_eq!(
        strictness(&leading_ir, leading_key),
        Strictness::DemandedBeforeEffect
    );

    let nested_ir = annotate(r#"({ a = {}; }).missing.${builtins.throw "key"}"#);
    let IrData::Select {
        path: nested_path, ..
    } = node(&nested_ir, nested_ir.root).data
    else {
        panic!("select payload expected");
    };
    let nested_segments = attr_path_segments(&nested_ir, nested_path);
    let IrAttrPathSegment::Dynamic(nested_key) = nested_segments[1] else {
        panic!("nested dynamic select segment expected");
    };
    // Per-execution semantics: a nested segment may never be evaluated, but
    // when it is, the lookup forces it in the same instant.
    assert_eq!(
        strictness(&nested_ir, nested_key),
        Strictness::DemandedBeforeEffect
    );
}

#[test]
fn strictness_marks_only_leading_dynamic_has_attr_segments() {
    let leading_ir = annotate(r#"({} ? ${builtins.throw "key"})"#);
    let IrData::HasAttr {
        path: leading_path, ..
    } = node(&leading_ir, leading_ir.root).data
    else {
        panic!("hasAttr payload expected");
    };
    let leading_segments = attr_path_segments(&leading_ir, leading_path);
    let IrAttrPathSegment::Dynamic(leading_key) = leading_segments[0] else {
        panic!("leading dynamic hasAttr segment expected");
    };
    assert_eq!(
        strictness(&leading_ir, leading_key),
        Strictness::DemandedBeforeEffect
    );

    let nested_ir = annotate(r#"({} ? missing.${builtins.throw "key"})"#);
    let IrData::HasAttr {
        path: nested_path, ..
    } = node(&nested_ir, nested_ir.root).data
    else {
        panic!("hasAttr payload expected");
    };
    let nested_segments = attr_path_segments(&nested_ir, nested_path);
    let IrAttrPathSegment::Dynamic(nested_key) = nested_segments[1] else {
        panic!("nested dynamic hasAttr segment expected");
    };
    // Per-execution semantics: forced in the same instant it is evaluated.
    assert_eq!(
        strictness(&nested_ir, nested_key),
        Strictness::DemandedBeforeEffect
    );
}

#[test]
fn strictness_marks_direct_lambda_argument_thunk_when_body_demands_parameter() {
    let mut ir = lowered("(x: x + 1) (1 + 2)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, argument).kind, IrKind::ThunkAlloc);

    let report = annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    assert!(report.nodes_marked_strict > 0);
    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
}

#[test]
fn strictness_marks_direct_formal_set_lambda_argument_for_pattern_matching() {
    let mut ir = lowered("({ a }: 1) { a = 1 / 0; }");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, argument).kind, IrKind::ThunkAlloc);

    annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
}

fn raw_direct_formal_set_lambda_ir(
    formal_symbol: crate::syntax::Symbol,
    symbols: SymbolTable,
    frame: Option<FrameId>,
    frames: Box<[FrameInfo]>,
) -> (Ir, IrId, IrId, IrId) {
    let formal_set = IrId::new(0);
    let formal = IrId::new(1);
    let body = IrId::new(2);
    let lambda = IrId::new(3);
    let argument = IrId::new(4);
    let root = IrId::new(5);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::FormalSet,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::FormalSet {
                    formals: IrChildSlice::new(0, 1),
                    ellipsis: false,
                    alias: None,
                },
            ),
            IrNode::new(
                IrKind::Formal,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Formal {
                    name: formal_symbol,
                    default: None,
                },
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(8, 9),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Lambda,
                Span::new(0, 10),
                EffectClass::pure(),
                IrData::Lambda {
                    pattern: formal_set,
                    body,
                    frame,
                },
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(11, 12),
                EffectClass::pure(),
                IrData::Int(2),
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 12),
                EffectClass::pure(),
                IrData::Pair {
                    first: lambda,
                    second: argument,
                },
            ),
        ],
        vec![formal],
    );
    (
        Ir {
            root,
            facts: IrFacts::conservative(arena.nodes().len()),
            arena,
            symbols,
            frames,
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        },
        formal,
        lambda,
        argument,
    )
}

#[test]
fn strictness_rejects_invalid_formal_set_symbol_before_marking_argument() {
    let invalid_symbol = crate::syntax::Symbol::new(99);
    let (mut ir, formal, _, argument) = raw_direct_formal_set_lambda_ir(
        invalid_symbol,
        SymbolTable::new(),
        Some(FrameId::new(0)),
        Box::new([FrameInfo {
            slot_count: 1,
            captures: Box::new([]),
            rec: false,
            has_with: false,
        }]),
    );

    let error = annotate_strictness(&mut ir).expect_err("invalid formal symbol rejects");

    assert_eq!(
        error,
        StrictnessAnalysisError::InvalidSymbol {
            id: formal,
            symbol: invalid_symbol,
        }
    );
    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_keeps_formal_set_argument_unknown_on_frame_slot_mismatch() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"a").expect("test symbol interns");
    let (mut ir, _, _, argument) = raw_direct_formal_set_lambda_ir(
        symbol,
        symbols,
        Some(FrameId::new(0)),
        Box::new([FrameInfo {
            slot_count: 0,
            captures: Box::new([]),
            rec: false,
            has_with: false,
        }]),
    );

    annotate_strictness(&mut ir).expect("slot mismatch keeps demand conservative");

    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_rejects_invalid_formal_set_frame_before_marking_argument() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"a").expect("test symbol interns");
    let invalid_frame = FrameId::new(1);
    let (mut ir, _, lambda, argument) = raw_direct_formal_set_lambda_ir(
        symbol,
        symbols,
        Some(invalid_frame),
        Box::new([FrameInfo {
            slot_count: 1,
            captures: Box::new([]),
            rec: false,
            has_with: false,
        }]),
    );

    let error = annotate_strictness(&mut ir).expect_err("invalid formal-set frame rejects");

    assert_eq!(
        error,
        StrictnessAnalysisError::InvalidFrame {
            id: lambda,
            frame: invalid_frame,
        }
    );
    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_marks_direct_lambda_argument_through_intervening_frame() {
    let mut ir = lowered("(x: let y = 1; in x + y) (1 + 2)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
}

#[test]
fn strictness_marks_direct_lambda_argument_in_recursive_dynamic_key() {
    let mut ir = lowered(r#"(x: rec { ${x} = 1; }) (builtins.throw "key")"#);
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    annotate_strictness(&mut ir).expect("strictness analysis succeeds");

    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
}

#[test]
fn strictness_keeps_direct_lambda_argument_lazy_when_body_ignores_parameter() {
    let ir = annotate("(x: 1) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, argument).kind, IrKind::ThunkAlloc);
    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_keeps_direct_lambda_argument_lazy_across_nested_lambda() {
    let ir = annotate("(x: (y: x + y)) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_respects_nested_lambda_parameter_shadowing() {
    let ir = annotate("(x: (x: x) 1) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_respects_shadowing_frames_in_direct_lambda_probe() {
    let ir = annotate("(x: let x = 1; in x) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };

    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_marks_argument_through_let_bound_lambda_chase() {
    let ir = annotate("let f = x: x + 1; in f (1 / 0)");
    let IrData::Let { body, .. } = node(&ir, ir.root).data else {
        panic!("let payload expected");
    };
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, body).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, argument).kind, IrKind::ThunkAlloc);
    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
}

#[test]
fn strictness_marks_argument_through_select_resolved_lambda_chase() {
    let ir = annotate("let lib = { inc = x: x + 1; }; in lib.inc (1 / 0)");
    let IrData::Let { body, .. } = node(&ir, ir.root).data else {
        panic!("let payload expected");
    };
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, body).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
}

#[test]
fn known_call_targets_follow_lexical_aliases_and_static_selection() {
    for source in [
        "let f = x: x; in f 1",
        "let functions = { f = x: x; }; in functions.f 1",
    ] {
        let ir = lowered(source);
        let targets = analyze_known_call_targets(&ir).expect("known-call analysis succeeds");

        assert_eq!(targets.len(), 1, "{source}");
        assert_eq!(node(&ir, targets[0].apply).kind, IrKind::Apply);
        assert_eq!(node(&ir, targets[0].lambda).kind, IrKind::Lambda);
        let IrData::Pair { first, .. } = node(&ir, targets[0].apply).data else {
            panic!("apply payload expected");
        };
        assert_ne!(
            node(&ir, first).kind,
            IrKind::Lambda,
            "the sparse fact should prove a non-literal callee"
        );
    }
}

#[test]
fn known_call_targets_omit_control_flow_callees() {
    let ir = lowered("(if true then (x: x) else (x: x)) 1");

    let targets = analyze_known_call_targets(&ir).expect("known-call analysis succeeds");

    assert!(targets.is_empty());
}

#[test]
fn closure_flow_propagates_formal_arguments_into_calls() {
    let ir = lowered("(f: f 1) (x: x)");
    let lambdas = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| (node.kind == IrKind::Lambda).then(|| IrId::new(index as u32)))
        .collect::<Vec<_>>();

    let report = analyze_call_target_candidates(&ir).expect("closure-flow analysis succeeds");

    assert_eq!(lambdas.len(), 2);
    assert_eq!(report.calls.len(), 2);
    assert!(
        report
            .calls
            .iter()
            .any(|call| { call.lambdas.as_ref() == [lambdas[0]] && !call.overflow })
    );
    assert!(
        report
            .calls
            .iter()
            .any(|call| { call.lambdas.as_ref() == [lambdas[1]] && !call.overflow })
    );
    assert!(report.activated_call_edges >= 4);
}

#[test]
fn closure_flow_propagates_apply_results_into_outer_calls() {
    let ir = lowered("let id = f: f; in (id (x: x)) 1");
    let argument_lambda = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| (node.kind == IrKind::Lambda).then(|| IrId::new(index as u32)))
        .last()
        .expect("argument lambda exists");

    let report = analyze_call_target_candidates(&ir).expect("closure-flow analysis succeeds");

    assert_eq!(report.calls.len(), 2);
    assert!(
        report
            .calls
            .iter()
            .any(|call| { call.lambdas.as_ref() == [argument_lambda] && !call.overflow })
    );
}

#[test]
fn closure_flow_retains_finite_conditional_target_sets() {
    let ir = lowered("(if true then (x: x) else (y: y)) 1");

    let report = analyze_call_target_candidates(&ir).expect("closure-flow analysis succeeds");

    assert_eq!(report.calls.len(), 1);
    assert_eq!(report.calls[0].lambdas.len(), 2);
    assert!(!report.calls[0].overflow);
}

#[test]
fn strictness_keeps_argument_lazy_through_ignoring_let_bound_lambda() {
    let ir = annotate("let f = x: 7; in f (1 / 0)");
    let IrData::Let { body, .. } = node(&ir, ir.root).data else {
        panic!("let payload expected");
    };
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, body).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_never_propagates_demand_through_try_eval_application() {
    // S4: forcing the argument at the apply would escape the tryEval catch.
    let ir = annotate(r#"(x: builtins.tryEval x) (builtins.throw "boom")"#);
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(node(&ir, argument).kind, IrKind::ThunkAlloc);
    assert_eq!(strictness(&ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_flags_try_eval_argument_barrier_for_relocation_consumers() {
    let ir = annotate(r#"builtins.tryEval (builtins.throw "boom")"#);
    let args = primop_args(&ir, ir.root);
    assert!(ir.facts.try_eval_barrier(args[0]));
    assert!(!ir.facts.try_eval_barrier(ir.root));
}

#[test]
fn strictness_caps_demand_behind_observable_trace_to_demanded() {
    // The parameter is forced only after the trace output is emitted, so
    // eager evaluation at the apply would lose the message ordering.
    let ir = annotate(r#"(x: builtins.trace "m" (x + 1)) (builtins.throw "e")"#);
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(strictness(&ir, argument), Strictness::Demanded);
}

#[test]
fn strictness_meets_demand_across_if_branches() {
    // Demanded in both branches of a total condition: before-effect holds.
    let both_ir = annotate("(x: if true then x + 1 else x - 1) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&both_ir, both_ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(
        strictness(&both_ir, argument),
        Strictness::DemandedBeforeEffect
    );

    // Demanded in only one branch: no proof on every path.
    let one_ir = annotate("(x: if true then x + 1 else 0) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&one_ir, one_ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(strictness(&one_ir, argument), Strictness::Unknown);
}

#[test]
fn strictness_marks_rec_let_forward_reference_bindings_demanded() {
    // The body demands `a`; `a`'s value forces `b` when the slot is used, so
    // both binding values earn the deferred-demand fan-out hint.
    let ir = annotate("let a = b + 1; b = 2; in a");
    let bindings = let_binding_values(&ir, ir.root);
    assert_eq!(strictness(&ir, bindings[0]), Strictness::Demanded);
    assert_eq!(strictness(&ir, bindings[1]), Strictness::Demanded);
}

#[test]
fn strictness_keeps_unused_let_binding_values_unproven() {
    let ir = annotate("let used = 1; dead = 1 / 0; in used + 1");
    let bindings = let_binding_values(&ir, ir.root);
    assert_eq!(strictness(&ir, bindings[0]), Strictness::Demanded);
    assert_eq!(strictness(&ir, bindings[1]), Strictness::Unknown);
}

#[test]
fn strictness_marks_selected_bindings_of_literal_attrset_receivers() {
    // The literal receiver is built (total) and selected in one step, so the
    // selected binding is forced before any effect.
    let ir = annotate("({ a = 1 / 0; b = 1; }).a");
    let IrData::Select { receiver, .. } = node(&ir, ir.root).data else {
        panic!("select payload expected");
    };
    let IrData::AttrSet { bindings, .. } = node(&ir, receiver).data else {
        panic!("attrset payload expected");
    };
    let selected = ir.bindings[bindings.start as usize];
    let unselected = ir.bindings[bindings.start as usize + 1];
    assert_eq!(
        strictness(&ir, selected.value),
        Strictness::DemandedBeforeEffect
    );
    assert_eq!(strictness(&ir, unselected.value), Strictness::Unknown);
}

#[test]
fn strictness_marks_selected_bindings_of_chased_attrset_receivers_demanded() {
    // A variable-chased receiver was constructed earlier, so the deferred
    // window back to its allocation only supports the S1 rank.
    let ir = annotate("let lib = { a = 1 / 0; }; in lib.a");
    let IrData::Let { bindings, .. } = node(&ir, ir.root).data else {
        panic!("let payload expected");
    };
    let lib_value = ir.bindings[bindings.start as usize].value;
    let literal = match node(&ir, lib_value).data {
        IrData::Node(body) => body,
        _ => lib_value,
    };
    let IrData::AttrSet { bindings, .. } = node(&ir, literal).data else {
        panic!("attrset payload expected");
    };
    let selected = ir.bindings[bindings.start as usize];
    assert_eq!(strictness(&ir, selected.value), Strictness::Demanded);
}

#[test]
fn strictness_transfers_result_spine_demand_from_forced_apply_positions() {
    // `x: x` returns its parameter: the argument is forced exactly when the
    // apply's value is, which at this forced root position is immediate.
    let ir = annotate("(x: x) (1 / 0)");
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
}

#[test]
fn strictness_declines_shared_ir_without_marking_facts() {
    // Two parents share one child: per-execution claims are ill-defined, so
    // the analysis declines and leaves every fact conservative.
    let shared = IrId::new(0);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op: crate::syntax::BinOpKind::Add,
                    lhs: shared,
                    rhs: shared,
                },
            ),
        ],
        Vec::new(),
    );
    let mut ir = Ir {
        root: IrId::new(1),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let report = annotate_strictness(&mut ir).expect("shared IR is declined, not rejected");

    assert_eq!(report.nodes_marked_strict, 0);
    assert_eq!(strictness(&ir, IrId::new(0)), Strictness::Unknown);
    assert_eq!(strictness(&ir, IrId::new(1)), Strictness::Unknown);
}

/// Returns `(value, key_bytes)` pairs for a (possibly thunk-wrapped) attrset
/// literal's static bindings, in source order.
fn attrset_binding_values(ir: &Ir, id: IrId) -> Vec<(IrId, Vec<u8>)> {
    let literal = match node(ir, id).data {
        IrData::Node(body) if node(ir, id).kind == IrKind::ThunkAlloc => body,
        _ => id,
    };
    let IrData::AttrSet { bindings, .. } = node(ir, literal).data else {
        panic!("attrset payload expected");
    };
    let start = bindings.start as usize;
    let end = start + bindings.len();
    ir.bindings[start..end]
        .iter()
        .filter_map(|binding| match binding.key {
            IrAttrPathSegment::Static(key) => Some((
                binding.value,
                ir.symbols.resolve(key).expect("key resolves").to_vec(),
            )),
            IrAttrPathSegment::Dynamic(_) => None,
        })
        .collect()
}

fn dialect_node_argument(ir: &Ir, id: IrId) -> IrId {
    let IrData::DialectNode { argument, .. } = node(ir, id).data else {
        panic!("dialect-node payload expected");
    };
    argument
}

fn binding_value(entries: &[(IrId, Vec<u8>)], key: &[u8]) -> IrId {
    entries
        .iter()
        .find(|(_, entry)| entry == key)
        .map(|(value, _)| *value)
        .unwrap_or_else(|| panic!("binding {:?} exists", String::from_utf8_lossy(key)))
}

#[test]
fn strictness_seeds_direct_derivation_strict_literal_bindings() {
    // Force order verified against the serializer: `name` first (nothing can
    // precede its force), then every attribute in sorted order with
    // possibly-effectful processing between forces.
    let ir = annotate_with_derivation_op(
        r#"builtins.derivationStrict {
             name = "d" + "x";
             builder = [ (1 / 0) ];
             src = 1 / 0;
           }"#,
    );
    let entries = attrset_binding_values(&ir, dialect_node_argument(&ir, ir.root));

    // `name` is non-total but first-forced: before-effect demand + license.
    let name = binding_value(&entries, b"name");
    assert_eq!(strictness(&ir, name), Strictness::DemandedBeforeEffect);
    assert!(ir.facts.assembly_eager(name));

    // `builder` is a total list literal: demanded (after possible events)
    // and eager-licensed by totality.
    let builder = binding_value(&entries, b"builder");
    assert_eq!(strictness(&ir, builder), Strictness::Demanded);
    assert!(ir.facts.assembly_eager(builder));

    // `src` is non-total and not first-forced: demanded only, kept lazy.
    let src = binding_value(&entries, b"src");
    assert_eq!(strictness(&ir, src), Strictness::Demanded);
    assert!(!ir.facts.assembly_eager(src));
}

#[test]
fn strictness_declines_recursive_derivation_strict_literals() {
    // Eager evaluation inside a recursive frame could read slots that are
    // not yet initialized, so recursive literals fail closed.
    let ir = annotate_with_derivation_op(
        r#"builtins.derivationStrict (rec {
             name = "d" + "x";
             builder = [ 1 ];
           })"#,
    );
    let entries = attrset_binding_values(&ir, dialect_node_argument(&ir, ir.root));
    for (value, _) in &entries {
        assert!(!ir.facts.assembly_eager(*value));
    }
    assert_eq!(
        strictness(&ir, binding_value(&entries, b"name")),
        Strictness::Unknown
    );
}

#[test]
fn strictness_declines_dynamic_key_derivation_strict_literals() {
    // Dynamic-key forces interleave with slot population and may collide
    // with the static `name` lookup, so mixed literals fail closed.
    let ir = annotate_with_derivation_op(
        r#"builtins.derivationStrict {
             name = "d" + "x";
             builder = [ 1 ];
             ${"ex" + "tra"} = 1 / 0;
           }"#,
    );
    let entries = attrset_binding_values(&ir, dialect_node_argument(&ir, ir.root));
    for (value, _) in &entries {
        assert!(!ir.facts.assembly_eager(*value));
    }
    assert_eq!(
        strictness(&ir, binding_value(&entries, b"name")),
        Strictness::Unknown
    );
}

#[test]
fn strictness_seeds_chased_derivation_strict_literals_without_name_license() {
    // A variable-chased literal may be assembled by another consumer first,
    // so only totality licenses eagerness and demand caps at S1.
    let ir = annotate_with_derivation_op(
        r#"let args = { name = "d" + "x"; builder = [ (1 / 0) ]; };
           in builtins.derivationStrict args"#,
    );
    let args_value = let_binding_values(&ir, ir.root)[0];
    let entries = attrset_binding_values(&ir, args_value);

    let name = binding_value(&entries, b"name");
    assert_eq!(strictness(&ir, name), Strictness::Demanded);
    assert!(!ir.facts.assembly_eager(name));

    let builder = binding_value(&entries, b"builder");
    assert_eq!(strictness(&ir, builder), Strictness::Demanded);
    assert!(ir.facts.assembly_eager(builder));
}

#[test]
fn strictness_seeds_derivation_wrapper_literals_with_totals_only() {
    // The `derivation` wrapper performs observable work before the
    // serializer loop and forces attributes only when its result is used, so
    // no demand marks and no first-force license - totality only.
    let ir = annotate(
        r#"builtins.derivation {
             name = "d" + "x";
             builder = [ (1 / 0) ];
           }"#,
    );
    let args = primop_args(&ir, ir.root);
    let entries = attrset_binding_values(&ir, args[0]);

    let name = binding_value(&entries, b"name");
    assert_eq!(strictness(&ir, name), Strictness::Unknown);
    assert!(!ir.facts.assembly_eager(name));

    let builder = binding_value(&entries, b"builder");
    assert_eq!(strictness(&ir, builder), Strictness::Unknown);
    assert!(ir.facts.assembly_eager(builder));
}

#[test]
fn strictness_collects_derivation_strict_name_demand_uncapped() {
    // The lambda summary sees the serializer force `name` before any event,
    // so the argument thunk earns the eager rank at the apply site.
    let ir = annotate_with_derivation_op(
        r#"(x: builtins.derivationStrict { name = x; builder = "b"; }) ("d" + "x")"#,
    );
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(strictness(&ir, argument), Strictness::DemandedBeforeEffect);
}

#[test]
fn strictness_collects_derivation_strict_non_name_demand_capped() {
    // Non-name attributes are forced after the serializer's name processing
    // can raise events, so the summary caps at S1.
    let ir = annotate_with_derivation_op(
        r#"(x: builtins.derivationStrict { name = "n"; builder = x; }) ("d" + "x")"#,
    );
    let IrData::Pair {
        second: argument, ..
    } = node(&ir, ir.root).data
    else {
        panic!("apply payload expected");
    };
    assert_eq!(strictness(&ir, argument), Strictness::Demanded);
}
