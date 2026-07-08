//! Worker-wrapper planning tests.

use super::*;

fn apply_parts(ir: &Ir, id: IrId) -> (IrId, IrId) {
    let IrData::Pair { first, second } = node(ir, id).data else {
        panic!("apply payload expected");
    };
    (first, second)
}

fn set_facts(ir: &mut Ir, id: IrId, facts: ExprFacts) {
    *ir.facts.get_mut(id).expect("fact exists") = facts;
}

fn strict_argument_facts() -> ExprFacts {
    ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
        cardinality: Cardinality::Many,
        escape: Escape::Escapes,
    }
}

fn raw_formal_set_worker_wrapper_ir(
    formal_symbol: crate::syntax::Symbol,
    symbols: SymbolTable,
    formals: IrChildSlice,
    child_pool: Vec<IrId>,
    frame: Option<FrameId>,
    frames: Box<[FrameInfo]>,
) -> (Ir, IrId, IrId, IrId) {
    let pattern = IrId::new(0);
    let formal = IrId::new(1);
    let body = IrId::new(2);
    let lambda = IrId::new(3);
    let argument = IrId::new(4);
    let root = IrId::new(5);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::FormalSet,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::FormalSet {
                    formals,
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
                Span::new(7, 8),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Lambda,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Lambda {
                    pattern,
                    body,
                    frame,
                },
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(9, 10),
                EffectClass::pure(),
                IrData::Int(2),
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 10),
                EffectClass::pure(),
                IrData::Pair {
                    first: lambda,
                    second: argument,
                },
            ),
        ],
        child_pool,
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
fn worker_wrapper_plan_splits_direct_lambda_strict_argument() {
    let mut ir = lowered("(x: x + 1) (1 + 2)");
    annotate_strictness(&mut ir).expect("strictness analysis succeeds");
    let (lambda, argument) = apply_parts(&ir, ir.root);

    let plan = worker_wrapper_plan(&ir).expect("worker-wrapper plan succeeds");

    assert_eq!(plan.apply_count(), 1);
    assert_eq!(plan.splits().len(), 1);
    assert!(plan.retained().is_empty());
    assert_eq!(plan.splits()[0].apply(), ir.root);
    assert_eq!(plan.splits()[0].lambda(), lambda);
    assert_eq!(plan.splits()[0].argument(), argument);
    assert_eq!(
        plan.splits()[0].mode(),
        WorkerWrapperArgumentMode::StrictValue
    );
}

#[test]
fn worker_wrapper_plan_splits_direct_formal_set_strict_argument() {
    let mut ir = lowered("({ x }: 1) { x = 1 / 0; }");
    annotate_strictness(&mut ir).expect("strictness analysis succeeds");
    let (lambda, argument) = apply_parts(&ir, ir.root);

    let plan = worker_wrapper_plan(&ir).expect("worker-wrapper plan succeeds");

    assert_eq!(plan.apply_count(), 1);
    assert_eq!(plan.splits().len(), 1);
    assert!(plan.retained().is_empty());
    assert_eq!(plan.splits()[0].apply(), ir.root);
    assert_eq!(plan.splits()[0].lambda(), lambda);
    assert_eq!(plan.splits()[0].argument(), argument);
    assert_eq!(
        plan.splits()[0].mode(),
        WorkerWrapperArgumentMode::StrictValue
    );
}

#[test]
fn worker_wrapper_plan_retains_unproven_arguments() {
    let ir = annotate("(x: 1) (1 / 0)");
    let (lambda, argument) = apply_parts(&ir, ir.root);

    let plan = worker_wrapper_plan(&ir).expect("worker-wrapper plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(plan.retained()[0].apply(), ir.root);
    assert_eq!(plan.retained()[0].callee(), lambda);
    assert_eq!(plan.retained()[0].argument(), argument);
    assert_eq!(
        plan.retained()[0].reason(),
        WorkerWrapperRetentionReason::ArgumentNotStrict {
            strictness: Strictness::Unknown
        }
    );
}

#[test]
fn worker_wrapper_plan_retains_forged_strict_facts_when_formal_is_ignored() {
    let mut ir = lowered("(x: 1) (builtins.throw \"unused\")");
    let (_lambda, argument) = apply_parts(&ir, ir.root);
    set_facts(
        &mut ir,
        argument,
        ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        },
    );

    let plan = worker_wrapper_plan(&ir).expect("worker-wrapper plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(
        plan.retained()[0].reason(),
        WorkerWrapperRetentionReason::FormalNotDemanded
    );
}

#[test]
fn worker_wrapper_plan_retains_non_literal_callees() {
    let ir = annotate("let f = x: x + 1; in f (1 + 2)");
    let IrData::Let { body, .. } = node(&ir, ir.root).data else {
        panic!("let payload expected");
    };
    let (callee, argument) = apply_parts(&ir, body);

    let plan = worker_wrapper_plan(&ir).expect("worker-wrapper plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.apply_count(), 1);
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(plan.retained()[0].apply(), body);
    assert_eq!(plan.retained()[0].callee(), callee);
    assert_eq!(plan.retained()[0].argument(), argument);
    assert_eq!(
        plan.retained()[0].reason(),
        WorkerWrapperRetentionReason::NonLiteralCallee {
            kind: node(&ir, callee).kind
        }
    );
}

#[test]
fn worker_wrapper_plan_retains_forged_formal_set_strict_fact_on_frame_mismatch() {
    let mut symbols = SymbolTable::new();
    let name = symbols.intern(b"x").expect("symbol interns");
    let (mut ir, _, lambda, argument) = raw_formal_set_worker_wrapper_ir(
        name,
        symbols,
        IrChildSlice::new(0, 1),
        vec![IrId::new(1)],
        Some(FrameId::new(0)),
        Box::new([FrameInfo {
            slot_count: 0,
            captures: Box::new([]),
            rec: false,
            has_with: false,
        }]),
    );
    set_facts(&mut ir, argument, strict_argument_facts());

    let plan = worker_wrapper_plan(&ir).expect("worker-wrapper plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(plan.retained()[0].apply(), ir.root);
    assert_eq!(plan.retained()[0].callee(), lambda);
    assert_eq!(plan.retained()[0].argument(), argument);
    assert_eq!(
        plan.retained()[0].reason(),
        WorkerWrapperRetentionReason::FormalNotDemanded
    );
}

#[test]
fn worker_wrapper_plan_rejects_invalid_formal_set_frame_during_strictness_replay() {
    let mut symbols = SymbolTable::new();
    let name = symbols.intern(b"x").expect("symbol interns");
    let invalid_frame = FrameId::new(1);
    let (mut ir, _, lambda, argument) = raw_formal_set_worker_wrapper_ir(
        name,
        symbols,
        IrChildSlice::new(0, 1),
        vec![IrId::new(1)],
        Some(invalid_frame),
        Box::new([FrameInfo {
            slot_count: 1,
            captures: Box::new([]),
            rec: false,
            has_with: false,
        }]),
    );
    set_facts(&mut ir, argument, strict_argument_facts());

    let error = worker_wrapper_plan(&ir).expect_err("invalid formal-set frame rejects");

    assert_eq!(
        error,
        WorkerWrapperPlanError::Strictness(StrictnessAnalysisError::InvalidFrame {
            id: lambda,
            frame: invalid_frame,
        })
    );
}

#[test]
fn worker_wrapper_plan_rejects_invalid_formal_set_child_slice_during_strictness_replay() {
    let mut symbols = SymbolTable::new();
    let name = symbols.intern(b"x").expect("symbol interns");
    let invalid_formals = IrChildSlice::new(2, 1);
    let (mut ir, _, _, argument) = raw_formal_set_worker_wrapper_ir(
        name,
        symbols,
        invalid_formals,
        vec![IrId::new(1)],
        Some(FrameId::new(0)),
        Box::new([FrameInfo {
            slot_count: 1,
            captures: Box::new([]),
            rec: false,
            has_with: false,
        }]),
    );
    set_facts(&mut ir, argument, strict_argument_facts());

    let error = worker_wrapper_plan(&ir).expect_err("invalid formal-set child slice rejects");

    assert_eq!(
        error,
        WorkerWrapperPlanError::Strictness(StrictnessAnalysisError::InvalidChildSlice {
            id: IrId::new(0),
            slice: invalid_formals,
        })
    );
}

#[test]
fn worker_wrapper_plan_rejects_invalid_formal_set_symbol_during_strictness_replay() {
    let invalid_symbol = crate::syntax::Symbol::new(99);
    let (mut ir, formal, _, argument) = raw_formal_set_worker_wrapper_ir(
        invalid_symbol,
        SymbolTable::new(),
        IrChildSlice::new(0, 1),
        vec![IrId::new(1)],
        Some(FrameId::new(0)),
        Box::new([FrameInfo {
            slot_count: 1,
            captures: Box::new([]),
            rec: false,
            has_with: false,
        }]),
    );
    set_facts(&mut ir, argument, strict_argument_facts());

    let error = worker_wrapper_plan(&ir).expect_err("invalid formal-set symbol rejects");

    assert_eq!(
        error,
        WorkerWrapperPlanError::Strictness(StrictnessAnalysisError::InvalidSymbol {
            id: formal,
            symbol: invalid_symbol,
        })
    );
}

#[test]
fn worker_wrapper_plan_retains_non_simple_literal_lambda_patterns() {
    let pattern = IrId::new(0);
    let body = IrId::new(1);
    let lambda = IrId::new(2);
    let argument = IrId::new(3);
    let root = IrId::new(4);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(3, 4),
                EffectClass::pure(),
                IrData::Int(2),
            ),
            IrNode::new(
                IrKind::Lambda,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Lambda {
                    pattern,
                    body,
                    frame: None,
                },
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(5, 6),
                EffectClass::pure(),
                IrData::Int(3),
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Pair {
                    first: lambda,
                    second: argument,
                },
            ),
        ],
        Vec::new(),
    );
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        argument,
        ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        },
    );

    let plan = worker_wrapper_plan(&ir).expect("worker-wrapper plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(
        plan.retained()[0].reason(),
        WorkerWrapperRetentionReason::NonSimplePattern {
            pattern,
            kind: IrKind::Int
        }
    );
}

#[test]
fn worker_wrapper_plan_rejects_fact_table_length_mismatches() {
    let mut ir = lowered("(x: x + 1) (1 + 2)");
    let (lambda, argument) = apply_parts(&ir, ir.root);
    let expected = ir.arena.nodes().len();
    ir.facts = IrFacts::conservative(argument.index());

    let error = worker_wrapper_plan(&ir).expect_err("short fact table rejects");

    assert_eq!(
        error,
        WorkerWrapperPlanError::InvalidFactTableLength {
            expected,
            actual: argument.index(),
        }
    );
    assert_eq!(node(&ir, lambda).kind, IrKind::Lambda);

    ir.facts = IrFacts::conservative(expected + 1);

    let error = worker_wrapper_plan(&ir).expect_err("overlong fact table rejects");

    assert_eq!(
        error,
        WorkerWrapperPlanError::InvalidFactTableLength {
            expected,
            actual: expected + 1,
        }
    );
}

#[test]
fn worker_wrapper_plan_rejects_invalid_apply_payloads() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Apply,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let ir = Ir {
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

    let error = worker_wrapper_plan(&ir).expect_err("invalid apply payload rejects");

    assert_eq!(
        error,
        WorkerWrapperPlanError::InvalidPayload {
            id: IrId::new(0),
            kind: IrKind::Apply,
            expected: "apply payload"
        }
    );
}

#[test]
fn worker_wrapper_plan_rejects_aliased_apply_payloads() {
    let mut symbols = SymbolTable::new();
    let name = symbols.intern(b"x").expect("symbol interns");

    for (first, second) in [
        (IrId::new(2), IrId::new(2)),
        (IrId::new(2), IrId::new(3)),
        (IrId::new(3), IrId::new(2)),
    ] {
        let root = IrId::new(3);
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Formal,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Formal {
                        name,
                        default: None,
                    },
                ),
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(3, 4),
                    EffectClass::pure(),
                    IrData::Local { slot: 0 },
                ),
                IrNode::new(
                    IrKind::Lambda,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::Lambda {
                        pattern: IrId::new(0),
                        body: IrId::new(1),
                        frame: None,
                    },
                ),
                IrNode::new(
                    IrKind::Apply,
                    Span::new(0, 7),
                    EffectClass::pure(),
                    IrData::Pair { first, second },
                ),
            ],
            Vec::new(),
        );
        let ir = Ir {
            root,
            facts: IrFacts::conservative(arena.nodes().len()),
            arena,
            symbols: symbols.clone(),
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        };

        let error = worker_wrapper_plan(&ir).expect_err("aliased apply payload rejects");

        assert_eq!(
            error,
            WorkerWrapperPlanError::InvalidPayload {
                id: root,
                kind: IrKind::Apply,
                expected: "non-aliased apply payload"
            }
        );
    }
}

#[test]
fn worker_wrapper_plan_rejects_invalid_lambda_payloads() {
    let lambda = IrId::new(0);
    let argument = IrId::new(1);
    let root = IrId::new(2);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Lambda,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Node(lambda),
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Pair {
                    first: lambda,
                    second: argument,
                },
            ),
        ],
        Vec::new(),
    );
    let ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = worker_wrapper_plan(&ir).expect_err("invalid lambda payload rejects");

    assert_eq!(
        error,
        WorkerWrapperPlanError::InvalidPayload {
            id: lambda,
            kind: IrKind::Lambda,
            expected: "lambda payload"
        }
    );
}

#[test]
fn worker_wrapper_plan_rejects_invalid_simple_formal_payloads() {
    let pattern = IrId::new(0);
    let body = IrId::new(1);
    let lambda = IrId::new(2);
    let argument = IrId::new(3);
    let root = IrId::new(4);
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Formal,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(3, 4),
                EffectClass::pure(),
                IrData::Local { slot: 0 },
            ),
            IrNode::new(
                IrKind::Lambda,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Lambda {
                    pattern,
                    body,
                    frame: None,
                },
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(6, 7),
                EffectClass::pure(),
                IrData::Node(body),
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 7),
                EffectClass::pure(),
                IrData::Pair {
                    first: lambda,
                    second: argument,
                },
            ),
        ],
        Vec::new(),
    );
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        argument,
        ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        },
    );

    let error = worker_wrapper_plan(&ir).expect_err("invalid formal payload rejects");

    assert_eq!(
        error,
        WorkerWrapperPlanError::InvalidPayload {
            id: pattern,
            kind: IrKind::Formal,
            expected: "formal payload"
        }
    );
}

#[test]
fn worker_wrapper_plan_rejects_invalid_body_payloads() {
    let pattern = IrId::new(0);
    let body = IrId::new(1);
    let lambda = IrId::new(2);
    let argument = IrId::new(3);
    let root = IrId::new(4);
    let mut symbols = SymbolTable::new();
    let name = symbols.intern(b"x").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Formal,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Formal {
                    name,
                    default: None,
                },
            ),
            IrNode::new(
                IrKind::BinOp,
                Span::new(3, 4),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::Lambda,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Lambda {
                    pattern,
                    body,
                    frame: None,
                },
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(6, 7),
                EffectClass::pure(),
                IrData::Node(body),
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 7),
                EffectClass::pure(),
                IrData::Pair {
                    first: lambda,
                    second: argument,
                },
            ),
        ],
        Vec::new(),
    );
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    set_facts(
        &mut ir,
        argument,
        ExprFacts {
            strictness: Strictness::DemandedBeforeEffect,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        },
    );

    let error = worker_wrapper_plan(&ir).expect_err("invalid body payload rejects");

    assert_eq!(
        error,
        WorkerWrapperPlanError::InvalidPayload {
            id: body,
            kind: IrKind::BinOp,
            expected: "binary payload"
        }
    );
}
