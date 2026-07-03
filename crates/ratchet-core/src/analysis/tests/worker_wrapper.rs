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
            strictness: Strictness::Strict,
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
fn worker_wrapper_plan_retains_non_simple_literal_lambda_patterns() {
    let mut ir = lowered("({ x }: x) { x = 1; }");
    let (lambda, argument) = apply_parts(&ir, ir.root);
    set_facts(
        &mut ir,
        argument,
        ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        },
    );
    let IrData::Lambda { pattern, .. } = node(&ir, lambda).data else {
        panic!("lambda payload expected");
    };

    let plan = worker_wrapper_plan(&ir).expect("worker-wrapper plan succeeds");

    assert!(plan.is_empty());
    assert_eq!(plan.retained().len(), 1);
    assert_eq!(
        plan.retained()[0].reason(),
        WorkerWrapperRetentionReason::NonSimplePattern {
            pattern,
            kind: IrKind::FormalSet
        }
    );
}

#[test]
fn worker_wrapper_plan_rejects_missing_argument_facts() {
    let mut ir = lowered("(x: x + 1) (1 + 2)");
    let (lambda, argument) = apply_parts(&ir, ir.root);
    ir.facts = IrFacts::conservative(argument.index());

    let error = worker_wrapper_plan(&ir).expect_err("missing argument fact rejects");

    assert_eq!(error, WorkerWrapperPlanError::MissingFact { id: argument });
    assert_eq!(node(&ir, lambda).kind, IrKind::Lambda);
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
            strictness: Strictness::Strict,
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
            strictness: Strictness::Strict,
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
