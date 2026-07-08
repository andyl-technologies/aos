//! Primitive-operation escape signature tests.

use proptest::prelude::*;

use super::*;
use crate::builtins::{BUILTINS, direct_builtin};
use crate::syntax::Symbol;

const IMMEDIATE_SCALAR_PRIMOP_NAMES: &[&[u8]] = &[
    b"isAttrs",
    b"isList",
    b"isFunction",
    b"isString",
    b"isInt",
    b"isFloat",
    b"isBool",
    b"isNull",
    b"isPath",
    b"length",
    b"ceil",
    b"floor",
    b"hasContext",
    b"stringLength",
    b"sub",
    b"mul",
    b"div",
    b"bitAnd",
    b"bitOr",
    b"bitXor",
    b"compareVersions",
    b"lessThan",
    b"all",
    b"any",
    b"hasAttr",
    b"elem",
];

fn root_escape(source: &str) -> Escape {
    let ir = annotate_allocations(source);
    escape(&ir, ir.root)
}

fn immediate_scalar_allowlisted(name: &[u8]) -> bool {
    IMMEDIATE_SCALAR_PRIMOP_NAMES
        .iter()
        .any(|allowlisted| *allowlisted == name)
}

fn registered_builtin_name() -> impl Strategy<Value = Vec<u8>> {
    prop::sample::select(
        BUILTINS
            .iter()
            .map(|builtin| builtin.name().to_vec())
            .collect::<Vec<_>>(),
    )
}

fn unknown_builtin_name() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(b'a'..=b'z', 0..24).prop_map(|mut suffix| {
        let mut name = b"__aos_escape_fuzz_".to_vec();
        name.append(&mut suffix);
        name
    })
}

fn raw_primop_escape(name: &[u8], arity: usize) -> Result<Escape, EscapeAnalysisError> {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(name).expect("symbol interns");
    let root = IrId::new(arity as u32);
    let children = (0..arity)
        .map(|index| IrId::new(index as u32))
        .collect::<Vec<_>>();
    let mut nodes = children
        .iter()
        .map(|_| {
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            )
        })
        .collect::<Vec<_>>();
    nodes.push(IrNode::new(
        IrKind::PrimOp,
        Span::new(0, 1),
        EffectClass::pure(),
        IrData::PrimOp {
            symbol,
            args: IrChildSlice::new(0, arity as u32),
        },
    ));
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(nodes.len()),
        arena: IrArena::from_raw_parts(nodes, children),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    annotate_escape(&mut ir).map(|_| escape(&ir, root))
}

fn raw_primop_scalar_replacement_plan(
    name: &[u8],
    arity: usize,
) -> Result<(IrId, ScalarReplacementPlan), ScalarReplacementError> {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(name).expect("symbol interns");
    let root = IrId::new(arity as u32);
    let children = (0..arity)
        .map(|index| IrId::new(index as u32))
        .collect::<Vec<_>>();
    let mut nodes = children
        .iter()
        .map(|_| {
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            )
        })
        .collect::<Vec<_>>();
    nodes.push(IrNode::new(
        IrKind::PrimOp,
        Span::new(0, 1),
        EffectClass::pure(),
        IrData::PrimOp {
            symbol,
            args: IrChildSlice::new(0, arity as u32),
        },
    ));
    let mut ir = Ir {
        root,
        facts: IrFacts::conservative(nodes.len()),
        arena: IrArena::from_raw_parts(nodes, children),
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };
    *ir.facts.get_mut(root).expect("root fact exists") = ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
        cardinality: Cardinality::Many,
        escape: Escape::NoEscape,
    };

    scalar_replacement_plan(&ir).map(|plan| (root, plan))
}

#[test]
fn escape_marks_scalar_returning_primops_no_escape() {
    for source in [
        "builtins.isInt 1",
        "builtins.sub 3 1",
        "builtins.lessThan 1 2",
        "builtins.hasAttr \"a\" { a = 1; }",
        "builtins.elem 1 [1 2]",
    ] {
        assert_eq!(root_escape(source), Escape::NoEscape, "{source}");
    }
}

#[test]
fn escape_keeps_allocating_and_overloaded_primops_escaping() {
    for source in [
        "builtins.toString 1",
        "builtins.add \"a\" \"b\"",
        "builtins.match \"a\" \"a\"",
        "builtins.seq 1 \"value\"",
    ] {
        assert_eq!(root_escape(source), Escape::Escapes, "{source}");
    }
}

#[test]
fn primop_escape_signature_classifies_only_scalar_results() {
    assert_eq!(
        primop_escape_signature(b"isBool"),
        PrimOpEscapeSignature::ImmediateScalar
    );
    assert_eq!(
        primop_escape_signature(b"bitXor"),
        PrimOpEscapeSignature::ImmediateScalar
    );
    assert_eq!(
        primop_escape_signature(b"hasAttr"),
        PrimOpEscapeSignature::ImmediateScalar
    );
    assert_eq!(
        primop_escape_signature(b"add"),
        PrimOpEscapeSignature::Conservative
    );
    assert_eq!(
        primop_escape_signature(b"toJSON"),
        PrimOpEscapeSignature::Conservative
    );
    assert_eq!(
        primop_escape_signature(b"__notABuiltin"),
        PrimOpEscapeSignature::Conservative
    );
}

#[test]
fn primop_escape_signature_matches_registered_builtin_allowlist() {
    for name in IMMEDIATE_SCALAR_PRIMOP_NAMES {
        assert!(
            BUILTINS.lookup(name).is_some(),
            "{}",
            String::from_utf8_lossy(name)
        );
    }

    for builtin in BUILTINS.iter() {
        let expected = if IMMEDIATE_SCALAR_PRIMOP_NAMES
            .iter()
            .any(|name| *name == builtin.name())
        {
            PrimOpEscapeSignature::ImmediateScalar
        } else {
            PrimOpEscapeSignature::Conservative
        };
        assert_eq!(
            primop_escape_signature(builtin.name()),
            expected,
            "{}",
            String::from_utf8_lossy(builtin.name())
        );
    }
}

#[test]
fn scalar_replacement_plan_matches_registered_builtin_signature_surface() {
    for builtin in BUILTINS.iter() {
        let signature = primop_escape_signature(builtin.name());
        let arity = builtin.direct().map_or(0, |direct| direct.arity());
        let (root, plan) = raw_primop_scalar_replacement_plan(builtin.name(), arity)
            .unwrap_or_else(|error| {
                panic!("{}: {error:?}", String::from_utf8_lossy(builtin.name()))
            });

        match signature {
            PrimOpEscapeSignature::ImmediateScalar => {
                assert!(
                    builtin.direct().is_some(),
                    "{}",
                    String::from_utf8_lossy(builtin.name())
                );
                assert_eq!(
                    plan.replacements().len(),
                    1,
                    "{}: {plan:?}",
                    String::from_utf8_lossy(builtin.name())
                );
                assert_eq!(
                    plan.replacements()[0].node(),
                    root,
                    "{}",
                    String::from_utf8_lossy(builtin.name())
                );
                assert_eq!(
                    plan.replacements()[0].kind(),
                    ScalarReplacementKind::PrimOpImmediateScalar,
                    "{}",
                    String::from_utf8_lossy(builtin.name())
                );
            }
            PrimOpEscapeSignature::Conservative => {
                assert!(
                    plan.replacements().is_empty(),
                    "{}: {plan:?}",
                    String::from_utf8_lossy(builtin.name())
                );
            }
        }
    }
}

proptest! {
    #[test]
    fn primop_escape_signature_fuzzes_registered_builtin_surface(name in registered_builtin_name()) {
        let expected = if immediate_scalar_allowlisted(&name) {
            PrimOpEscapeSignature::ImmediateScalar
        } else {
            PrimOpEscapeSignature::Conservative
        };

        prop_assert_eq!(
            primop_escape_signature(&name),
            expected,
            "{}",
            String::from_utf8_lossy(&name)
        );
    }

    #[test]
    fn primop_escape_signature_fuzzes_unknown_names_conservative(name in unknown_builtin_name()) {
        prop_assert!(BUILTINS.lookup(&name).is_none(), "{}", String::from_utf8_lossy(&name));
        prop_assert_eq!(
            primop_escape_signature(&name),
            PrimOpEscapeSignature::Conservative,
            "{}",
            String::from_utf8_lossy(&name)
        );
        prop_assert_eq!(raw_primop_escape(&name, 2).expect("unknown primop annotates"), Escape::Escapes);
        let (_root, plan) = raw_primop_scalar_replacement_plan(&name, 2)
            .expect("unknown primop plans");
        prop_assert!(plan.replacements().is_empty(), "{:?}", plan);
    }

    #[test]
    fn raw_primop_escape_fuzzes_signature_and_direct_arity(
        name in registered_builtin_name(),
        arity in 0usize..=4,
    ) {
        let result = raw_primop_escape(&name, arity);
        if let Some(direct) = direct_builtin(&name)
            && arity != direct.arity()
        {
            let Err(EscapeAnalysisError::InvalidPrimOpArity { expected, actual, .. }) = result
            else {
                return Err(TestCaseError::fail(format!("{result:?}")));
            };
            prop_assert_eq!(expected, direct.arity());
            prop_assert_eq!(actual, arity);
            return Ok(());
        }

        let escape = result
            .map_err(|error| TestCaseError::fail(format!("{error:?}")))?;
        prop_assert_eq!(
            escape,
            primop_escape_signature(&name).escape(),
            "{}",
            String::from_utf8_lossy(&name)
        );
    }

    #[test]
    fn raw_primop_scalar_replacement_fuzzes_signature_and_direct_arity(
        name in registered_builtin_name(),
        arity in 0usize..=4,
    ) {
        let result = raw_primop_scalar_replacement_plan(&name, arity);
        if let Some(direct) = direct_builtin(&name)
            && arity != direct.arity()
        {
            let Err(ScalarReplacementError::InvalidPrimOpArity { expected, actual, .. }) = result
            else {
                return Err(TestCaseError::fail(format!("{result:?}")));
            };
            prop_assert_eq!(expected, direct.arity());
            prop_assert_eq!(actual, arity);
            return Ok(());
        }

        let (root, plan) = result
            .map_err(|error| TestCaseError::fail(format!("{error:?}")))?;
        if primop_escape_signature(&name) == PrimOpEscapeSignature::ImmediateScalar {
            prop_assert_eq!(
                plan.replacements().len(),
                1,
                "{}: {:?}",
                String::from_utf8_lossy(&name),
                plan
            );
            prop_assert_eq!(
                plan.replacements()[0].node(),
                root,
                "{}",
                String::from_utf8_lossy(&name)
            );
            prop_assert_eq!(
                plan.replacements()[0].kind(),
                ScalarReplacementKind::PrimOpImmediateScalar,
                "{}",
                String::from_utf8_lossy(&name)
            );
        } else {
            prop_assert!(
                plan.replacements().is_empty(),
                "{}: {:?}",
                String::from_utf8_lossy(&name),
                plan
            );
        }
    }
}

#[test]
fn escape_rejects_malformed_primop_symbol() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::PrimOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::PrimOp {
                symbol: Symbol::new(999),
                args: IrChildSlice::new(0, 0),
            },
        )],
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

    let error = annotate_escape(&mut ir).expect_err("invalid primop symbol rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidSymbol {
            id: IrId::new(0),
            symbol: Symbol::new(999)
        }
    );
}

#[test]
fn escape_rejects_malformed_primop_child_slice() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"isInt").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::PrimOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::PrimOp {
                symbol,
                args: IrChildSlice::new(0, 1),
            },
        )],
        Vec::new(),
    );
    let mut ir = Ir {
        root: IrId::new(0),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = annotate_escape(&mut ir).expect_err("invalid primop child slice rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidChildSlice {
            id: IrId::new(0),
            slice: IrChildSlice::new(0, 1)
        }
    );
}

#[test]
fn escape_rejects_missing_primop_child_nodes() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"isInt").expect("symbol interns");
    let missing = IrId::new(9);
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::PrimOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::PrimOp {
                symbol,
                args: IrChildSlice::new(0, 1),
            },
        )],
        vec![missing],
    );
    let mut ir = Ir {
        root: IrId::new(0),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = annotate_escape(&mut ir).expect_err("missing primop child rejects");

    assert_eq!(error, EscapeAnalysisError::InvalidNode { id: missing });
}

#[test]
fn escape_rejects_scalar_unary_primop_with_wrong_arity() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"isInt").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::PrimOp,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::PrimOp {
                symbol,
                args: IrChildSlice::new(0, 0),
            },
        )],
        Vec::new(),
    );
    let mut ir = Ir {
        root: IrId::new(0),
        facts: IrFacts::conservative(arena.nodes().len()),
        arena,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = annotate_escape(&mut ir).expect_err("wrong unary primop arity rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidPrimOpArity {
            id: IrId::new(0),
            symbol,
            expected: 1,
            actual: 0
        }
    );
}

#[test]
fn escape_rejects_scalar_binary_primop_with_wrong_arity() {
    let value = IrId::new(0);
    let root = IrId::new(1);
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"sub").expect("symbol interns");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::PrimOp,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::PrimOp {
                    symbol,
                    args: IrChildSlice::new(0, 1),
                },
            ),
        ],
        vec![value],
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

    let error = annotate_escape(&mut ir).expect_err("wrong binary primop arity rejects");

    assert_eq!(
        error,
        EscapeAnalysisError::InvalidPrimOpArity {
            id: root,
            symbol,
            expected: 2,
            actual: 1
        }
    );
}
