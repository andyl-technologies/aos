//! Primitive-operation escape signature tests.

use super::*;
use crate::syntax::Symbol;

fn root_escape(source: &str) -> Escape {
    let ir = annotate_allocations(source);
    escape(&ir, ir.root)
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
