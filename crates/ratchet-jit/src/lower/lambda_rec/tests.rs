//! Unit tests for the tier-2 self-recursive lambda lowerer.

use super::*;
use super::*;

use ratchet_core::{
    EffectClass, IrChildSlice, IrNode,
    syntax::{Span, Symbol},
};

fn node(kind: IrKind, data: IrData) -> IrNode {
    IrNode::new(kind, Span::new(0, 1), EffectClass::pure(), data)
}

fn arena(nodes: Vec<IrNode>) -> IrArena {
    IrArena::from_raw_parts(nodes, Vec::new())
}

/// Builds the canonical `fib`-shaped arena and returns the lambda id.
///
/// `fib = n: if n < 2 then n else fib (n - 1) + fib (n - 2)` with the
/// self-callee as upvalue `(1, 3)` and lazy-wrapped call arguments.
fn fib_arena() -> (IrArena, IrId, IrId) {
    let nodes = vec![
        /* 0 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        /* 1 */ node(IrKind::LocalVar, IrData::Local { slot: 0 }),
        /* 2 */ node(IrKind::Int, IrData::Int(2)),
        /* 3 */
        node(
            IrKind::BinOp,
            IrData::Binary {
                op: BinOpKind::Lt,
                lhs: IrId::new(1),
                rhs: IrId::new(2),
            },
        ),
        /* 4 */ node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 3 }),
        /* 5 */ node(IrKind::Int, IrData::Int(1)),
        /* 6 */
        node(
            IrKind::BinOp,
            IrData::Binary {
                op: BinOpKind::Sub,
                lhs: IrId::new(1),
                rhs: IrId::new(5),
            },
        ),
        /* 7 */ node(IrKind::ThunkAlloc, IrData::Node(IrId::new(6))),
        /* 8 */
        node(
            IrKind::Apply,
            IrData::Pair {
                first: IrId::new(4),
                second: IrId::new(7),
            },
        ),
        /* 9 */ node(IrKind::Int, IrData::Int(2)),
        /* 10 */
        node(
            IrKind::BinOp,
            IrData::Binary {
                op: BinOpKind::Sub,
                lhs: IrId::new(1),
                rhs: IrId::new(9),
            },
        ),
        /* 11 */ node(IrKind::ThunkAlloc, IrData::Node(IrId::new(10))),
        /* 12 */
        node(
            IrKind::Apply,
            IrData::Pair {
                first: IrId::new(4),
                second: IrId::new(11),
            },
        ),
        /* 13 */
        node(
            IrKind::BinOp,
            IrData::Binary {
                op: BinOpKind::Add,
                lhs: IrId::new(8),
                rhs: IrId::new(12),
            },
        ),
        /* 14 */
        node(
            IrKind::If,
            IrData::Triple {
                first: IrId::new(3),
                second: IrId::new(1),
                third: IrId::new(13),
            },
        ),
        /* 15 */
        node(
            IrKind::Lambda,
            IrData::Lambda {
                pattern: IrId::new(0),
                body: IrId::new(14),
                frame: None,
            },
        ),
    ];
    (arena(nodes), IrId::new(0), IrId::new(14))
}

/// The canonical fib shape lowers to a verified two-function artifact.
#[test]
fn fib_shape_lowers_with_two_self_calls() {
    let (arena, pattern, body) = fib_arena();
    let lowering =
        lower_tier2_self_recursive_lambda(&arena, pattern, body, TIER2_NATIVE_DEPTH_BUDGET)
            .expect("fib shape lowers");
    assert_eq!(lowering.self_call_count(), 2);
    assert_eq!(lowering.self_upval(), (1, 3));
    assert_eq!(lowering.source(), body);
    // The entry keeps the frozen 4-param lambda ABI; inner adds the budget.
    assert_eq!(lowering.entry().signature.params.len(), 4);
    assert_eq!(lowering.inner().signature.params.len(), 5);
}

/// A non-self callee (a different upvalue per call site) is rejected.
#[test]
fn mixed_callee_upvalues_are_rejected() {
    let nodes = vec![
        /* 0 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        /* 1 */ node(IrKind::LocalVar, IrData::Local { slot: 0 }),
        /* 2 */ node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 0 }),
        /* 3 */ node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 1 }),
        /* 4 */
        node(
            IrKind::Apply,
            IrData::Pair {
                first: IrId::new(2),
                second: IrId::new(1),
            },
        ),
        /* 5 */
        node(
            IrKind::Apply,
            IrData::Pair {
                first: IrId::new(3),
                second: IrId::new(4),
            },
        ),
        /* 6 */
        node(
            IrKind::Lambda,
            IrData::Lambda {
                pattern: IrId::new(0),
                body: IrId::new(5),
                frame: None,
            },
        ),
    ];
    let arena = arena(nodes);
    assert!(lower_tier2_self_recursive_lambda(&arena, IrId::new(0), IrId::new(5), TIER2_NATIVE_DEPTH_BUDGET).is_err());
}

/// A body outside the arithmetic grammar (a bare upvalue read) is rejected.
#[test]
fn non_grammar_body_is_rejected() {
    let nodes = vec![
        node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 0 }),
        node(
            IrKind::Lambda,
            IrData::Lambda {
                pattern: IrId::new(0),
                body: IrId::new(1),
                frame: None,
            },
        ),
    ];
    let arena = arena(nodes);
    assert!(lower_tier2_self_recursive_lambda(&arena, IrId::new(0), IrId::new(1), TIER2_NATIVE_DEPTH_BUDGET).is_err());
}

/// A formal-set pattern is outside the tier-2 grammar.
#[test]
fn formal_set_pattern_is_rejected() {
    let nodes = vec![
        node(
            IrKind::FormalSet,
            IrData::FormalSet {
                formals: IrChildSlice::new(0, 0),
                ellipsis: false,
                alias: None,
            },
        ),
        node(IrKind::Int, IrData::Int(1)),
        node(
            IrKind::Lambda,
            IrData::Lambda {
                pattern: IrId::new(0),
                body: IrId::new(1),
                frame: None,
            },
        ),
    ];
    let arena = arena(nodes);
    assert!(lower_tier2_self_recursive_lambda(&arena, IrId::new(0), IrId::new(1), TIER2_NATIVE_DEPTH_BUDGET).is_err());
}

/// An `if` condition that is not statically boolean is rejected.
#[test]
fn dynamic_if_condition_is_rejected() {
    let nodes = vec![
        node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        node(IrKind::LocalVar, IrData::Local { slot: 0 }),
        node(IrKind::Int, IrData::Int(1)),
        node(IrKind::Int, IrData::Int(2)),
        node(
            IrKind::If,
            IrData::Triple {
                first: IrId::new(1),
                second: IrId::new(2),
                third: IrId::new(3),
            },
        ),
        node(
            IrKind::Lambda,
            IrData::Lambda {
                pattern: IrId::new(0),
                body: IrId::new(4),
                frame: None,
            },
        ),
    ];
    let arena = arena(nodes);
    assert!(lower_tier2_self_recursive_lambda(&arena, IrId::new(0), IrId::new(4), TIER2_NATIVE_DEPTH_BUDGET).is_err());
}

