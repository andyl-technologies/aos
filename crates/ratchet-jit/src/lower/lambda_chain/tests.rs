//! Unit tests for the tier-2 fused curried-chain lowerer.

use super::*;
use ratchet_core::{
    EffectClass, IrNode,
    syntax::{Span, Symbol},
};

fn node(kind: IrKind, data: IrData) -> IrNode {
    IrNode::new(kind, Span::new(0, 1), EffectClass::pure(), data)
}

fn arena(nodes: Vec<IrNode>) -> IrArena {
    IrArena::from_raw_parts(nodes, Vec::new())
}

/// Builds a fold-operator arena mirroring the real lowering of
/// `acc: i: mod (acc + i * i + 7) 13` with `mod = a: b: a - b * (a / b)`
/// bound at upvalue `(2, 0)`, and returns
/// `(arena, op_root_pattern, op_root_body, mod_pattern, mod_body)`.
fn fold_op_arena() -> (IrArena, IrId, IrId, IrId, IrId) {
    let nodes = vec![
        // mod = a: b: a - b * (a / b)
        /* 0 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        /* 1 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(1), default: None }),
        /* 2 */ node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 0 }),
        /* 3 */ node(IrKind::LocalVar, IrData::Local { slot: 0 }),
        /* 4 */ node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 0 }),
        /* 5 */ node(IrKind::LocalVar, IrData::Local { slot: 0 }),
        /* 6 */
        node(
            IrKind::BinOp,
            IrData::Binary { op: BinOpKind::Div, lhs: IrId::new(4), rhs: IrId::new(5) },
        ),
        /* 7 */
        node(
            IrKind::BinOp,
            IrData::Binary { op: BinOpKind::Mul, lhs: IrId::new(3), rhs: IrId::new(6) },
        ),
        /* 8 */
        node(
            IrKind::BinOp,
            IrData::Binary { op: BinOpKind::Sub, lhs: IrId::new(2), rhs: IrId::new(7) },
        ),
        /* 9 */
        node(
            IrKind::Lambda,
            IrData::Lambda { pattern: IrId::new(1), body: IrId::new(8), frame: None },
        ),
        // op = acc: i: mod (acc + i * i + 7) 13
        /* 10 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(2), default: None }),
        /* 11 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(3), default: None }),
        /* 12 */ node(IrKind::UpvalVar, IrData::Upval { depth: 2, slot: 0 }), // mod
        /* 13 */ node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 0 }), // acc
        /* 14 */ node(IrKind::LocalVar, IrData::Local { slot: 0 }),           // i
        /* 15 */ node(IrKind::LocalVar, IrData::Local { slot: 0 }),           // i
        /* 16 */
        node(
            IrKind::BinOp,
            IrData::Binary { op: BinOpKind::Mul, lhs: IrId::new(14), rhs: IrId::new(15) },
        ),
        /* 17 */
        node(
            IrKind::BinOp,
            IrData::Binary { op: BinOpKind::Add, lhs: IrId::new(13), rhs: IrId::new(16) },
        ),
        /* 18 */ node(IrKind::Int, IrData::Int(7)),
        /* 19 */
        node(
            IrKind::BinOp,
            IrData::Binary { op: BinOpKind::Add, lhs: IrId::new(17), rhs: IrId::new(18) },
        ),
        /* 20 */ node(IrKind::ThunkAlloc, IrData::Node(IrId::new(19))),
        /* 21 */
        node(
            IrKind::Apply,
            IrData::Pair { first: IrId::new(12), second: IrId::new(20) },
        ),
        /* 22 */ node(IrKind::Int, IrData::Int(13)),
        /* 23 */
        node(
            IrKind::Apply,
            IrData::Pair { first: IrId::new(21), second: IrId::new(22) },
        ),
        /* 24 */
        node(
            IrKind::Lambda,
            IrData::Lambda { pattern: IrId::new(11), body: IrId::new(23), frame: None },
        ),
    ];
    (
        arena(nodes),
        IrId::new(10),
        IrId::new(24),
        IrId::new(0),
        IrId::new(9),
    )
}

/// The fold-operator chain scans to arity 2 with one pinned callee site, and
/// lowers with the callee inlined and no self-calls.
#[test]
fn fold_operator_chain_scans_and_lowers_with_pinned_inline() {
    let (arena, op_pattern, op_body, mod_pattern, mod_body) = fold_op_arena();
    let scan = scan_tier2_curried_chain(&arena, op_pattern, op_body).expect("op chain scans");
    assert_eq!(scan.arity(), 2);
    assert_eq!(
        scan.callee_sites(),
        &[JitTier2ChainCalleeSite {
            upval: (2, 0),
            arity: 2,
            chain_count: 1,
        }]
    );

    let callee_body =
        scan_tier2_pinned_callee(&arena, mod_pattern, mod_body, 2).expect("mod chain validates");
    assert_eq!(callee_body, IrId::new(8));

    let pinned = [JitTier2PinnedCallee {
        upval: (2, 0),
        arity: 2,
        body: callee_body,
    }];
    let lowering = lower_tier2_curried_chain(&arena, &scan, None, &pinned, 16)
        .expect("fold operator lowers");
    assert_eq!(lowering.arity(), 2);
    assert_eq!(lowering.self_call_count(), 0);
    assert_eq!(lowering.self_upval(), None);
    // Entry keeps the frozen 3-param argv ABI; inner carries rt, env, two
    // unboxed value pairs, and the budget.
    assert_eq!(lowering.entry().signature.params.len(), 3);
    assert_eq!(lowering.inner().signature.params.len(), 2 + 4 + 1);
}

/// Builds a tak-shaped arity-3 arena: `x: y: z: if y < x then
/// self (self (x-1) y z) (self (y-1) z x) (self (z-1) x y) else z` with the
/// self-callee at upvalue `(3, 0)`. Returns `(arena, root_pattern, root_body)`.
fn tak_arena() -> (IrArena, IrId, IrId) {
    let mut nodes = vec![
        /* 0 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        /* 1 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(1), default: None }),
        /* 2 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(2), default: None }),
        /* 3 */ node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 0 }), // y
        /* 4 */ node(IrKind::UpvalVar, IrData::Upval { depth: 2, slot: 0 }), // x
        /* 5 */
        node(
            IrKind::BinOp,
            IrData::Binary { op: BinOpKind::Lt, lhs: IrId::new(3), rhs: IrId::new(4) },
        ),
        /* 6 */ node(IrKind::Int, IrData::Int(1)),
    ];
    // Emits one `self (p0 - 1) p1 p2` chain and returns the chain root id.
    // Parameter reads: x = Upval(2,0), y = Upval(1,0), z = Local(0).
    let mut param = |nodes: &mut Vec<IrNode>, which: u32| -> IrId {
        let id = IrId::new(nodes.len() as u32);
        match which {
            0 => nodes.push(node(IrKind::UpvalVar, IrData::Upval { depth: 2, slot: 0 })),
            1 => nodes.push(node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 0 })),
            _ => nodes.push(node(IrKind::LocalVar, IrData::Local { slot: 0 })),
        }
        id
    };
    let mut chain = |nodes: &mut Vec<IrNode>, a: u32, b: u32, c: u32| -> IrId {
        let head = IrId::new(nodes.len() as u32);
        nodes.push(node(IrKind::UpvalVar, IrData::Upval { depth: 3, slot: 0 }));
        let first = param(nodes, a);
        let sub = IrId::new(nodes.len() as u32);
        nodes.push(node(
            IrKind::BinOp,
            IrData::Binary { op: BinOpKind::Sub, lhs: first, rhs: IrId::new(6) },
        ));
        let wrapped = IrId::new(nodes.len() as u32);
        nodes.push(node(IrKind::ThunkAlloc, IrData::Node(sub)));
        let apply1 = IrId::new(nodes.len() as u32);
        nodes.push(node(IrKind::Apply, IrData::Pair { first: head, second: wrapped }));
        let second = param(nodes, b);
        let apply2 = IrId::new(nodes.len() as u32);
        nodes.push(node(IrKind::Apply, IrData::Pair { first: apply1, second }));
        let third = param(nodes, c);
        let apply3 = IrId::new(nodes.len() as u32);
        nodes.push(node(IrKind::Apply, IrData::Pair { first: apply2, second: third }));
        apply3
    };
    let inner_a = chain(&mut nodes, 0, 1, 2); // self (x-1) y z
    let inner_b = chain(&mut nodes, 1, 2, 0); // self (y-1) z x
    let inner_c = chain(&mut nodes, 2, 0, 1); // self (z-1) x y
    // Outer chain: self inner_a inner_b inner_c.
    let head = IrId::new(nodes.len() as u32);
    nodes.push(node(IrKind::UpvalVar, IrData::Upval { depth: 3, slot: 0 }));
    let apply1 = IrId::new(nodes.len() as u32);
    nodes.push(node(IrKind::Apply, IrData::Pair { first: head, second: inner_a }));
    let apply2 = IrId::new(nodes.len() as u32);
    nodes.push(node(IrKind::Apply, IrData::Pair { first: apply1, second: inner_b }));
    let apply3 = IrId::new(nodes.len() as u32);
    nodes.push(node(IrKind::Apply, IrData::Pair { first: apply2, second: inner_c }));
    let z_read = IrId::new(nodes.len() as u32);
    nodes.push(node(IrKind::LocalVar, IrData::Local { slot: 0 }));
    let body = IrId::new(nodes.len() as u32);
    nodes.push(node(
        IrKind::If,
        IrData::Triple { first: IrId::new(5), second: apply3, third: z_read },
    ));
    let inner_lambda = IrId::new(nodes.len() as u32);
    nodes.push(node(
        IrKind::Lambda,
        IrData::Lambda { pattern: IrId::new(2), body, frame: None },
    ));
    let middle_lambda = IrId::new(nodes.len() as u32);
    nodes.push(node(
        IrKind::Lambda,
        IrData::Lambda { pattern: IrId::new(1), body: inner_lambda, frame: None },
    ));
    // The scan takes the ROOT lambda's own (pattern, body): the outermost
    // formal and the middle lambda node.
    (arena(nodes), IrId::new(0), middle_lambda)
}

/// The tak shape scans to arity 3 with four full self chains and lowers to a
/// self-recursive fused body.
#[test]
fn tak_chain_scans_and_lowers_with_direct_self_calls() {
    let (arena, root_pattern, root_body) = tak_arena();
    let scan = scan_tier2_curried_chain(&arena, root_pattern, root_body).expect("tak scans");
    assert_eq!(scan.arity(), 3);
    assert_eq!(
        scan.callee_sites(),
        &[JitTier2ChainCalleeSite {
            upval: (3, 0),
            arity: 3,
            chain_count: 4,
        }]
    );

    let lowering = lower_tier2_curried_chain(&arena, &scan, Some((3, 0)), &[], 32)
        .expect("tak lowers");
    assert_eq!(lowering.arity(), 3);
    assert_eq!(lowering.self_call_count(), 4);
    assert_eq!(lowering.self_upval(), Some((3, 0)));
    assert_eq!(lowering.entry().signature.params.len(), 3);
    assert_eq!(lowering.inner().signature.params.len(), 2 + 6 + 1);
}

/// A callee applied with two different chain lengths is rejected by the scan
/// (a partial application could escape).
#[test]
fn inconsistent_callee_chain_arity_is_rejected() {
    let nodes = vec![
        /* 0 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        /* 1 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(1), default: None }),
        /* 2 */ node(IrKind::UpvalVar, IrData::Upval { depth: 2, slot: 0 }),
        /* 3 */ node(IrKind::LocalVar, IrData::Local { slot: 0 }),
        /* 4 */ node(IrKind::Apply, IrData::Pair { first: IrId::new(2), second: IrId::new(3) }),
        /* 5 */ node(IrKind::UpvalVar, IrData::Upval { depth: 2, slot: 0 }),
        /* 6 */ node(IrKind::Apply, IrData::Pair { first: IrId::new(5), second: IrId::new(4) }),
        /* 7 */ node(IrKind::Int, IrData::Int(1)),
        /* 8 */ node(IrKind::Apply, IrData::Pair { first: IrId::new(6), second: IrId::new(7) }),
        /* 9 */
        node(
            IrKind::Lambda,
            IrData::Lambda { pattern: IrId::new(1), body: IrId::new(8), frame: None },
        ),
    ];
    let arena = arena(nodes);
    assert!(scan_tier2_curried_chain(&arena, IrId::new(0), IrId::new(9)).is_err());
}

/// A single-formal (arity-1) lambda is outside the chain lowerer's domain.
#[test]
fn arity_one_lambda_is_rejected() {
    let nodes = vec![
        node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        node(IrKind::LocalVar, IrData::Local { slot: 0 }),
    ];
    let arena = arena(nodes);
    assert!(scan_tier2_curried_chain(&arena, IrId::new(0), IrId::new(1)).is_err());
}

/// A pinned callee whose body applies anything is rejected as call-free.
#[test]
fn pinned_callee_with_a_call_is_rejected() {
    let nodes = vec![
        /* 0 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        /* 1 */ node(IrKind::Formal, IrData::Formal { name: Symbol::new(1), default: None }),
        /* 2 */ node(IrKind::UpvalVar, IrData::Upval { depth: 2, slot: 0 }),
        /* 3 */ node(IrKind::LocalVar, IrData::Local { slot: 0 }),
        /* 4 */ node(IrKind::Apply, IrData::Pair { first: IrId::new(2), second: IrId::new(3) }),
        /* 5 */
        node(
            IrKind::Lambda,
            IrData::Lambda { pattern: IrId::new(1), body: IrId::new(4), frame: None },
        ),
    ];
    let arena = arena(nodes);
    assert!(scan_tier2_pinned_callee(&arena, IrId::new(0), IrId::new(5), 2).is_err());
}

/// A stray upvalue read beyond the parameter frames (not a call head) is
/// outside the fused grammar.
#[test]
fn stray_deep_upvalue_read_is_rejected() {
    let nodes = vec![
        node(IrKind::Formal, IrData::Formal { name: Symbol::new(0), default: None }),
        node(IrKind::Formal, IrData::Formal { name: Symbol::new(1), default: None }),
        node(IrKind::UpvalVar, IrData::Upval { depth: 2, slot: 0 }),
        node(
            IrKind::Lambda,
            IrData::Lambda { pattern: IrId::new(1), body: IrId::new(2), frame: None },
        ),
    ];
    let arena = arena(nodes);
    assert!(scan_tier2_curried_chain(&arena, IrId::new(0), IrId::new(3)).is_err());
}
