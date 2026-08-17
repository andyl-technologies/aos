//! Lowering-time cost estimate for a tier-1 body, driving profit-based promotion.
//!
//! A dispatched tier-1 body pays a fixed per-call *harness*: the native call
//! itself, a [`RuntimeJitContext`](ratchet_oracle) pin, a trap-scope swap, and a
//! GC-safety environment clone (measured at roughly one to three microseconds in
//! the RFC-0007 cost decomposition). Promoting a body only pays off when its
//! native execution saves more interpreter work than that harness costs. This
//! module estimates the saving from the lowered CLIF [`Function`], so a promotion
//! policy can gate on profit rather than promoting every lowerable shape.
//!
//! # Cost model
//!
//! The estimate splits a body's CLIF instructions into two classes:
//!
//! - **Helper calls** ([`call_insts`](Tier1BodyCost::call_insts)): every `call`
//!   or `call_indirect` back into the runtime — `aos_env_get`, `aos_force`,
//!   `aos_primop_call`, `aos_apply`, `aos_update`, and the like. A delegating
//!   call re-enters the exact interpreter work the tree walk would do (plus the
//!   call overhead), so it saves nothing; a pure trampoline body is *all*
//!   helper call and is net-negative by construction.
//! - **Native instructions** ([`native_insts`](Tier1BodyCost::native_insts)):
//!   everything else — the inline arithmetic, tag guards, branches, and constant
//!   materialization the body runs itself instead of dispatching through the
//!   interpreter. These are the instructions that replace recursive `eval_node`
//!   dispatch and `Value` boxing, so their count is the proxy for the saving.
//!
//! A body profits when its native instruction count clears a threshold chosen to
//! represent the harness break-even (see [`Tier1BodyCost::is_profitable`]). A
//! single-op trampoline (one call, a return) has a native count near zero and is
//! gated; a compound arithmetic tree (`a * b + c` over forced slots) accumulates
//! inline `imul`/`iadd`/guard instructions and clears it.
//!
//! # Deopt-guard conservatism
//!
//! An inline body's guards branch to a cold `aos_deopt` bailout block that never
//! runs on the hot (successful) path. This estimate counts that cold `aos_deopt`
//! call among [`call_insts`](Tier1BodyCost::call_insts) rather than singling it
//! out, which slightly under-credits the body's profit. That bias is safe for a
//! promotion gate: it can only withhold promotion from a marginal body, never
//! promote a net-negative one.

use cranelift_codegen::ir::Function;

/// A lowering-time cost estimate for one tier-1 body.
///
/// Produced by [`estimate_tier1_body_cost`] from a verified CLIF [`Function`].
/// The estimate is a static instruction census, not a runtime measurement: it
/// counts the instructions the lowerer emitted, classifying each as a runtime
/// helper call or native compute. See the [module docs](self) for the model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tier1BodyCost {
    /// The total number of CLIF instructions across every block of the body.
    total_insts: u32,
    /// The number of instructions that call back into the runtime (`call` /
    /// `call_indirect`), each of which delegates rather than saving work.
    call_insts: u32,
}

impl Tier1BodyCost {
    /// Returns the total CLIF instruction count of the body.
    #[must_use]
    pub const fn total_insts(&self) -> u32 {
        self.total_insts
    }

    /// Returns the number of runtime helper-call instructions in the body.
    ///
    /// Each is a `call` or `call_indirect` that re-enters the interpreter or a
    /// runtime helper, so it delegates the work rather than saving it.
    #[must_use]
    pub const fn call_insts(&self) -> u32 {
        self.call_insts
    }

    /// Returns the native (non-call) instruction count, the profit proxy.
    ///
    /// This is [`total_insts`](Self::total_insts) minus
    /// [`call_insts`](Self::call_insts): the inline arithmetic, tag guards,
    /// branches, and constants the body runs itself instead of dispatching
    /// through the interpreter. A larger count means more interpreter dispatch
    /// avoided, so it is the estimated saving a promotion trades against the
    /// per-dispatch harness.
    #[must_use]
    pub const fn native_insts(&self) -> u32 {
        self.total_insts.saturating_sub(self.call_insts)
    }

    /// Returns whether the body's native compute clears `native_inst_threshold`.
    ///
    /// A body is deemed profitable to promote when its
    /// [`native_insts`](Self::native_insts) is at least `native_inst_threshold`,
    /// the count chosen to represent the per-dispatch harness break-even. Below
    /// it, the native saving does not cover the harness and promoting the body
    /// regresses wall time, so the policy gates it and keeps the tree walk.
    #[must_use]
    pub const fn is_profitable(&self, native_inst_threshold: u32) -> bool {
        self.native_insts() >= native_inst_threshold
    }
}

/// Estimates the tier-1 cost of a lowered body from its CLIF function.
///
/// Walks every block in layout order and every instruction in each block,
/// counting the total instructions and the subset that are runtime helper calls
/// (`call` / `call_indirect`). The result is a static census used to decide
/// whether promoting the body would save more than the per-dispatch harness
/// costs; see the [module docs](self) for the cost model.
///
/// The walk is read-only and allocation-free, so it is cheap enough to run on
/// every lowered body at promotion time.
#[must_use]
pub fn estimate_tier1_body_cost(function: &Function) -> Tier1BodyCost {
    let mut total_insts: u32 = 0;
    let mut call_insts: u32 = 0;
    for block in function.layout.blocks() {
        for inst in function.layout.block_insts(block) {
            total_insts = total_insts.saturating_add(1);
            if function.dfg.insts[inst].opcode().is_call() {
                call_insts = call_insts.saturating_add(1);
            }
        }
    }
    Tier1BodyCost {
        total_insts,
        call_insts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ratchet_core::{
        EffectClass, IrArena, IrData, IrId, IrKind, IrNode, syntax::BinOpKind, syntax::Span,
    };

    use crate::lower::{
        lower_primop_call_ir_thunk_body_artifact, lower_tier1_ir_thunk_body_artifact,
    };

    /// Builds an integer-literal node.
    fn int(value: i64) -> IrNode {
        IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(value),
        )
    }

    /// Builds a binary-operator node over two operand ids.
    fn binop(op: BinOpKind, lhs: u32, rhs: u32) -> IrNode {
        IrNode::new(
            IrKind::BinOp,
            Span::new(0, 3),
            EffectClass::pure(),
            IrData::Binary {
                op,
                lhs: IrId::new(lhs),
                rhs: IrId::new(rhs),
            },
        )
    }

    /// A pure primop trampoline body is almost all helper call: its native
    /// instruction count is tiny and it is not profitable at any real threshold.
    #[test]
    fn primop_trampoline_body_is_not_profitable() {
        // The trampoline lowering is keyed only by the def-site root and the
        // primop node identity, so a bare root/module/node triple suffices.
        let root = IrId::new(0);
        let artifact = lower_primop_call_ir_thunk_body_artifact(root, 0, root)
            .expect("primop trampoline lowers");
        let cost = estimate_tier1_body_cost(artifact.function());
        assert!(
            cost.call_insts() >= 1,
            "a trampoline must contain the delegating call, got {cost:?}"
        );
        // A single delegating call plus its return is well under any harness
        // break-even threshold.
        assert!(
            !cost.is_profitable(4),
            "a pure trampoline must not be profitable, got {cost:?}"
        );
    }

    /// A nested arithmetic tree lowers to inline native ops, so its native
    /// instruction count exceeds a small trampoline's and clears a low threshold.
    ///
    /// Arith trees decline on the one-word carrier (their inline payload
    /// decode is two-word codegen), so this runs on the baseline only.
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn arithmetic_tree_body_has_more_native_compute_than_a_trampoline() {
        // `(1 + 2) * 3`: two nested integer BinOps over literals, lowering fully
        // inline with no runtime helper delegation.
        // 0:1  1:2  2:(1+2)  3:3  4:((1+2)*3)
        let arena = IrArena::from_raw_parts(
            vec![
                int(1),
                int(2),
                binop(BinOpKind::Add, 0, 1),
                int(3),
                binop(BinOpKind::Mul, 2, 3),
            ],
            Vec::new(),
        );
        let artifact = lower_tier1_ir_thunk_body_artifact(&arena, IrId::new(4))
            .expect("arithmetic tree lowers");
        let cost = estimate_tier1_body_cost(artifact.function());
        // The only call an all-literal arithmetic tree emits is the cold-path
        // `aos_deopt` guard bailout (never taken on the hot path), so it counts
        // at most one call while running its compute inline.
        assert!(
            cost.call_insts() <= 1,
            "an all-literal arithmetic tree delegates nothing on the hot path, got {cost:?}"
        );
        // The inline `imul`/`iadd`/guard instructions dominate: this compound body
        // has far more native compute than a one-call trampoline.
        assert!(
            cost.native_insts() >= 8,
            "a two-op arithmetic tree should have several native ops, got {cost:?}"
        );
        assert!(
            cost.is_profitable(8),
            "a compound arithmetic tree should clear a modest threshold, got {cost:?}"
        );
    }
}
