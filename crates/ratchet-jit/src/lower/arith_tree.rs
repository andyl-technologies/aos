//! Recursive CLIF lowering for scalar integer arithmetic and comparison trees.
//!
//! The bounded per-shape lowerers in [`super`] each wrap exactly one runtime
//! helper call. This module generalizes the `BinOp` slot to small expression
//! *trees*: an integer add/sub/mul/div or an integer comparison whose operands
//! are themselves integer literals, forced local-slot reads, or nested
//! arithmetic/comparison subexpressions. It emits the arithmetic inline in CLIF
//! rather than delegating each operation to a runtime helper, so a hot
//! arithmetic body runs as native code instead of a helper-call-per-op.
//!
//! # Runtime value ABI
//!
//! A compiled thunk body returns a runtime [`Value`](ratchet_value::value::Value)
//! as two machine words: the tag word and the payload word. An integer has tag
//! `0x00` and its raw two's-complement `i64` in the payload; a boolean has tag
//! `0x02` and `0`/`1` in the payload. Local-slot operands are loaded with
//! `aos_env_get` and forced with `aos_force`, which yields the same two-word
//! pair; literals materialize the pair directly.
//!
//! # Deoptimization discipline
//!
//! Inline arithmetic can only run when both operands are integers, so every
//! operation guards its operand tags at runtime and branches to a shared deopt
//! block when either is not an integer (a float, a type error, or the null trap
//! sentinel a failed force returns). Division additionally guards against a zero
//! divisor and the `i64::MIN / -1` overflow case, matching the tree walk which
//! errors on both. The deopt block calls the `aos_deopt` helper, which records a
//! deopt signal in the active runtime trap scope; the live engine observes it as
//! a silent deopt and re-runs the body through the tree walk.
//! Because forcing memoizes, the re-run observes the same operand values and
//! reproduces the exact value or error the tree walk would have produced, so a
//! deopt is never a parity divergence. Integer add/sub/mul wrap on overflow,
//! matching the tree walk's `wrapping_*`, so those need no overflow guard.
//!
//! Any shape outside this grammar fails to lower (returns a [`JitLowerError`]),
//! which blacklists the def-site: a body that cannot be proven safe stays on the
//! tree walk rather than risking a wrong compilation.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, condcodes::IntCC, types},
};
use ratchet_core::{
    IrArena, IrData, IrId, IrKind, runtime_thunk_call_signature, syntax::BinOpKind,
};

use super::{
    AOS_DEOPT_SYMBOL, AOS_ENV_GET_SYMBOL, AOS_FORCE_SYMBOL, AOS_UPVAL_GET_SYMBOL, JitLowerError,
    append_entry_block_params, clif_external_name_for_aos_deopt, clif_external_name_for_aos_force,
    clif_name_for_ir_root, import_env_get_function, import_runtime_helper_function,
    import_upval_get_function, stack_maps, thunk_body_artifact, verify_clif_function,
};
use crate::{
    abi::clif_signature_for_runtime_call,
    artifact::{JitClifArtifact, JitClifArtifactSource},
};

/// A Cranelift SSA value, aliased to avoid confusion with the runtime `Value`.
type ClifValue = cranelift_codegen::ir::Value;

/// The runtime tag word for an inline integer value (`ValueTag::Int`).
const TAG_INT: i64 = 0x00;
/// The runtime tag word for an inline boolean value (`ValueTag::Bool`).
const TAG_BOOL: i64 = 0x02;

/// The scalar operation a supported `BinOp` lowers to.
#[derive(Clone, Copy)]
enum ArithKind {
    /// Wrapping integer addition.
    Add,
    /// Wrapping integer subtraction.
    Sub,
    /// Wrapping integer multiplication.
    Mul,
    /// Truncating integer division, guarded against zero and `MIN / -1`.
    Div,
    /// A signed integer comparison producing a boolean.
    Cmp(IntCC),
}

/// Classifies a binary operator as an inline scalar operation, if supported.
///
/// Returns `None` for operators outside the arithmetic/comparison grammar
/// (including attr update, list concat, and the short-circuiting boolean and
/// pipe operators), so the caller can reject the shape.
fn classify(op: BinOpKind) -> Option<ArithKind> {
    Some(match op {
        BinOpKind::Add => ArithKind::Add,
        BinOpKind::Sub => ArithKind::Sub,
        BinOpKind::Mul => ArithKind::Mul,
        BinOpKind::Div => ArithKind::Div,
        BinOpKind::Lt => ArithKind::Cmp(IntCC::SignedLessThan),
        BinOpKind::Gt => ArithKind::Cmp(IntCC::SignedGreaterThan),
        BinOpKind::Le => ArithKind::Cmp(IntCC::SignedLessThanOrEqual),
        BinOpKind::Ge => ArithKind::Cmp(IntCC::SignedGreaterThanOrEqual),
        BinOpKind::Eq => ArithKind::Cmp(IntCC::Equal),
        BinOpKind::Ne => ArithKind::Cmp(IntCC::NotEqual),
        _ => return None,
    })
}

/// Shared CLIF references and entry values threaded through the tree emitter.
struct ArithCtx {
    /// Imported `aos_env_get` helper for local-slot loads.
    env_get: cranelift_codegen::ir::FuncRef,
    /// Imported `aos_upval_get` helper for upvalue-slot loads.
    ///
    /// `None` when the operand tree reads no upvalue, so a pure local-slot
    /// arithmetic body declares no `aos_upval_get` import.
    upval_get: Option<cranelift_codegen::ir::FuncRef>,
    /// Imported `aos_force` helper (forces loaded local-slot values to WHNF).
    force: cranelift_codegen::ir::FuncRef,
    /// Compiled-frame bindings and user stack maps for every force call.
    safepoints: stack_maps::ForceSafepoints,
    /// Imported `aos_deopt` helper called by the shared deopt block.
    deopt_fn: cranelift_codegen::ir::FuncRef,
    /// The runtime-context entry parameter passed to forcing and deopt calls.
    rt: ClifValue,
    /// The environment entry parameter passed to slot loads.
    env: ClifValue,
    /// The shared block every runtime guard branches to on failure.
    deopt: cranelift_codegen::ir::Block,
}

/// Lowers a `BinOp` thunk body, routing attr update and scalar arithmetic.
///
/// `root` is either the `BinOp` node itself or a [`IrKind::ThunkAlloc`] wrapper
/// around one. Attr update (`//`) stays with the dedicated force-and-merge
/// lowerer in [`super`]; every other supported operator lowers as an inline
/// scalar arithmetic or comparison tree.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] or [`JitLowerError::MissingIrBody`]
/// when the node or its thunk body is absent,
/// [`JitLowerError::MismatchedIrNodeData`] when a node carries the wrong
/// payload, [`JitLowerError::UnsupportedArithOp`] for an operator outside the
/// supported set, and the operand and verifier errors of
/// [`build_arith_function`] for a non-lowerable operand tree.
pub(super) fn lower_binop_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;
    let binop_id = match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => body,
        (IrKind::ThunkAlloc, data) => {
            return Err(JitLowerError::MismatchedIrNodeData {
                kind: IrKind::ThunkAlloc,
                data,
                expected: "body node",
            });
        }
        _ => root,
    };

    let (op, _lhs, _rhs) = binop_operands(arena, binop_id)?;
    if op == BinOpKind::Update {
        return super::lower_update_local_slots_ir_thunk_body_artifact(arena, root);
    }
    if classify(op).is_none() {
        return Err(JitLowerError::UnsupportedArithOp { op });
    }

    let function = build_arith_function(arena, root, binop_id)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Returns the operator and operand ids of a `BinOp` node.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrBody`] when the node is absent and
/// [`JitLowerError::MismatchedIrNodeData`] when it is not a binary-operator node
/// with a binary payload.
fn binop_operands(arena: &IrArena, id: IrId) -> Result<(BinOpKind, IrId, IrId), JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::BinOp, IrData::Binary { op, lhs, rhs }) => Ok((op, lhs, rhs)),
        (IrKind::BinOp, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::BinOp,
            data,
            expected: "binary operator payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand { operand: id, kind }),
    }
}

/// Builds the verified CLIF function for a scalar arithmetic/comparison tree.
///
/// The function has the frozen compiled-thunk runtime signature and imports
/// `aos_env_get` and `aos_force`. It emits the operand tree inline, returns the
/// computed two-word runtime value, and fills the shared deopt block.
///
/// # Errors
///
/// Returns [`JitLowerError::Abi`] when the runtime signature cannot be lowered,
/// the operand errors of [`emit_binop`], [`JitLowerError::MissingEntryBlockParameter`]
/// when the entry block lacks the runtime or environment parameter, and
/// [`JitLowerError::Verifier`] when Cranelift rejects the generated body.
fn build_arith_function(
    arena: &IrArena,
    root: IrId,
    binop_id: IrId,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(clif_name_for_ir_root(root), signature);
    let env_get = import_env_get_function(&mut function)?;
    let (op, lhs, rhs) = binop_operands(arena, binop_id)?;
    let upval_get = if arith_tree_reads_upval(arena, lhs) || arith_tree_reads_upval(arena, rhs) {
        Some(import_upval_get_function(&mut function)?)
    } else {
        None
    };
    let force = import_runtime_helper_function(
        &mut function,
        AOS_FORCE_SYMBOL,
        clif_external_name_for_aos_force(),
    )?;
    let safepoints = stack_maps::ForceSafepoints::import(&mut function)?;
    let deopt_fn = import_runtime_helper_function(
        &mut function,
        AOS_DEOPT_SYMBOL,
        clif_external_name_for_aos_deopt(),
    )?;
    let entry_block = append_entry_block_params(&mut function);
    let deopt = function.dfg.make_block();

    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let params = cursor.func.dfg.block_params(entry_block);
    let rt = params
        .first()
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 0 })?;
    let env = params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let mut ctx = ArithCtx {
        env_get,
        upval_get,
        force,
        safepoints,
        deopt_fn,
        rt,
        env,
        deopt,
    };

    let mut live = Vec::new();
    let (tag, payload) = emit_binop(&mut cursor, arena, &mut ctx, op, lhs, rhs, &mut live)?;
    cursor.ins().return_(&[tag, payload]);
    emit_deopt_block(&mut cursor, &ctx)?;
    drop(cursor);

    verify_clif_function(&function)?;
    Ok(function)
}

/// Emits one operand subtree, returning its forced `(tag, payload)` word pair.
///
/// Integer literals materialize the pair directly; local-slot reads load and
/// force the slot; nested binary operators recurse through [`emit_binop`]. The
/// cursor is left in the block where the returned values are defined.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingArithOperand`] when the operand node is
/// absent, [`JitLowerError::UnsupportedArithOperand`] for an operand outside the
/// grammar, and the call-arity errors of the helper calls it emits.
fn emit_operand(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ArithCtx,
    id: IrId,
    live: &mut Vec<[ClifValue; 2]>,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingArithOperand { operand: id })?;
    match (node.kind, node.data) {
        (IrKind::Int, IrData::Int(value)) => {
            let tag = cursor.ins().iconst(types::I64, TAG_INT);
            let payload = cursor.ins().iconst(types::I64, value);
            Ok((tag, payload))
        }
        (IrKind::LocalVar, IrData::Local { slot }) => {
            let slot = cursor.ins().iconst(types::I32, i64::from(slot));
            let loaded = call2(cursor, ctx.env_get, &[ctx.env, slot], AOS_ENV_GET_SYMBOL)?;
            let forced = ctx.safepoints.force(
                cursor,
                ctx.force,
                ctx.rt,
                loaded,
                live,
            )?;
            Ok((forced[0], forced[1]))
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            let upval_get =
                ctx.upval_get
                    .ok_or(JitLowerError::MissingRuntimeHelperSignature {
                        symbol_name: AOS_UPVAL_GET_SYMBOL,
                    })?;
            let depth = cursor.ins().iconst(types::I32, i64::from(depth));
            let slot = cursor.ins().iconst(types::I32, i64::from(slot));
            let loaded = call2(cursor, upval_get, &[ctx.env, depth, slot], AOS_UPVAL_GET_SYMBOL)?;
            let forced = ctx.safepoints.force(
                cursor,
                ctx.force,
                ctx.rt,
                loaded,
                live,
            )?;
            Ok((forced[0], forced[1]))
        }
        (IrKind::BinOp, IrData::Binary { op, lhs, rhs }) => {
            emit_binop(cursor, arena, ctx, op, lhs, rhs, live)
        }
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand { operand: id, kind }),
    }
}

/// Returns true when any leaf of the operand subtree rooted at `id` is an upvalue.
///
/// Walks the same integer-arithmetic grammar [`emit_operand`] accepts (literals,
/// slot reads, nested binary operators). Used to decide whether the arithmetic
/// body needs to import `aos_upval_get`, so a pure local-slot tree declares no
/// upvalue import.
fn arith_tree_reads_upval(arena: &IrArena, id: IrId) -> bool {
    let Some(node) = arena.node(id).copied() else {
        return false;
    };
    match (node.kind, node.data) {
        (IrKind::UpvalVar, _) => true,
        (IrKind::BinOp, IrData::Binary { lhs, rhs, .. }) => {
            arith_tree_reads_upval(arena, lhs) || arith_tree_reads_upval(arena, rhs)
        }
        _ => false,
    }
}

/// Emits one binary operation over two operand subtrees.
///
/// Both operands are lowered, then guarded to be integers before the operation
/// runs; a non-integer operand branches to the shared deopt block. Division adds
/// zero-divisor and `MIN / -1` guards. Arithmetic yields an integer word pair;
/// comparison yields a boolean word pair. The cursor is left in the block where
/// the result values are defined.
///
/// # Errors
///
/// Returns [`JitLowerError::UnsupportedArithOp`] for an unsupported operator and
/// the operand errors of [`emit_operand`].
fn emit_binop(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ArithCtx,
    op: BinOpKind,
    lhs: IrId,
    rhs: IrId,
    live: &mut Vec<[ClifValue; 2]>,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    let kind = classify(op).ok_or(JitLowerError::UnsupportedArithOp { op })?;

    let (lhs_tag, lhs_payload) = emit_operand(cursor, arena, ctx, lhs, live)?;
    let lhs_index = live.len();
    live.push([lhs_tag, lhs_payload]);
    let (rhs_tag, rhs_payload) = emit_operand(cursor, arena, ctx, rhs, live)?;
    let [lhs_tag, lhs_payload] = live[lhs_index];
    live.truncate(lhs_index);

    // Both operands must be integers (tag word == 0) for the inline path.
    let lhs_is_int = cursor.ins().icmp_imm(IntCC::Equal, lhs_tag, TAG_INT);
    let rhs_is_int = cursor.ins().icmp_imm(IntCC::Equal, rhs_tag, TAG_INT);
    let both_int = cursor.ins().band(lhs_is_int, rhs_is_int);
    let compute = cursor.func.dfg.make_block();
    cursor.ins().brif(both_int, compute, &[], ctx.deopt, &[]);
    cursor.insert_block(compute);

    match kind {
        ArithKind::Add => {
            let result = cursor.ins().iadd(lhs_payload, rhs_payload);
            Ok(int_word_pair(cursor, result))
        }
        ArithKind::Sub => {
            let result = cursor.ins().isub(lhs_payload, rhs_payload);
            Ok(int_word_pair(cursor, result))
        }
        ArithKind::Mul => {
            let result = cursor.ins().imul(lhs_payload, rhs_payload);
            Ok(int_word_pair(cursor, result))
        }
        ArithKind::Div => {
            // The tree walk errors on a zero divisor and on `i64::MIN / -1`;
            // both must deopt rather than take Cranelift's trapping `sdiv`.
            let nonzero = cursor.ins().icmp_imm(IntCC::NotEqual, rhs_payload, 0);
            let lhs_is_min = cursor.ins().icmp_imm(IntCC::Equal, lhs_payload, i64::MIN);
            let rhs_is_neg1 = cursor.ins().icmp_imm(IntCC::Equal, rhs_payload, -1);
            let is_overflow = cursor.ins().band(lhs_is_min, rhs_is_neg1);
            let not_overflow = cursor.ins().icmp_imm(IntCC::Equal, is_overflow, 0);
            let safe = cursor.ins().band(nonzero, not_overflow);
            let divide = cursor.func.dfg.make_block();
            cursor.ins().brif(safe, divide, &[], ctx.deopt, &[]);
            cursor.insert_block(divide);
            let result = cursor.ins().sdiv(lhs_payload, rhs_payload);
            Ok(int_word_pair(cursor, result))
        }
        ArithKind::Cmp(condition) => {
            let compared = cursor.ins().icmp(condition, lhs_payload, rhs_payload);
            let payload = cursor.ins().uextend(types::I64, compared);
            let tag = cursor.ins().iconst(types::I64, TAG_BOOL);
            Ok((tag, payload))
        }
    }
}

/// Materializes an integer runtime value word pair from a computed payload.
fn int_word_pair(cursor: &mut FuncCursor, payload: ClifValue) -> (ClifValue, ClifValue) {
    let tag = cursor.ins().iconst(types::I64, TAG_INT);
    (tag, payload)
}

/// Fills the shared deopt block with a call to the `aos_deopt` helper.
///
/// `aos_deopt` records a deopt control signal in the active trap scope and
/// returns the trap sentinel; the engine observes the recorded trap as a silent
/// deopt and re-runs the body through the tree walk. The deopt-record pointer is
/// unused by the wrapper, so a null pointer is passed. The returned sentinel is
/// meaningless and discarded by the caller.
///
/// # Errors
///
/// Returns [`JitLowerError::InvalidRuntimeCallResultArity`] if the frozen
/// `aos_deopt` ABI stops returning a two-word value.
fn emit_deopt_block(cursor: &mut FuncCursor, ctx: &ArithCtx) -> Result<(), JitLowerError> {
    cursor.insert_block(ctx.deopt);
    let deopt_record = cursor.ins().iconst(types::I64, 0);
    let sentinel = call2(
        cursor,
        ctx.deopt_fn,
        &[ctx.rt, deopt_record],
        AOS_DEOPT_SYMBOL,
    )?;
    cursor.ins().return_(&[sentinel[0], sentinel[1]]);
    Ok(())
}

/// Emits a call and returns its exactly-two result values.
///
/// # Errors
///
/// Returns [`JitLowerError::InvalidRuntimeCallResultArity`] when the callee does
/// not produce exactly two CLIF results, i.e. the frozen two-word `Value` return
/// ABI changed.
fn call2(
    cursor: &mut FuncCursor,
    callee: cranelift_codegen::ir::FuncRef,
    args: &[ClifValue],
    symbol_name: &'static str,
) -> Result<[ClifValue; 2], JitLowerError> {
    let call = cursor.ins().call(callee, args);
    let results = cursor.func.dfg.inst_results(call);
    if results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name,
            expected: 2,
            actual: results.len(),
        });
    }
    Ok([results[0], results[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    use cranelift_codegen::ir::Opcode;
    use ratchet_core::{EffectClass, IrNode, syntax::Span};

    use crate::artifact::JitClifArtifactSource;

    /// Builds a `LocalVar` node reading `slot`.
    fn local(slot: u32) -> IrNode {
        IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Local { slot },
        )
    }

    /// Builds an `UpvalVar` node reading `slot` from `depth` frames up.
    fn upval(depth: u32, slot: u32) -> IrNode {
        IrNode::new(
            IrKind::UpvalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Upval { depth, slot },
        )
    }

    /// Builds an integer-literal node.
    fn int(value: i64) -> IrNode {
        IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(value),
        )
    }

    /// Builds a floating-point-literal node.
    fn float(value: f64) -> IrNode {
        IrNode::new(
            IrKind::Float,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Float(value),
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

    /// Builds a thunk-allocation wrapper around a body node.
    fn thunk_alloc(body: u32) -> IrNode {
        IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 3),
            EffectClass::pure(),
            IrData::Node(IrId::new(body)),
        )
    }

    fn arena(nodes: Vec<IrNode>) -> IrArena {
        IrArena::from_raw_parts(nodes, Vec::new())
    }

    /// A two-local binary operator over `op` lowers to a verified artifact.
    #[test]
    fn binary_local_slot_ops_lower_to_verified_artifacts() {
        let ops = [
            BinOpKind::Add,
            BinOpKind::Sub,
            BinOpKind::Mul,
            BinOpKind::Div,
            BinOpKind::Lt,
            BinOpKind::Gt,
            BinOpKind::Le,
            BinOpKind::Ge,
            BinOpKind::Eq,
            BinOpKind::Ne,
        ];
        for op in ops {
            let arena = arena(vec![local(0), local(1), binop(op, 0, 1)]);
            let artifact = lower_binop_ir_thunk_body_artifact(&arena, IrId::new(2))
                .unwrap_or_else(|error| panic!("{op:?} lowers: {error}"));
            assert_eq!(
                artifact.source(),
                JitClifArtifactSource::IrRoot(IrId::new(2))
            );
        }
    }

    /// An arithmetic operand reading an upvalue lowers to a verified artifact.
    #[test]
    fn upvalue_operand_arith_lowers_to_verified_artifact() {
        // 0:upval(depth 1, slot 0)  1:int 1  2:(upval + 1)
        let arena = arena(vec![upval(1, 0), int(1), binop(BinOpKind::Add, 0, 1)]);
        lower_binop_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("upvalue-operand arithmetic lowers");
    }

    /// A mixed local/upvalue arithmetic tree lowers to a verified artifact.
    #[test]
    fn mixed_local_and_upvalue_operand_arith_lowers() {
        // 0:local(0)  1:upval(depth 2, slot 1)  2:(local + upval)
        let arena = arena(vec![local(0), upval(2, 1), binop(BinOpKind::Mul, 0, 1)]);
        lower_binop_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("mixed local/upvalue arithmetic lowers");
    }

    /// A nested arithmetic tree `(a * b) + c` lowers to a verified artifact.
    #[test]
    fn nested_arithmetic_tree_lowers() {
        // 0:a 1:b 2:c 3:(a*b) 4:((a*b)+c)
        let arena = arena(vec![
            local(0),
            local(1),
            local(2),
            binop(BinOpKind::Mul, 0, 1),
            binop(BinOpKind::Add, 3, 2),
        ]);
        lower_binop_ir_thunk_body_artifact(&arena, IrId::new(4)).expect("nested tree lowers");
    }

    /// Each arithmetic force maps its input and preserves earlier operands.
    #[test]
    fn binary_local_forces_map_values_live_across_later_force() {
        let arena = arena(vec![local(0), local(1), binop(BinOpKind::Add, 0, 1)]);
        let artifact = lower_binop_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("two-force arithmetic lowers");
        let function = artifact.function();
        let maps = function
            .layout
            .blocks()
            .flat_map(|block| function.layout.block_insts(block))
            .filter_map(|inst| function.dfg.user_stack_map_entries(inst))
            .collect::<Vec<_>>();

        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0].len(), 2);
        assert_eq!(maps[0][0].offset, 24);
        assert_eq!(maps[0][1].offset, 32);
        assert_eq!(function.sized_stack_slots[maps[0][1].slot].size, 48);
        assert_eq!(maps[1].len(), 3);
        assert_eq!(maps[1][0].offset, 24);
        assert_eq!(maps[1][1].offset, 32);
        assert_eq!(maps[1][2].offset, 48);
        assert_eq!(function.sized_stack_slots[maps[1][1].slot].size, 64);
        let reloads = function
            .layout
            .blocks()
            .flat_map(|block| function.layout.block_insts(block))
            .filter(|inst| function.dfg.insts[*inst].opcode() == Opcode::StackLoad)
            .count();
        assert_eq!(reloads, 2, "the first value reloads after the second force");
    }

    /// A comparison over nested arithmetic `(a + b) < c` lowers.
    #[test]
    fn comparison_over_arithmetic_lowers() {
        let arena = arena(vec![
            local(0),
            local(1),
            local(2),
            binop(BinOpKind::Add, 0, 1),
            binop(BinOpKind::Lt, 3, 2),
        ]);
        lower_binop_ir_thunk_body_artifact(&arena, IrId::new(4)).expect("comparison tree lowers");
    }

    /// An integer literal operand `x + 1` lowers.
    #[test]
    fn integer_literal_operand_lowers() {
        let arena = arena(vec![local(0), int(1), binop(BinOpKind::Add, 0, 1)]);
        lower_binop_ir_thunk_body_artifact(&arena, IrId::new(2)).expect("literal operand lowers");
    }

    /// A `ThunkAlloc` wrapper around an arithmetic body lowers.
    #[test]
    fn thunk_alloc_wrapped_body_lowers() {
        let arena = arena(vec![
            local(0),
            local(1),
            binop(BinOpKind::Add, 0, 1),
            thunk_alloc(2),
        ]);
        let artifact = lower_binop_ir_thunk_body_artifact(&arena, IrId::new(3))
            .expect("thunk-wrapped body lowers");
        assert_eq!(
            artifact.source(),
            JitClifArtifactSource::IrRoot(IrId::new(3))
        );
    }

    /// The attr-update operator stays routed to the dedicated update lowerer.
    #[test]
    fn update_operator_routes_to_update_lowerer() {
        let arena = arena(vec![local(0), local(1), binop(BinOpKind::Update, 0, 1)]);
        lower_binop_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("update routes to the update lowerer");
    }

    /// List concat is not a scalar arithmetic operator and is rejected.
    #[test]
    fn concat_operator_is_rejected() {
        let arena = arena(vec![local(0), local(1), binop(BinOpKind::Concat, 0, 1)]);
        let error = lower_binop_ir_thunk_body_artifact(&arena, IrId::new(2))
            .err()
            .expect("concat is rejected");
        assert!(matches!(
            error,
            JitLowerError::UnsupportedArithOp {
                op: BinOpKind::Concat
            }
        ));
    }

    /// A short-circuiting boolean operator is rejected by the scalar lowerer.
    #[test]
    fn boolean_operator_is_rejected() {
        let arena = arena(vec![local(0), local(1), binop(BinOpKind::And, 0, 1)]);
        let error = lower_binop_ir_thunk_body_artifact(&arena, IrId::new(2))
            .err()
            .expect("boolean and is rejected");
        assert!(matches!(
            error,
            JitLowerError::UnsupportedArithOp { op: BinOpKind::And }
        ));
    }

    /// A float-literal operand is outside the inline integer grammar.
    #[test]
    fn float_literal_operand_is_rejected() {
        let arena = arena(vec![local(0), float(1.5), binop(BinOpKind::Add, 0, 1)]);
        let error = lower_binop_ir_thunk_body_artifact(&arena, IrId::new(2))
            .err()
            .expect("float operand is rejected");
        assert!(matches!(
            error,
            JitLowerError::UnsupportedArithOperand {
                operand,
                kind: IrKind::Float,
            } if operand == IrId::new(1)
        ));
    }

    /// A binary operator referencing an absent operand is rejected.
    #[test]
    fn missing_operand_is_rejected() {
        let arena = arena(vec![local(0), binop(BinOpKind::Add, 0, 9)]);
        let error = lower_binop_ir_thunk_body_artifact(&arena, IrId::new(1))
            .err()
            .expect("missing operand is rejected");
        assert!(matches!(
            error,
            JitLowerError::MissingArithOperand { operand } if operand == IrId::new(9)
        ));
    }
}
