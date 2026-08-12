//! One-word (Candidate-C) CLIF lowering for scalar arithmetic trees.
//!
//! The compressed-word sibling of [`super::arith_tree`]: same grammar (integer
//! literals, forced local/upvalue slot reads, nested arithmetic/comparison
//! subtrees), different value representation. A Candidate-C runtime value is a
//! single 64-bit word whose high half carries the kind, arena domain, and
//! forced bit; an inline integer's high half is all zero and its low half is
//! the sign-extended `i32` payload.
//!
//! # Emission strategy
//!
//! Instead of threading `(tag, payload)` pairs per operation, this emitter
//! decodes at the leaves and encodes once at the root:
//!
//! - every leaf (literal or forced slot read) is guarded to be an inline
//!   integer (`word >> 32 == 0`) and decoded by sign-extending its low half;
//!   boxed integers, floats, and every other kind branch to the shared deopt
//!   block;
//! - the operation tree computes on plain `i64` values with wrapping ops,
//!   which is exactly the tree walk's per-step `wrapping_*` semantics — the
//!   inline `i32` range only constrains the *representation* of materialized
//!   values, and intermediates never materialize;
//! - the root result is re-encoded as an inline word when it fits `i32`, and
//!   deopts otherwise (the tree walk re-runs and boxes the wide result).
//!   Comparisons select between the two canonical boolean words, which are
//!   always inline.
//!
//! Division keeps both tree-walk guards (zero divisor and `i64::MIN / -1`):
//! although decoded leaves are `i32`-range, nested intermediates are full
//! wrapped `i64` values, so the overflow case is reachable.
//!
//! Deoptimization discipline is identical to the two-word emitter: forcing
//! memoizes, so a deopted re-run observes the same operands and reproduces the
//! exact tree-walk value or error — a deopt is never a parity divergence.
//! Decoded integers are not heap references, so only each force call's input
//! word needs a stack-map spill; computed `i64`s stay in SSA across
//! safepoints.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, condcodes::IntCC, types},
};
use ratchet_core::{
    IrArena, IrData, IrId, IrKind, runtime_thunk_call_signature, syntax::BinOpKind,
};
use ratchet_value::value::compressed::CompressedValueWord;

use super::arith_tree::{ArithKind, arith_tree_reads_upval, binop_operands, classify};
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

/// Shared CLIF references and entry values threaded through the tree emitter.
struct CompressedArithCtx {
    /// Imported `aos_env_get` helper for local-slot loads.
    env_get: cranelift_codegen::ir::FuncRef,
    /// Imported `aos_upval_get` helper, present only when an operand needs it.
    upval_get: Option<cranelift_codegen::ir::FuncRef>,
    /// Imported `aos_force` helper (forces loaded slot values to WHNF).
    force: cranelift_codegen::ir::FuncRef,
    /// Imported stack-map enter/exit helpers bracketing each force call.
    stack_map_runtime: stack_maps::Runtime,
    /// The next force call's safepoint index.
    next_safepoint: u32,
    /// Imported `aos_deopt` helper called by the shared deopt block.
    deopt_fn: cranelift_codegen::ir::FuncRef,
    /// The runtime-context entry parameter passed to forcing and deopt calls.
    rt: ClifValue,
    /// The environment entry parameter passed to slot loads.
    env: ClifValue,
    /// The shared block every runtime guard branches to on failure.
    deopt: cranelift_codegen::ir::Block,
}

/// Lowers a non-`Update` scalar `BinOp` body on the one-word carrier.
///
/// `root` names the artifact (it may be the `BinOp` node or its `ThunkAlloc`
/// wrapper); `binop_id` is the operator node itself, already unwrapped and
/// `Update`-routed by [`super::arith_tree::lower_binop_ir_thunk_body_artifact`].
///
/// # Errors
///
/// Returns [`JitLowerError::UnsupportedArithOp`] for an operator outside the
/// supported set, [`JitLowerError::UnsupportedArithOperand`] for an operand
/// outside the grammar, plus the ABI, entry-parameter, call-arity, and
/// verifier errors of the emitted body. Integer literals of any width are in
/// the grammar: operands join the decoded `i64` computation directly and only
/// the root re-encode constrains the result.
pub(super) fn lower_binop_compressed_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
    binop_id: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
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
    let stack_map_runtime = stack_maps::import_runtime(&mut function)?;
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
    let mut ctx = CompressedArithCtx {
        env_get,
        upval_get,
        force,
        stack_map_runtime,
        next_safepoint: 0,
        deopt_fn,
        rt,
        env,
        deopt,
    };

    let kind = classify(op).ok_or(JitLowerError::UnsupportedArithOp { op })?;
    let result = match kind {
        ArithKind::Cmp(condition) => {
            let lhs_int = emit_int_operand(&mut cursor, arena, &mut ctx, lhs)?;
            let rhs_int = emit_int_operand(&mut cursor, arena, &mut ctx, rhs)?;
            let compared = cursor.ins().icmp(condition, lhs_int, rhs_int);
            let true_word = cursor
                .ins()
                .iconst(types::I64, CompressedValueWord::boolean(true).raw() as i64);
            let false_word = cursor
                .ins()
                .iconst(types::I64, CompressedValueWord::boolean(false).raw() as i64);
            cursor.ins().select(compared, true_word, false_word)
        }
        _ => {
            let computed = emit_int_binop(&mut cursor, arena, &mut ctx, kind, lhs, rhs)?;
            emit_inline_int_encode(&mut cursor, &ctx, computed)
        }
    };
    cursor.ins().return_(&[result]);
    emit_deopt_block(&mut cursor, &ctx)?;
    drop(cursor);

    verify_clif_function(&function)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Emits one operand subtree, returning its decoded `i64` integer value.
///
/// Literals materialize the integer directly — including out-of-inline-range
/// integers: an operand-position literal never materializes as a runtime
/// value, so it needs no inline word (it participates in the decoded `i64`
/// computation exactly like a wrapped intermediate; only the root re-encode
/// constrains the final result). Slot reads load, force, guard, and decode.
/// Nested binary operators recurse; a nested comparison is outside this
/// integer grammar and declines, so a body mixing booleans into arithmetic
/// stays on the tree walk (which reports the type error).
///
/// # Errors
///
/// Returns [`JitLowerError::MissingArithOperand`] when the operand node is
/// absent, [`JitLowerError::UnsupportedArithOperand`] for an operand outside
/// the grammar, and the call-arity errors of the helper calls it emits.
fn emit_int_operand(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut CompressedArithCtx,
    id: IrId,
) -> Result<ClifValue, JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingArithOperand { operand: id })?;
    match (node.kind, node.data) {
        (IrKind::Int, IrData::Int(value)) => Ok(cursor.ins().iconst(types::I64, value)),
        (IrKind::LocalVar, IrData::Local { slot }) => {
            let slot = cursor.ins().iconst(types::I32, i64::from(slot));
            let loaded = call1(cursor, ctx.env_get, &[ctx.env, slot], AOS_ENV_GET_SYMBOL)?;
            let forced = emit_force(cursor, ctx, loaded)?;
            Ok(emit_inline_int_decode(cursor, ctx, forced))
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            let upval_get = ctx
                .upval_get
                .ok_or(JitLowerError::MissingRuntimeHelperSignature {
                    symbol_name: AOS_UPVAL_GET_SYMBOL,
                })?;
            let depth = cursor.ins().iconst(types::I32, i64::from(depth));
            let slot = cursor.ins().iconst(types::I32, i64::from(slot));
            let loaded = call1(
                cursor,
                upval_get,
                &[ctx.env, depth, slot],
                AOS_UPVAL_GET_SYMBOL,
            )?;
            let forced = emit_force(cursor, ctx, loaded)?;
            Ok(emit_inline_int_decode(cursor, ctx, forced))
        }
        (IrKind::BinOp, IrData::Binary { op, lhs, rhs }) => {
            match classify(op).ok_or(JitLowerError::UnsupportedArithOp { op })? {
                ArithKind::Cmp(_) => Err(JitLowerError::UnsupportedArithOperand {
                    operand: id,
                    kind: IrKind::BinOp,
                }),
                kind => emit_int_binop(cursor, arena, ctx, kind, lhs, rhs),
            }
        }
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand { operand: id, kind }),
    }
}

/// Emits one integer binary operation over two decoded operand subtrees.
///
/// Add, sub, and mul use wrapping CLIF ops, matching the tree walk's
/// `wrapping_*` per-step semantics. Division guards the zero divisor and
/// `i64::MIN / -1` (reachable through wrapped intermediates) and deopts on
/// either, matching the tree walk's errors.
///
/// # Errors
///
/// Returns the operand errors of [`emit_int_operand`].
fn emit_int_binop(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut CompressedArithCtx,
    kind: ArithKind,
    lhs: IrId,
    rhs: IrId,
) -> Result<ClifValue, JitLowerError> {
    let lhs_int = emit_int_operand(cursor, arena, ctx, lhs)?;
    let rhs_int = emit_int_operand(cursor, arena, ctx, rhs)?;
    Ok(match kind {
        ArithKind::Add => cursor.ins().iadd(lhs_int, rhs_int),
        ArithKind::Sub => cursor.ins().isub(lhs_int, rhs_int),
        ArithKind::Mul => cursor.ins().imul(lhs_int, rhs_int),
        ArithKind::Div => {
            let nonzero = cursor.ins().icmp_imm(IntCC::NotEqual, rhs_int, 0);
            let lhs_is_min = cursor.ins().icmp_imm(IntCC::Equal, lhs_int, i64::MIN);
            let rhs_is_neg1 = cursor.ins().icmp_imm(IntCC::Equal, rhs_int, -1);
            let is_overflow = cursor.ins().band(lhs_is_min, rhs_is_neg1);
            let not_overflow = cursor.ins().icmp_imm(IntCC::Equal, is_overflow, 0);
            let safe = cursor.ins().band(nonzero, not_overflow);
            let divide = cursor.func.dfg.make_block();
            cursor.ins().brif(safe, divide, &[], ctx.deopt, &[]);
            cursor.insert_block(divide);
            cursor.ins().sdiv(lhs_int, rhs_int)
        }
        // The caller routes comparisons before reaching this emitter.
        ArithKind::Cmp(condition) => {
            let compared = cursor.ins().icmp(condition, lhs_int, rhs_int);
            cursor.ins().uextend(types::I64, compared)
        }
    })
}

/// Emits one mapped force call over a loaded slot word.
///
/// The input word may be a heap reference the collector rewrites, so it is
/// spilled into a one-word stack-map slot bracketed by the enter/exit binding
/// helpers, exactly like the delegating shapes' force calls.
fn emit_force(
    cursor: &mut FuncCursor,
    ctx: &mut CompressedArithCtx,
    input: ClifValue,
) -> Result<ClifValue, JitLowerError> {
    let binding = stack_maps::spill_values_one_word(cursor, &[input]);
    let safepoint = ctx.next_safepoint;
    ctx.next_safepoint =
        ctx.next_safepoint
            .checked_add(1)
            .ok_or(JitLowerError::MalformedForceSafepoint {
                reason: "function contains more than u32::MAX force calls",
            })?;
    stack_maps::enter(cursor, ctx.stack_map_runtime, ctx.rt, binding, safepoint);
    let call = cursor.ins().call(ctx.force, &[ctx.rt, input]);
    stack_maps::attach_one_word(cursor, call, binding);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    stack_maps::exit(cursor, ctx.stack_map_runtime, ctx.rt, binding);
    expect_one(&results, AOS_FORCE_SYMBOL)
}

/// Guards a forced word to be an inline integer and decodes its payload.
///
/// An inline integer's high half (kind, domain, forced bit) is all zero, so
/// the guard is a single compare of the shifted word; boxed integers, floats,
/// booleans, null, heap kinds, and the trap sentinel all branch to the shared
/// deopt block. The payload is the low half sign-extended from `i32`.
fn emit_inline_int_decode(
    cursor: &mut FuncCursor,
    ctx: &CompressedArithCtx,
    word: ClifValue,
) -> ClifValue {
    let high = cursor.ins().ushr_imm(word, 32);
    let is_inline_int = cursor.ins().icmp_imm(IntCC::Equal, high, 0);
    let decode = cursor.func.dfg.make_block();
    cursor
        .ins()
        .brif(is_inline_int, decode, &[], ctx.deopt, &[]);
    cursor.insert_block(decode);
    let low = cursor.ins().ireduce(types::I32, word);
    cursor.ins().sextend(types::I64, low)
}

/// Re-encodes a computed integer as an inline word, deopting when too wide.
///
/// The result fits the inline representation exactly when sign-extending its
/// low 32 bits reproduces it; a wider result deopts so the tree walk can box
/// it. An in-range value's inline word is its low half with a zero high half
/// (the `InlineInt` kind, domain, and forced bits are all zero).
fn emit_inline_int_encode(
    cursor: &mut FuncCursor,
    ctx: &CompressedArithCtx,
    computed: ClifValue,
) -> ClifValue {
    let low = cursor.ins().ireduce(types::I32, computed);
    let round_trip = cursor.ins().sextend(types::I64, low);
    let fits = cursor.ins().icmp(IntCC::Equal, round_trip, computed);
    let encode = cursor.func.dfg.make_block();
    cursor.ins().brif(fits, encode, &[], ctx.deopt, &[]);
    cursor.insert_block(encode);
    cursor.ins().band_imm(computed, 0xFFFF_FFFF)
}

/// Fills the shared deopt block with a call to the `aos_deopt` helper.
///
/// Mirrors the two-word emitter: `aos_deopt` records a deopt control signal in
/// the active trap scope and returns the (one-word) trap sentinel, which the
/// engine discards when it observes the recorded trap as a silent deopt.
///
/// # Errors
///
/// Returns [`JitLowerError::InvalidRuntimeCallResultArity`] if the frozen
/// `aos_deopt` ABI stops returning a one-word value.
fn emit_deopt_block(
    cursor: &mut FuncCursor,
    ctx: &CompressedArithCtx,
) -> Result<(), JitLowerError> {
    cursor.insert_block(ctx.deopt);
    let deopt_record = cursor.ins().iconst(types::I64, 0);
    let sentinel = call1(
        cursor,
        ctx.deopt_fn,
        &[ctx.rt, deopt_record],
        AOS_DEOPT_SYMBOL,
    )?;
    cursor.ins().return_(&[sentinel]);
    Ok(())
}

/// Emits a call and returns its exactly-one result value.
///
/// # Errors
///
/// Returns [`JitLowerError::InvalidRuntimeCallResultArity`] when the callee
/// does not produce exactly one CLIF result, i.e. the frozen one-word `Value`
/// return ABI changed.
fn call1(
    cursor: &mut FuncCursor,
    callee: cranelift_codegen::ir::FuncRef,
    args: &[ClifValue],
    symbol_name: &'static str,
) -> Result<ClifValue, JitLowerError> {
    let call = cursor.ins().call(callee, args);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    expect_one(&results, symbol_name)
}

/// Checks a one-word result arity and returns the single value.
fn expect_one(
    results: &[ClifValue],
    symbol_name: &'static str,
) -> Result<ClifValue, JitLowerError> {
    match results {
        [value] => Ok(*value),
        _ => Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name,
            expected: 1,
            actual: results.len(),
        }),
    }
}
