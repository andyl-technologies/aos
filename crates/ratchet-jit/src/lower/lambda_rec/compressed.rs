//! One-word (Candidate-C) tier-2 lowering for self-recursive lambda bodies.
//!
//! The compressed-word sibling of [`super`]: same grammar, same two-function
//! shape (`inner` + boundary `entry`), same deoptimization and budget
//! discipline, but every runtime value is one compressed word instead of a
//! `(tag, payload)` pair.
//!
//! # Value discipline (decoded core)
//!
//! Expressions carry one of two `i64` SSA classes (decoded-core-tier2-spec):
//! statically integer-typed nodes — literals of ANY width, arithmetic
//! results, and `if` joins whose arms are both integer-typed — live as plain
//! decoded `i64` values with no inline-range constraint (wrapping ops are
//! the tree walk's per-step semantics; intermediates never materialize as
//! runtime values); everything else is an encoded compressed word. Guards
//! happen only at word-to-int coercions (an inline integer's high half is
//! all zero) and encodes only at materialization points (the body return
//! and self-call arguments), where a wide value deopts so the tree walk
//! re-runs and boxes it. Comparisons select between the two canonical
//! boolean words. The parameter is forced at its first strict use on each
//! path, exactly like the two-word emitter and the tree walk (a force can
//! record impure observations, so its timing is load-bearing for trace
//! parity); the fast path skips the `aos_force` call when the raw argument
//! word is already an inline integer, which the recursion's own self-call
//! arguments always are.
//!
//! # Sentinel
//!
//! The internal deopt-unwind sentinel is a word whose kind byte is `0xFF` —
//! no valid compressed kind uses it — propagated by every self-call site and
//! translated to the canonical null word at the boundary before it could
//! materialize as a Rust `Value`.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, Signature, UserFuncName, condcodes::IntCC, types},
};
use ratchet_core::{
    IrArena, IrData, IrId, IrKind, runtime_lambda_call_signature, syntax::BinOpKind,
};
use ratchet_value::value::compressed::CompressedValueWord;

use super::{
    AOS_TIER2_LOCAL_FUNCTION_NAMESPACE, Block, ClifValue, JitTier2LambdaLowering,
    find_single_self_callee, import_tier2_local_function, inner_signature_from_entry,
    require_bare_formal_pattern, unwrap_thunk_alloc,
};
use crate::abi::clif_signature_for_runtime_call;
use crate::lower::{
    AOS_DEOPT_SYMBOL, AOS_FORCE_SYMBOL, JitLowerError, append_entry_block_params,
    clif_external_name_for_aos_deopt, clif_external_name_for_aos_force, clif_name_for_ir_root,
    import_runtime_helper_function, stack_maps, verify_clif_function,
};

/// The internal deopt-unwind sentinel word (invalid kind byte `0xFF`).
const TIER2_DEOPT_SENTINEL_WORD: i64 = 0xFF << 32;

/// The SSA class of one emitted expression (both classes are `i64` values).
///
/// `IntDecoded` is a plain decoded integer with no inline-range constraint;
/// `Word` is an encoded compressed word. Coercions between them are the only
/// guard/encode sites (see the module docs).
#[derive(Clone, Copy)]
enum TypedVal {
    /// A statically integer-typed value, decoded, full `i64` range.
    IntDecoded(ClifValue),
    /// An encoded compressed word (booleans, parameter reads, call results).
    Word(ClifValue),
}

/// The statically inferred class of a grammar expression.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExprClass {
    /// Produces a decoded integer.
    Int,
    /// Produces an encoded word (booleans, dynamic reads, call results).
    Word,
}

/// Infers the emission class of a grammar node.
///
/// Mirrors the emitter's own rules exactly: integer literals and arithmetic
/// are `Int`; `if` is `Int` only when both arms are; everything dynamic
/// (parameter reads, self-calls, booleans) is `Word`. Nodes outside the
/// grammar report `Word` — the emitter rejects them later regardless.
fn infer_class(arena: &IrArena, id: IrId) -> ExprClass {
    let Some(node) = arena.node(id).copied() else {
        return ExprClass::Word;
    };
    match (node.kind, node.data) {
        (IrKind::Int, _) => ExprClass::Int,
        (IrKind::BinOp, IrData::Binary { op, .. }) => match op {
            BinOpKind::Add | BinOpKind::Sub | BinOpKind::Mul | BinOpKind::Div => ExprClass::Int,
            _ => ExprClass::Word,
        },
        (
            IrKind::If,
            IrData::Triple { second, third, .. },
        ) => {
            if infer_class(arena, second) == ExprClass::Int
                && infer_class(arena, third) == ExprClass::Int
            {
                ExprClass::Int
            } else {
                ExprClass::Word
            }
        }
        _ => ExprClass::Word,
    }
}

/// Shared CLIF references threaded through the compressed body emitter.
struct CompressedLambdaCtx {
    /// Imported `aos_force` helper (forces the parameter at first strict use).
    force: cranelift_codegen::ir::FuncRef,
    /// Imported stack-map enter/exit helpers bracketing slow-path forces.
    stack_map_runtime: stack_maps::Runtime,
    /// The next force call's safepoint index.
    next_safepoint: u32,
    /// Imported `aos_deopt` helper called by the shared deopt block.
    deopt_fn: cranelift_codegen::ir::FuncRef,
    /// The module-local self reference for direct recursive calls.
    self_ref: cranelift_codegen::ir::FuncRef,
    /// The runtime-context entry parameter.
    rt: ClifValue,
    /// The environment entry parameter (passed through to self-calls).
    env: ClifValue,
    /// The raw (possibly still suspended) parameter word.
    arg_word: ClifValue,
    /// The remaining native self-call depth budget.
    budget: ClifValue,
    /// The shared guard-failure block: records a deopt trap, returns the sentinel.
    deopt: Block,
    /// The shared sentinel-propagation block: returns the sentinel unchanged.
    sentinel: Block,
    /// The self-callee upvalue coordinates every `Apply` must match.
    self_upval: (u32, u32),
    /// The number of self-call sites emitted so far.
    self_call_count: u32,
}

/// Lowers a single-parameter self-recursive lambda on the one-word carrier.
///
/// The one-word counterpart of
/// [`lower_tier2_self_recursive_lambda`](super::lower_tier2_self_recursive_lambda),
/// with the same grammar, budget, and deoptimization contract.
///
/// # Errors
///
/// Returns the same grammar, ABI, and verifier errors as the two-word
/// lowerer.
pub(in crate::lower) fn lower_tier2_self_recursive_lambda_compressed(
    arena: &IrArena,
    pattern: IrId,
    body: IrId,
    depth_budget: i64,
) -> Result<JitTier2LambdaLowering, JitLowerError> {
    require_bare_formal_pattern(arena, pattern)?;
    let self_upval = find_single_self_callee(arena, body)?;

    let entry_signature = clif_signature_for_runtime_call(runtime_lambda_call_signature())?;
    let inner_signature = inner_signature_from_entry(&entry_signature);

    let (inner, self_call_count) =
        build_inner_function(arena, body, inner_signature.clone(), self_upval)?;
    let entry = build_entry_function(body, entry_signature, &inner_signature, depth_budget)?;

    verify_clif_function(&inner)?;
    verify_clif_function(&entry)?;

    Ok(JitTier2LambdaLowering::from_cached_parts(
        entry,
        inner,
        body,
        self_upval,
        self_call_count,
    ))
}

/// Builds the compiled body function and returns it with its self-call count.
fn build_inner_function(
    arena: &IrArena,
    body: IrId,
    signature: Signature,
    self_upval: (u32, u32),
) -> Result<(Function, u32), JitLowerError> {
    let mut function = Function::with_name_signature(
        UserFuncName::user(AOS_TIER2_LOCAL_FUNCTION_NAMESPACE, body.as_u32()),
        signature.clone(),
    );
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
    let self_ref = import_tier2_local_function(&mut function, &signature);

    let entry_block = append_entry_block_params(&mut function);
    let deopt = function.dfg.make_block();
    let sentinel = function.dfg.make_block();

    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let params = cursor.func.dfg.block_params(entry_block).to_vec();
    let [rt, env, arg_word, budget] = params[..] else {
        return Err(JitLowerError::MissingEntryBlockParameter {
            index: params.len(),
        });
    };
    let mut ctx = CompressedLambdaCtx {
        force,
        stack_map_runtime,
        next_safepoint: 0,
        deopt_fn,
        self_ref,
        rt,
        env,
        arg_word,
        budget,
        deopt,
        sentinel,
        self_upval,
        self_call_count: 0,
    };

    let mut forced_param: Option<ClifValue> = None;
    let result = emit_expr(&mut cursor, arena, &mut ctx, body, &mut forced_param)?;
    let result_word = to_word(&mut cursor, &ctx, result);
    cursor.ins().return_(&[result_word]);

    // Shared guard-failure block: record the deopt trap, unwind with the sentinel.
    cursor.insert_block(deopt);
    let deopt_record = cursor.ins().iconst(types::I64, 0);
    let _sentinel_value = cursor.ins().call(ctx.deopt_fn, &[ctx.rt, deopt_record]);
    let deopt_word = cursor.ins().iconst(types::I64, TIER2_DEOPT_SENTINEL_WORD);
    cursor.ins().return_(&[deopt_word]);

    // Shared propagation block: a callee already recorded the trap; just unwind.
    cursor.insert_block(sentinel);
    let propagate_word = cursor.ins().iconst(types::I64, TIER2_DEOPT_SENTINEL_WORD);
    cursor.ins().return_(&[propagate_word]);

    let self_call_count = ctx.self_call_count;
    drop(cursor);
    Ok((function, self_call_count))
}

/// Builds the boundary entry adapter with the frozen lambda-call ABI.
fn build_entry_function(
    body: IrId,
    entry_signature: Signature,
    inner_signature: &Signature,
    depth_budget: i64,
) -> Result<Function, JitLowerError> {
    let mut function = Function::with_name_signature(clif_name_for_ir_root(body), entry_signature);
    let inner_ref = import_tier2_local_function(&mut function, inner_signature);

    let entry_block = append_entry_block_params(&mut function);
    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let params = cursor.func.dfg.block_params(entry_block).to_vec();
    let [rt, env, arg_word] = params[..] else {
        return Err(JitLowerError::MissingEntryBlockParameter {
            index: params.len(),
        });
    };
    let budget = cursor.ins().iconst(types::I64, depth_budget);
    let call = cursor.ins().call(inner_ref, &[rt, env, arg_word, budget]);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let [word] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: "tier2_inner",
            expected: 1,
            actual: results.len(),
        });
    };
    // Translate the internal deopt sentinel into the canonical null word
    // before it crosses into Rust: the recorded trap, not the value, carries
    // the deopt, and an invalid kind byte must never materialize as a Rust
    // `Value`.
    let is_sentinel = cursor
        .ins()
        .icmp_imm(IntCC::Equal, word, TIER2_DEOPT_SENTINEL_WORD);
    let clean = cursor.func.dfg.make_block();
    let deopted = cursor.func.dfg.make_block();
    cursor.ins().brif(is_sentinel, deopted, &[], clean, &[]);
    cursor.insert_block(clean);
    cursor.ins().return_(&[word]);
    cursor.insert_block(deopted);
    let null_word = cursor
        .ins()
        .iconst(types::I64, CompressedValueWord::null().raw() as i64);
    cursor.ins().return_(&[null_word]);
    drop(cursor);
    Ok(function)
}

/// Emits one grammar expression, returning its encoded word.
///
/// `forced_param` caches the forced parameter word for the current dominating
/// path, with the same per-arm clone-and-restore discipline as the two-word
/// emitter.
fn emit_expr(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut CompressedLambdaCtx,
    id: IrId,
    forced_param: &mut Option<ClifValue>,
) -> Result<TypedVal, JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        // Any-width literal: operand position never materializes a word.
        (IrKind::Int, IrData::Int(value)) => {
            Ok(TypedVal::IntDecoded(cursor.ins().iconst(types::I64, value)))
        }
        (IrKind::Bool, IrData::Bool(value)) => Ok(TypedVal::Word(
            cursor
                .ins()
                .iconst(types::I64, CompressedValueWord::boolean(value).raw() as i64),
        )),
        (IrKind::LocalVar, IrData::Local { slot: 0 }) => {
            Ok(TypedVal::Word(emit_forced_param(cursor, ctx, forced_param)?))
        }
        (IrKind::BinOp, IrData::Binary { op, lhs, rhs }) => {
            emit_binop(cursor, arena, ctx, op, lhs, rhs, forced_param)
        }
        (
            IrKind::If,
            IrData::Triple {
                first,
                second,
                third,
            },
        ) => emit_if(cursor, arena, ctx, first, second, third, forced_param),
        (IrKind::Apply, IrData::Pair { first, second }) => {
            emit_self_call(cursor, arena, ctx, first, second, forced_param)
        }
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand { operand: id, kind }),
    }
}

/// Emits the parameter read, forcing it on first strict use of this path.
///
/// The fast path skips the `aos_force` call when the raw argument word is
/// already an inline integer (its high half is zero) — the recursion's own
/// self-call arguments always are. Any other word (a suspended thunk, a boxed
/// scalar, a heap value) takes the slow path through `aos_force`, whose
/// result feeds the operand guards exactly as the tree walk's forced value
/// would.
fn emit_forced_param(
    cursor: &mut FuncCursor,
    ctx: &mut CompressedLambdaCtx,
    forced_param: &mut Option<ClifValue>,
) -> Result<ClifValue, JitLowerError> {
    if let Some(cached) = *forced_param {
        return Ok(cached);
    }
    let high = cursor.ins().ushr_imm(ctx.arg_word, 32);
    let is_inline_int = cursor.ins().icmp_imm(IntCC::Equal, high, 0);
    let slow = cursor.func.dfg.make_block();
    let join = cursor.func.dfg.make_block();
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor
        .ins()
        .brif(is_inline_int, join, &[ctx.arg_word.into()], slow, &[]);
    cursor.insert_block(slow);
    let forced = emit_force(cursor, ctx, ctx.arg_word)?;
    cursor.ins().jump(join, &[forced.into()]);
    cursor.insert_block(join);
    let joined = cursor.func.dfg.block_params(join).to_vec();
    let word = joined[0];
    *forced_param = Some(word);
    Ok(word)
}

/// Emits one mapped force call over the raw parameter word.
fn emit_force(
    cursor: &mut FuncCursor,
    ctx: &mut CompressedLambdaCtx,
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
    match results[..] {
        [word] => Ok(word),
        _ => Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_FORCE_SYMBOL,
            expected: 1,
            actual: results.len(),
        }),
    }
}

/// Coerces a typed value to a decoded `i64` integer.
///
/// A `Word` gets the inline-integer guard (all-zero high half; anything
/// else — bools, boxed scalars, heap words, the sentinel — deopts) and a
/// sign-extending decode; an `IntDecoded` is already the integer.
fn to_int(cursor: &mut FuncCursor, ctx: &CompressedLambdaCtx, value: TypedVal) -> ClifValue {
    match value {
        TypedVal::IntDecoded(int) => int,
        TypedVal::Word(word) => {
            let high = cursor.ins().ushr_imm(word, 32);
            let is_inline_int = cursor.ins().icmp_imm(IntCC::Equal, high, 0);
            let decode = cursor.func.dfg.make_block();
            cursor.ins().brif(is_inline_int, decode, &[], ctx.deopt, &[]);
            cursor.insert_block(decode);
            let low = cursor.ins().ireduce(types::I32, word);
            cursor.ins().sextend(types::I64, low)
        }
    }
}

/// Coerces a typed value to an encoded word (a materialization point).
///
/// An `IntDecoded` re-encodes with the inline-range check, deopting when
/// wide so the tree walk re-runs and boxes it; a `Word` is already encoded.
fn to_word(cursor: &mut FuncCursor, ctx: &CompressedLambdaCtx, value: TypedVal) -> ClifValue {
    match value {
        TypedVal::Word(word) => word,
        TypedVal::IntDecoded(int) => emit_inline_int_encode(cursor, ctx, int),
    }
}

/// Emits one binary operation, mirroring the tree walk's operand order.
///
/// Operands coerce to decoded integers (`Word` operands get the inline
/// guard exactly once; decoded operands join directly), the operation runs
/// on wrapping `i64` — intermediates carry no inline-range constraint — and
/// arithmetic stays decoded while comparisons select between the two
/// canonical boolean words.
fn emit_binop(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut CompressedLambdaCtx,
    op: BinOpKind,
    lhs: IrId,
    rhs: IrId,
    forced_param: &mut Option<ClifValue>,
) -> Result<TypedVal, JitLowerError> {
    let rhs_first = matches!(op, BinOpKind::Gt | BinOpKind::Le);
    let (lhs_val, rhs_val) = if rhs_first {
        let rhs_val = emit_expr(cursor, arena, ctx, rhs, forced_param)?;
        let lhs_val = emit_expr(cursor, arena, ctx, lhs, forced_param)?;
        (lhs_val, rhs_val)
    } else {
        let lhs_val = emit_expr(cursor, arena, ctx, lhs, forced_param)?;
        let rhs_val = emit_expr(cursor, arena, ctx, rhs, forced_param)?;
        (lhs_val, rhs_val)
    };
    let lhs_int = to_int(cursor, ctx, lhs_val);
    let rhs_int = to_int(cursor, ctx, rhs_val);

    match op {
        BinOpKind::Add => Ok(TypedVal::IntDecoded(cursor.ins().iadd(lhs_int, rhs_int))),
        BinOpKind::Sub => Ok(TypedVal::IntDecoded(cursor.ins().isub(lhs_int, rhs_int))),
        BinOpKind::Mul => Ok(TypedVal::IntDecoded(cursor.ins().imul(lhs_int, rhs_int))),
        BinOpKind::Div => {
            // The tree walk errors on a zero divisor and on `i64::MIN / -1`;
            // both are reachable through wide decoded operands and deopt.
            let nonzero = cursor.ins().icmp_imm(IntCC::NotEqual, rhs_int, 0);
            let lhs_is_min = cursor.ins().icmp_imm(IntCC::Equal, lhs_int, i64::MIN);
            let rhs_is_neg1 = cursor.ins().icmp_imm(IntCC::Equal, rhs_int, -1);
            let is_overflow = cursor.ins().band(lhs_is_min, rhs_is_neg1);
            let not_overflow = cursor.ins().icmp_imm(IntCC::Equal, is_overflow, 0);
            let safe = cursor.ins().band(nonzero, not_overflow);
            let divide = cursor.func.dfg.make_block();
            cursor.ins().brif(safe, divide, &[], ctx.deopt, &[]);
            cursor.insert_block(divide);
            let result = cursor.ins().sdiv(lhs_int, rhs_int);
            Ok(TypedVal::IntDecoded(result))
        }
        BinOpKind::Lt => Ok(TypedVal::Word(bool_word(
            cursor,
            IntCC::SignedLessThan,
            lhs_int,
            rhs_int,
        ))),
        BinOpKind::Gt => Ok(TypedVal::Word(bool_word(
            cursor,
            IntCC::SignedGreaterThan,
            lhs_int,
            rhs_int,
        ))),
        BinOpKind::Le => Ok(TypedVal::Word(bool_word(
            cursor,
            IntCC::SignedLessThanOrEqual,
            lhs_int,
            rhs_int,
        ))),
        BinOpKind::Ge => Ok(TypedVal::Word(bool_word(
            cursor,
            IntCC::SignedGreaterThanOrEqual,
            lhs_int,
            rhs_int,
        ))),
        BinOpKind::Eq => Ok(TypedVal::Word(bool_word(cursor, IntCC::Equal, lhs_int, rhs_int))),
        BinOpKind::Ne => Ok(TypedVal::Word(bool_word(
            cursor,
            IntCC::NotEqual,
            lhs_int,
            rhs_int,
        ))),
        op => Err(JitLowerError::UnsupportedArithOp { op }),
    }
}

/// Re-encodes a computed integer as an inline word, deopting when too wide.
fn emit_inline_int_encode(
    cursor: &mut FuncCursor,
    ctx: &CompressedLambdaCtx,
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

/// Materializes a boolean word from an integer comparison.
fn bool_word(
    cursor: &mut FuncCursor,
    condition: IntCC,
    lhs: ClifValue,
    rhs: ClifValue,
) -> ClifValue {
    let compared = cursor.ins().icmp(condition, lhs, rhs);
    let true_word = cursor
        .ins()
        .iconst(types::I64, CompressedValueWord::boolean(true).raw() as i64);
    let false_word = cursor
        .ins()
        .iconst(types::I64, CompressedValueWord::boolean(false).raw() as i64);
    cursor.ins().select(compared, true_word, false_word)
}

/// Emits an `if`/`then`/`else`, joining both arms on a one-word block param.
///
/// The condition must be statically boolean (a comparison `BinOp` or a
/// boolean literal); its truth is the word's low bit, which is `1` exactly
/// for the canonical `true` word.
fn emit_if(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut CompressedLambdaCtx,
    cond: IrId,
    then_id: IrId,
    else_id: IrId,
    forced_param: &mut Option<ClifValue>,
) -> Result<TypedVal, JitLowerError> {
    let cond_node = arena
        .node(cond)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: cond })?;
    let statically_boolean = match (cond_node.kind, cond_node.data) {
        (IrKind::Bool, _) => true,
        (IrKind::BinOp, IrData::Binary { op, .. }) => matches!(
            op,
            BinOpKind::Lt
                | BinOpKind::Gt
                | BinOpKind::Le
                | BinOpKind::Ge
                | BinOpKind::Eq
                | BinOpKind::Ne
        ),
        _ => false,
    };
    if !statically_boolean {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: cond,
            kind: cond_node.kind,
        });
    }
    let cond_val = emit_expr(cursor, arena, ctx, cond, forced_param)?;
    let cond_word = to_word(cursor, ctx, cond_val);
    let truth = cursor.ins().band_imm(cond_word, 1);

    // Both classes are i64 SSA, so the join parameter type never changes;
    // only the wrapper class does. An Int/Int join stays decoded across the
    // branch (the common recursive-arithmetic pattern), everything else
    // joins as encoded words (a wide arm deopts at its own to_word).
    let join_class = if infer_class(arena, then_id) == ExprClass::Int
        && infer_class(arena, else_id) == ExprClass::Int
    {
        ExprClass::Int
    } else {
        ExprClass::Word
    };

    let then_block = cursor.func.dfg.make_block();
    let else_block = cursor.func.dfg.make_block();
    let join = cursor.func.dfg.make_block();
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor.ins().brif(truth, then_block, &[], else_block, &[]);

    let before_branch = *forced_param;
    cursor.insert_block(then_block);
    let mut then_param = before_branch;
    let then_val = emit_expr(cursor, arena, ctx, then_id, &mut then_param)?;
    let then_carried = match join_class {
        ExprClass::Int => to_int(cursor, ctx, then_val),
        ExprClass::Word => to_word(cursor, ctx, then_val),
    };
    cursor.ins().jump(join, &[then_carried.into()]);

    cursor.insert_block(else_block);
    let mut else_param = before_branch;
    let else_val = emit_expr(cursor, arena, ctx, else_id, &mut else_param)?;
    let else_carried = match join_class {
        ExprClass::Int => to_int(cursor, ctx, else_val),
        ExprClass::Word => to_word(cursor, ctx, else_val),
    };
    cursor.ins().jump(join, &[else_carried.into()]);

    cursor.insert_block(join);
    *forced_param = before_branch;
    let joined = cursor.func.dfg.block_params(join).to_vec();
    Ok(match join_class {
        ExprClass::Int => TypedVal::IntDecoded(joined[0]),
        ExprClass::Word => TypedVal::Word(joined[0]),
    })
}

/// Emits one direct self-call with its depth guard and sentinel propagation.
fn emit_self_call(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut CompressedLambdaCtx,
    callee: IrId,
    argument: IrId,
    forced_param: &mut Option<ClifValue>,
) -> Result<TypedVal, JitLowerError> {
    let callee_node = arena
        .node(callee)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: callee })?;
    match (callee_node.kind, callee_node.data) {
        (IrKind::UpvalVar, IrData::Upval { depth, slot })
            if (depth, slot) == ctx.self_upval && depth >= 1 => {}
        (kind, _) => {
            return Err(JitLowerError::UnsupportedArithOperand {
                operand: callee,
                kind,
            });
        }
    }
    let argument = unwrap_thunk_alloc(arena, argument)?;
    let arg_val = emit_expr(cursor, arena, ctx, argument, forced_param)?;
    // Materialization point: the inner ABI takes an encoded word, so a wide
    // decoded argument deopts here (the tree walk re-runs and boxes it).
    let arg_word = to_word(cursor, ctx, arg_val);

    // Depth guard: a self-call needs remaining budget for the callee frame.
    let has_budget = cursor
        .ins()
        .icmp_imm(IntCC::SignedGreaterThan, ctx.budget, 1);
    let call_block = cursor.func.dfg.make_block();
    cursor
        .ins()
        .brif(has_budget, call_block, &[], ctx.deopt, &[]);
    cursor.insert_block(call_block);
    let next_budget = cursor.ins().iadd_imm(ctx.budget, -1);
    let call = cursor
        .ins()
        .call(ctx.self_ref, &[ctx.rt, ctx.env, arg_word, next_budget]);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let [word] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: "tier2_self",
            expected: 1,
            actual: results.len(),
        });
    };
    // Propagate a callee deopt outward without re-recording the trap.
    let is_sentinel = cursor
        .ins()
        .icmp_imm(IntCC::Equal, word, TIER2_DEOPT_SENTINEL_WORD);
    let continue_block = cursor.func.dfg.make_block();
    cursor
        .ins()
        .brif(is_sentinel, ctx.sentinel, &[], continue_block, &[]);
    cursor.insert_block(continue_block);
    ctx.self_call_count = ctx.self_call_count.saturating_add(1);
    Ok(TypedVal::Word(word))
}
