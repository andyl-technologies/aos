//! CLIF emission for the fused curried-chain grammar.
//!
//! [`lambda_chain`](super) owns the lowering entry points and the compiled
//! shape; this module owns the expression emitter they share: the recursive
//! walk that turns one in-grammar body into straight-line CLIF over unboxed
//! `(tag, payload)` word pairs, with parameter forces at first strict use,
//! deopt guards on every operand tag, direct self-calls, and pinned-callee
//! inlining.
//!
//! # Grammar widenings owned here
//!
//! Landing 3 widened the chain-body grammar with two shapes beyond the
//! original literals/params/arith/if/call set:
//!
//! - **Unary integer negation** (`-e`): the operand is emitted, guarded as an
//!   integer, and negated with wrapping semantics — exactly the tree walk's
//!   `wrapping_neg` (a float operand deopts and re-runs interpreted).
//! - **General environment reads** (an upvalue read beyond the chain's own
//!   parameters): emitted as an `aos_upval_get` call against the boundary
//!   `env` pointer plus a force at first strict use, cached per dominating
//!   path exactly like parameter forces. The compile-time depth translation
//!   depends on which seam owns the boundary env — see
//!   [`JitTier2EnvBoundary`](super::JitTier2EnvBoundary) — and reads stay
//!   sound across native self-calls because every translated read lands in
//!   the recursion-invariant captured prefix of the boundary environment
//!   (chain parameters occupy the frames below `depth == arity`, so a read
//!   admitted by the scan can never alias a per-call argument frame).
//!
//! Pinned-callee and fused-generator bodies remain **environment-free** by
//! scan construction: their closures capture their *own* environments, which
//! are not the boundary `env` the compiled code carries, so an env read
//! inside an inlined body would read the wrong environment. The scans reject
//! the shape before emission can see it.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, Signature, UserFuncName, condcodes::IntCC, types},
};
use ratchet_core::{IrArena, IrData, IrId, IrKind, syntax::BinOpKind, syntax::UnaryOpKind};

use super::super::{
    AOS_DEOPT_SYMBOL, AOS_FORCE_SYMBOL, AOS_UPVAL_GET_SYMBOL, JitLowerError,
    append_entry_block_params, clif_external_name_for_aos_deopt, clif_external_name_for_aos_force,
    clif_external_name_for_aos_upval_get, import_runtime_helper_function,
};
use super::super::lambda_rec::import_tier2_local_function;
use super::scan::{flatten_apply_chain, require_static_bool_condition};
use super::{
    JitTier2ChainScan, JitTier2EnvBoundary, JitTier2PinnedCallee, TAG_BOOL, TAG_INT,
    TIER2_DEOPT_SENTINEL_TAG,
};

/// A Cranelift SSA value, aliased to avoid confusion with the runtime `Value`.
type ClifValue = cranelift_codegen::ir::Value;
type Block = cranelift_codegen::ir::Block;

/// The body shape compiled into one chain inner function.
#[derive(Clone, Copy, Debug)]
pub(super) enum ChainInnerBody {
    /// The chain's own innermost body (the plain fold/apply-seam shape).
    Plain,
    /// A fused `builtins.genList` fold step: the generator body is emitted
    /// over the raw index parameter first and its result is seeded as the
    /// already-forced element parameter of the operator body.
    FusedGenerator(IrId),
}

/// Shared CLIF references threaded through the fused body emitter.
struct ChainCtx {
    /// Imported `aos_force` helper (forces parameters at first strict use).
    force: cranelift_codegen::ir::FuncRef,
    /// Imported `aos_deopt` helper called by the shared deopt block.
    deopt_fn: cranelift_codegen::ir::FuncRef,
    /// Imported `aos_upval_get` helper, present when the scan saw env reads.
    upval_get: Option<cranelift_codegen::ir::FuncRef>,
    /// The module-local self reference for direct recursive calls.
    self_ref: cranelift_codegen::ir::FuncRef,
    /// The runtime-context entry parameter.
    rt: ClifValue,
    /// The environment entry parameter (the boundary seam's closure env).
    env: ClifValue,
    /// The raw (possibly suspended) `(tag, payload)` pair per chain parameter.
    raw_params: Vec<(ClifValue, ClifValue)>,
    /// The remaining native self-call depth budget.
    budget: ClifValue,
    /// The shared guard-failure block: records a deopt trap, returns the sentinel.
    deopt: Block,
    /// The shared sentinel-propagation block: returns the sentinel unchanged.
    sentinel: Block,
    /// The chain arity K.
    arity: u32,
    /// The conceptual frames missing from the boundary `env` pointer.
    ///
    /// A body-relative read at `depth >= arity` translates to
    /// `aos_upval_get(env, depth - env_skew, slot)`; see
    /// [`JitTier2EnvBoundary`](super::JitTier2EnvBoundary).
    env_skew: u32,
    /// The self-callee upvalue coordinates, when the chain self-recurses.
    self_upval: Option<(u32, u32)>,
    /// The pinned callees available for inlining.
    pinned: Vec<JitTier2PinnedCallee>,
    /// The number of self-call chains emitted so far.
    self_call_count: u32,
}

/// The per-dominating-path evaluation state of the emitter.
///
/// `forced_params` caches the forced value of each chain parameter along the
/// current path and `forced_upvals` the forced value of each environment read
/// (an `If` arm must not leak its forces past the join, so arms clone and
/// restore both caches). `inline_params` is `Some` while emitting a pinned
/// callee's (or fused generator's) inlined body, mapping the callee's own
/// parameter reads to the already-evaluated argument pairs.
#[derive(Clone)]
struct EmitState {
    forced_params: Vec<Option<(ClifValue, ClifValue)>>,
    forced_upvals: Vec<((u32, u32), (ClifValue, ClifValue))>,
    inline_params: Option<Vec<(ClifValue, ClifValue)>>,
}

/// Builds the compiled chain body and returns it with its self-call count.
///
/// `body` selects between the plain innermost-body emission and the fused
/// `genList` fold-step emission; `env_boundary` fixes the compile-time depth
/// translation for environment reads.
pub(super) fn build_inner_function(
    arena: &IrArena,
    scan: &JitTier2ChainScan,
    signature: Signature,
    self_upval: Option<(u32, u32)>,
    pinned: &[JitTier2PinnedCallee],
    env_boundary: JitTier2EnvBoundary,
    body: ChainInnerBody,
) -> Result<(Function, u32), JitLowerError> {
    let mut function = Function::with_name_signature(
        UserFuncName::user(
            super::super::lambda_rec::AOS_TIER2_LOCAL_FUNCTION_NAMESPACE,
            scan.inner_body().as_u32(),
        ),
        signature.clone(),
    );
    let force = import_runtime_helper_function(
        &mut function,
        AOS_FORCE_SYMBOL,
        clif_external_name_for_aos_force(),
    )?;
    let deopt_fn = import_runtime_helper_function(
        &mut function,
        AOS_DEOPT_SYMBOL,
        clif_external_name_for_aos_deopt(),
    )?;
    let upval_get = if scan.reads_env() {
        Some(import_runtime_helper_function(
            &mut function,
            AOS_UPVAL_GET_SYMBOL,
            clif_external_name_for_aos_upval_get(),
        )?)
    } else {
        None
    };
    let self_ref = import_tier2_local_function(&mut function, &signature);

    let entry_block = append_entry_block_params(&mut function);
    let deopt = function.dfg.make_block();
    let sentinel = function.dfg.make_block();

    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let params = cursor.func.dfg.block_params(entry_block).to_vec();
    let arity = scan.arity();
    let expected = 2 + 2 * arity as usize + 1;
    if params.len() != expected {
        return Err(JitLowerError::MissingEntryBlockParameter {
            index: params.len(),
        });
    }
    let rt = params[0];
    let env = params[1];
    let mut raw_params = Vec::with_capacity(arity as usize);
    for j in 0..arity as usize {
        raw_params.push((params[2 + 2 * j], params[2 + 2 * j + 1]));
    }
    let budget = params[expected - 1];

    let mut ctx = ChainCtx {
        force,
        deopt_fn,
        upval_get,
        self_ref,
        rt,
        env,
        raw_params,
        budget,
        deopt,
        sentinel,
        arity,
        env_skew: env_boundary.skew(arity),
        self_upval,
        pinned: pinned.to_vec(),
        self_call_count: 0,
    };
    let mut state = EmitState {
        forced_params: vec![None; arity as usize],
        forced_upvals: Vec::new(),
        inline_params: None,
    };

    if let ChainInnerBody::FusedGenerator(generator_body) = body {
        // The generator body is call-free arithmetic over the raw index
        // parameter (always an inline integer supplied by the native loop),
        // so it is emitted eagerly with the index as its sole inline
        // parameter. This is sound even when the operator never demands its
        // element: the emission is pure and side-effect-free — its only exits
        // are a value or the shared deopt block, never a force or a call.
        let index_pair = ctx.raw_params[1];
        let mut generator_state = EmitState {
            forced_params: vec![None; arity as usize],
            forced_upvals: Vec::new(),
            inline_params: Some(vec![index_pair]),
        };
        let element = emit_expr(&mut cursor, arena, &mut ctx, generator_body, &mut generator_state)?;
        // The generated element replaces the raw element parameter: it is by
        // construction already in weak head normal form, so the operator body
        // sees it as forced and never round-trips through `aos_force`.
        state.forced_params[1] = Some(element);
    }

    let (tag, payload) = emit_expr(&mut cursor, arena, &mut ctx, scan.inner_body(), &mut state)?;
    cursor.ins().return_(&[tag, payload]);

    // Shared guard-failure block: record the deopt trap, unwind with the sentinel.
    cursor.insert_block(deopt);
    let deopt_record = cursor.ins().iconst(types::I64, 0);
    let _sentinel_value = cursor.ins().call(ctx.deopt_fn, &[ctx.rt, deopt_record]);
    let deopt_tag = cursor.ins().iconst(types::I64, TIER2_DEOPT_SENTINEL_TAG);
    let deopt_payload = cursor.ins().iconst(types::I64, 0);
    cursor.ins().return_(&[deopt_tag, deopt_payload]);

    // Shared propagation block: a callee already recorded the trap; just unwind.
    cursor.insert_block(sentinel);
    let propagate_tag = cursor.ins().iconst(types::I64, TIER2_DEOPT_SENTINEL_TAG);
    let propagate_payload = cursor.ins().iconst(types::I64, 0);
    cursor.ins().return_(&[propagate_tag, propagate_payload]);

    let self_call_count = ctx.self_call_count;
    drop(cursor);
    Ok((function, self_call_count))
}

/// Emits one grammar expression, returning its `(tag, payload)` word pair.
fn emit_expr(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx,
    id: IrId,
    state: &mut EmitState,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::Int, IrData::Int(value)) => {
            let tag = cursor.ins().iconst(types::I64, TAG_INT);
            let payload = cursor.ins().iconst(types::I64, value);
            Ok((tag, payload))
        }
        (IrKind::Bool, IrData::Bool(value)) => {
            let tag = cursor.ins().iconst(types::I64, TAG_BOOL);
            let payload = cursor.ins().iconst(types::I64, i64::from(value));
            Ok((tag, payload))
        }
        (IrKind::LocalVar, IrData::Local { slot: 0 }) => {
            if let Some(inline) = &state.inline_params {
                let arity = inline.len();
                return Ok(inline[arity - 1]);
            }
            Ok(emit_forced_param(
                cursor,
                ctx,
                (ctx.arity - 1) as usize,
                state,
            ))
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot: 0 })
            if state.inline_params.is_none() && depth < ctx.arity =>
        {
            // Chain parameter j at depth K-1-j: index = K-1-depth.
            Ok(emit_forced_param(
                cursor,
                ctx,
                (ctx.arity - 1 - depth) as usize,
                state,
            ))
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot })
            if state.inline_params.is_none() && depth >= ctx.arity =>
        {
            emit_forced_upval(cursor, ctx, depth, slot, state)
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot: 0 })
            if state.inline_params.is_some() =>
        {
            let inline = state
                .inline_params
                .as_ref()
                .ok_or(JitLowerError::MissingIrBody { body: id })?;
            let arity = inline.len() as u32;
            if depth < arity {
                Ok(inline[(arity - 1 - depth) as usize])
            } else {
                Err(JitLowerError::UnsupportedArithOperand {
                    operand: id,
                    kind: IrKind::UpvalVar,
                })
            }
        }
        (IrKind::BinOp, IrData::Binary { op, lhs, rhs }) => {
            emit_binop(cursor, arena, ctx, op, lhs, rhs, state)
        }
        (
            IrKind::UnaryOp,
            IrData::Unary {
                op: UnaryOpKind::Neg,
                operand,
            },
        ) => emit_neg(cursor, arena, ctx, operand, state),
        (
            IrKind::If,
            IrData::Triple {
                first,
                second,
                third,
            },
        ) => emit_if(cursor, arena, ctx, first, second, third, state),
        (IrKind::Apply, _) => emit_call_chain(cursor, arena, ctx, id, state),
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand { operand: id, kind }),
    }
}

/// Emits a chain-parameter read, forcing it at first strict use on this path.
fn emit_forced_param(
    cursor: &mut FuncCursor,
    ctx: &ChainCtx,
    index: usize,
    state: &mut EmitState,
) -> (ClifValue, ClifValue) {
    if let Some(cached) = state.forced_params[index] {
        return cached;
    }
    let (raw_tag, raw_payload) = ctx.raw_params[index];
    let pair = emit_force_int_fast_path(cursor, ctx, raw_tag, raw_payload);
    state.forced_params[index] = Some(pair);
    pair
}

/// Emits an environment read beyond the chain parameters.
///
/// The body-relative `depth` is translated onto the boundary `env` pointer by
/// subtracting the seam's frame skew (see [`ChainCtx::env_skew`]), read
/// through `aos_upval_get`, and forced at first strict use on this dominating
/// path — the same discipline as chain parameters, with the forced pair
/// cached per `(depth, slot)` coordinate.
fn emit_forced_upval(
    cursor: &mut FuncCursor,
    ctx: &mut ChainCtx,
    depth: u32,
    slot: u32,
    state: &mut EmitState,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    if let Some((_, cached)) = state
        .forced_upvals
        .iter()
        .find(|(coordinate, _)| *coordinate == (depth, slot))
    {
        return Ok(*cached);
    }
    let Some(upval_get) = ctx.upval_get else {
        // The scan promised no env reads; drifting here is a lowering bug
        // surfaced as an unsupported operand rather than bad code.
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: IrId::new(0),
            kind: IrKind::UpvalVar,
        });
    };
    let native_depth = cursor
        .ins()
        .iconst(types::I32, i64::from(depth - ctx.env_skew));
    let native_slot = cursor.ins().iconst(types::I32, i64::from(slot));
    let read = cursor
        .ins()
        .call(upval_get, &[ctx.env, native_depth, native_slot]);
    let results = cursor.func.dfg.inst_results(read).to_vec();
    let [raw_tag, raw_payload] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_UPVAL_GET_SYMBOL,
            expected: 2,
            actual: results.len(),
        });
    };
    let pair = emit_force_int_fast_path(cursor, ctx, raw_tag, raw_payload);
    state.forced_upvals.push(((depth, slot), pair));
    Ok(pair)
}

/// Emits the shared inline-int-or-force join for a raw value pair.
///
/// An inline integer skips the call; anything else round-trips through
/// `aos_force`, which either returns the forced value or transfers an
/// evaluator error as a trap the boundary converts to a deopt.
fn emit_force_int_fast_path(
    cursor: &mut FuncCursor,
    ctx: &ChainCtx,
    raw_tag: ClifValue,
    raw_payload: ClifValue,
) -> (ClifValue, ClifValue) {
    let is_int = cursor.ins().icmp_imm(IntCC::Equal, raw_tag, TAG_INT);
    let slow = cursor.func.dfg.make_block();
    let join = cursor.func.dfg.make_block();
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor
        .ins()
        .brif(is_int, join, &[raw_tag.into(), raw_payload.into()], slow, &[]);
    cursor.insert_block(slow);
    let force_call = cursor.ins().call(ctx.force, &[ctx.rt, raw_tag, raw_payload]);
    let force_results = cursor.func.dfg.inst_results(force_call).to_vec();
    cursor
        .ins()
        .jump(join, &[force_results[0].into(), force_results[1].into()]);
    cursor.insert_block(join);
    let joined = cursor.func.dfg.block_params(join).to_vec();
    (joined[0], joined[1])
}

/// Emits one binary operation, mirroring the tree walk's operand order.
fn emit_binop(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx,
    op: BinOpKind,
    lhs: IrId,
    rhs: IrId,
    state: &mut EmitState,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    let rhs_first = matches!(op, BinOpKind::Gt | BinOpKind::Le);
    let (lhs_pair, rhs_pair) = if rhs_first {
        let rhs_pair = emit_expr(cursor, arena, ctx, rhs, state)?;
        let lhs_pair = emit_expr(cursor, arena, ctx, lhs, state)?;
        (lhs_pair, rhs_pair)
    } else {
        let lhs_pair = emit_expr(cursor, arena, ctx, lhs, state)?;
        let rhs_pair = emit_expr(cursor, arena, ctx, rhs, state)?;
        (lhs_pair, rhs_pair)
    };
    let (lhs_tag, lhs_payload) = lhs_pair;
    let (rhs_tag, rhs_payload) = rhs_pair;

    let lhs_is_int = cursor.ins().icmp_imm(IntCC::Equal, lhs_tag, TAG_INT);
    let rhs_is_int = cursor.ins().icmp_imm(IntCC::Equal, rhs_tag, TAG_INT);
    let both_int = cursor.ins().band(lhs_is_int, rhs_is_int);
    let compute = cursor.func.dfg.make_block();
    cursor.ins().brif(both_int, compute, &[], ctx.deopt, &[]);
    cursor.insert_block(compute);

    match op {
        BinOpKind::Add => {
            let result = cursor.ins().iadd(lhs_payload, rhs_payload);
            Ok(int_pair(cursor, result))
        }
        BinOpKind::Sub => {
            let result = cursor.ins().isub(lhs_payload, rhs_payload);
            Ok(int_pair(cursor, result))
        }
        BinOpKind::Mul => {
            let result = cursor.ins().imul(lhs_payload, rhs_payload);
            Ok(int_pair(cursor, result))
        }
        BinOpKind::Div => {
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
            Ok(int_pair(cursor, result))
        }
        BinOpKind::Lt => Ok(bool_pair(cursor, IntCC::SignedLessThan, lhs_payload, rhs_payload)),
        BinOpKind::Gt => Ok(bool_pair(
            cursor,
            IntCC::SignedGreaterThan,
            lhs_payload,
            rhs_payload,
        )),
        BinOpKind::Le => Ok(bool_pair(
            cursor,
            IntCC::SignedLessThanOrEqual,
            lhs_payload,
            rhs_payload,
        )),
        BinOpKind::Ge => Ok(bool_pair(
            cursor,
            IntCC::SignedGreaterThanOrEqual,
            lhs_payload,
            rhs_payload,
        )),
        BinOpKind::Eq => Ok(bool_pair(cursor, IntCC::Equal, lhs_payload, rhs_payload)),
        BinOpKind::Ne => Ok(bool_pair(cursor, IntCC::NotEqual, lhs_payload, rhs_payload)),
        op => Err(JitLowerError::UnsupportedArithOp { op }),
    }
}

/// Emits an integer unary negation with the tree walk's wrapping semantics.
///
/// The operand is guarded as an inline integer (a float operand deopts and
/// the interpreted re-run produces the tree walk's float negation) and
/// negated as `0 - x`, which wraps at `i64::MIN` exactly like the oracle's
/// `wrapping_neg`.
fn emit_neg(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx,
    operand: IrId,
    state: &mut EmitState,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    let (tag, payload) = emit_expr(cursor, arena, ctx, operand, state)?;
    let is_int = cursor.ins().icmp_imm(IntCC::Equal, tag, TAG_INT);
    let compute = cursor.func.dfg.make_block();
    cursor.ins().brif(is_int, compute, &[], ctx.deopt, &[]);
    cursor.insert_block(compute);
    let zero = cursor.ins().iconst(types::I64, 0);
    let result = cursor.ins().isub(zero, payload);
    Ok(int_pair(cursor, result))
}

/// Emits an `if`/`then`/`else`, joining both arms on a two-word block param.
fn emit_if(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx,
    cond: IrId,
    then_id: IrId,
    else_id: IrId,
    state: &mut EmitState,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    require_static_bool_condition(arena, cond)?;
    let (_cond_tag, cond_payload) = emit_expr(cursor, arena, ctx, cond, state)?;

    let then_block = cursor.func.dfg.make_block();
    let else_block = cursor.func.dfg.make_block();
    let join = cursor.func.dfg.make_block();
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor
        .ins()
        .brif(cond_payload, then_block, &[], else_block, &[]);

    let before_branch = state.clone();
    cursor.insert_block(then_block);
    let mut then_state = before_branch.clone();
    let (then_tag, then_payload) = emit_expr(cursor, arena, ctx, then_id, &mut then_state)?;
    cursor
        .ins()
        .jump(join, &[then_tag.into(), then_payload.into()]);

    cursor.insert_block(else_block);
    let mut else_state = before_branch.clone();
    let (else_tag, else_payload) = emit_expr(cursor, arena, ctx, else_id, &mut else_state)?;
    cursor
        .ins()
        .jump(join, &[else_tag.into(), else_payload.into()]);

    cursor.insert_block(join);
    *state = before_branch;
    let joined = cursor.func.dfg.block_params(join).to_vec();
    Ok((joined[0], joined[1]))
}

/// Emits one full application chain: a direct self-call or a pinned inline.
///
/// The chain's head upvalue selects the classification recorded at lowering
/// time; argument expressions are evaluated eagerly, in call order, before the
/// self-call or the inlined callee body.
fn emit_call_chain(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx,
    id: IrId,
    state: &mut EmitState,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    if state.inline_params.is_some() {
        // A pinned callee body is call-free by validation; a chain here means
        // the classification drifted from the scan.
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: id,
            kind: IrKind::Apply,
        });
    }
    let (upval, arguments) = flatten_apply_chain(arena, id, ctx.arity)?;

    if ctx.self_upval == Some(upval) {
        if arguments.len() as u32 != ctx.arity {
            return Err(JitLowerError::UnsupportedArithOperand {
                operand: id,
                kind: IrKind::Apply,
            });
        }
        let mut argument_pairs = Vec::with_capacity(arguments.len());
        for argument in &arguments {
            argument_pairs.push(emit_expr(cursor, arena, ctx, *argument, state)?);
        }
        return emit_self_call(cursor, ctx, &argument_pairs);
    }

    let Some(pinned) = ctx.pinned.iter().find(|callee| callee.upval == upval).copied() else {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: id,
            kind: IrKind::Apply,
        });
    };
    if arguments.len() as u32 != pinned.arity {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: id,
            kind: IrKind::Apply,
        });
    }
    let mut argument_pairs = Vec::with_capacity(arguments.len());
    for argument in &arguments {
        argument_pairs.push(emit_expr(cursor, arena, ctx, *argument, state)?);
    }
    // Inline the pinned callee body over the evaluated arguments. The inlined
    // body reads only its own parameters (validated call-free), so the outer
    // forced-parameter caches pass through unchanged.
    let mut inline_state = EmitState {
        forced_params: state.forced_params.clone(),
        forced_upvals: state.forced_upvals.clone(),
        inline_params: Some(argument_pairs),
    };
    let result = emit_expr(cursor, arena, ctx, pinned.body, &mut inline_state)?;
    state.forced_params = inline_state.forced_params;
    state.forced_upvals = inline_state.forced_upvals;
    Ok(result)
}

/// Emits one direct self-call with its depth guard and sentinel propagation.
fn emit_self_call(
    cursor: &mut FuncCursor,
    ctx: &mut ChainCtx,
    argument_pairs: &[(ClifValue, ClifValue)],
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    let has_budget = cursor
        .ins()
        .icmp_imm(IntCC::SignedGreaterThan, ctx.budget, 1);
    let call_block = cursor.func.dfg.make_block();
    cursor
        .ins()
        .brif(has_budget, call_block, &[], ctx.deopt, &[]);
    cursor.insert_block(call_block);
    let next_budget = cursor.ins().iadd_imm(ctx.budget, -1);
    let mut call_arguments = vec![ctx.rt, ctx.env];
    for (tag, payload) in argument_pairs {
        call_arguments.push(*tag);
        call_arguments.push(*payload);
    }
    call_arguments.push(next_budget);
    let call = cursor.ins().call(ctx.self_ref, &call_arguments);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let [tag, payload] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: "tier2_chain_self",
            expected: 2,
            actual: results.len(),
        });
    };
    let is_sentinel = cursor
        .ins()
        .icmp_imm(IntCC::Equal, tag, TIER2_DEOPT_SENTINEL_TAG);
    let continue_block = cursor.func.dfg.make_block();
    cursor
        .ins()
        .brif(is_sentinel, ctx.sentinel, &[], continue_block, &[]);
    cursor.insert_block(continue_block);
    ctx.self_call_count = ctx.self_call_count.saturating_add(1);
    Ok((tag, payload))
}

/// Materializes an integer runtime value pair from a computed payload.
fn int_pair(cursor: &mut FuncCursor, payload: ClifValue) -> (ClifValue, ClifValue) {
    let tag = cursor.ins().iconst(types::I64, TAG_INT);
    (tag, payload)
}

/// Materializes a boolean runtime value pair from an integer comparison.
fn bool_pair(
    cursor: &mut FuncCursor,
    condition: IntCC,
    lhs: ClifValue,
    rhs: ClifValue,
) -> (ClifValue, ClifValue) {
    let compared = cursor.ins().icmp(condition, lhs, rhs);
    let payload = cursor.ins().uextend(types::I64, compared);
    let tag = cursor.ins().iconst(types::I64, TAG_BOOL);
    (tag, payload)
}
