//! One-word (Candidate-C) CLIF emission for the fused curried-chain grammar.
//!
//! The compressed-word sibling of [`super::super::emit`]: same grammar, same
//! recursive walk, same forced-parameter/environment/`let` discipline, direct
//! self-calls, pinned-callee inlining, and deopt guards — but on the
//! decoded-core value model (decoded-core-tier2-spec).
//!
//! # Value discipline (decoded core)
//!
//! Each emitted expression carries one of two `i64` SSA classes: a statically
//! integer-typed node (a literal of ANY width, an arithmetic result, or an
//! `if`/`let` whose value is integer-typed) lives as a plain decoded `i64`
//! with no inline-range constraint (wrapping ops are the tree walk's per-step
//! semantics; intermediates never materialize); everything else is an encoded
//! compressed word. Guards happen only at word-to-int coercions (an inline
//! integer's high half is all zero) and encodes only at materialization points
//! (the body return and self-call arguments), where a wide value deopts so the
//! tree walk re-runs and boxes it. A wide operator literal (`2654435761`) is
//! therefore a plain `iconst.i64`, so the operator lowers instead of declining.
//!
//! # Live values across forces
//!
//! Only **word-class** live values (potential heap references the collector
//! relocates) are spilled into the one-word stack-map slot and reloaded across
//! a force safepoint, threaded through the fast/slow join so both paths agree.
//! Decoded integers are not heap references, so they survive a force in SSA
//! with no spill and no join threading.
//!
//! # Sentinel
//!
//! The internal deopt-unwind sentinel is a word whose kind byte is `0xFF` —
//! propagated by every self-call site and translated to the canonical null
//! word at the boundary before it could materialize as a Rust `Value`.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, Signature, UserFuncName, condcodes::IntCC, types},
};
use ratchet_core::{
    IrArena, IrBinding, IrData, IrId, IrKind, syntax::BinOpKind, syntax::UnaryOpKind,
};
use ratchet_value::value::compressed::CompressedValueWord;

use super::super::super::{
    AOS_DEOPT_SYMBOL, AOS_FORCE_SYMBOL, AOS_UPVAL_GET_SYMBOL, JitLowerError,
    append_entry_block_params, clif_external_name_for_aos_deopt, clif_external_name_for_aos_force,
    clif_external_name_for_aos_upval_get, import_runtime_helper_function, stack_maps,
};
use super::super::super::lambda_rec::import_tier2_local_function;
use super::super::scan::{flatten_apply_chain, require_static_bool_condition, unwrap_thunk_alloc};
use super::super::{JitTier2ChainScan, JitTier2EnvBoundary, JitTier2PinnedCallee};
use super::{ExprClass, TIER2_DEOPT_SENTINEL_WORD, infer_class};

/// A Cranelift SSA value, aliased to avoid confusion with the runtime `Value`.
type ClifValue = cranelift_codegen::ir::Value;
type Block = cranelift_codegen::ir::Block;

/// The SSA class of one emitted expression (both classes are `i64` values).
///
/// `IntDecoded` is a plain decoded integer with no inline-range constraint;
/// `Word` is an encoded compressed word. Coercions between them
/// ([`to_int`]/[`to_word`]) are the only guard/encode sites.
#[derive(Clone, Copy)]
enum TypedVal {
    /// A statically integer-typed value, decoded, full `i64` range.
    IntDecoded(ClifValue),
    /// An encoded compressed word (booleans, reads, call results).
    Word(ClifValue),
}

/// The body shape compiled into one chain inner function.
#[derive(Clone, Copy, Debug)]
pub(in crate::lower::lambda_chain) enum ChainInnerBody {
    /// The chain's own innermost body (the plain fold/apply-seam shape).
    Plain,
    /// A fused `builtins.genList` fold step: the generator body is emitted
    /// over the raw index parameter first and its result seeds the operator's
    /// already-forced element parameter.
    FusedGenerator(IrId),
}

/// Shared CLIF references threaded through the fused body emitter.
struct ChainCtx<'a> {
    /// The IR `let`-binding side-table of the compiled module.
    bindings: &'a [IrBinding],
    /// Imported `aos_force` helper (forces parameters at first strict use).
    force: cranelift_codegen::ir::FuncRef,
    /// Imported stack-map enter/exit helpers bracketing slow-path forces.
    stack_map_runtime: stack_maps::Runtime,
    /// The next force call's safepoint index.
    next_safepoint: u32,
    /// Word-class runtime values currently live across recursive emission
    /// (spilled and reloaded across each force; decoded ints stay in SSA).
    live_words: Vec<ClifValue>,
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
    /// The raw (possibly suspended) word per chain parameter.
    raw_params: Vec<ClifValue>,
    /// The remaining native self-call depth budget.
    budget: ClifValue,
    /// The shared guard-failure block: records a deopt trap, returns the sentinel.
    deopt: Block,
    /// The shared sentinel-propagation block: returns the sentinel unchanged.
    sentinel: Block,
    /// The chain arity K.
    arity: u32,
    /// The conceptual frames missing from the boundary `env` pointer.
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
/// current path (a `Word`, except the fused generator's seeded element, which
/// may be decoded), `forced_upvals` the forced value of each environment read
/// (keyed by **normalized**, let-free coordinates), and `let_scopes` the
/// virtual registers of the enclosing `let` frames (each holds a `TypedVal`, so
/// a let-bound arithmetic result stays decoded across its uses). `inline_params`
/// is `Some` while emitting a pinned callee's (or fused generator's) inlined
/// body, mapping the callee's own parameter reads to the already-evaluated
/// argument values.
#[derive(Clone)]
struct EmitState {
    forced_params: Vec<Option<TypedVal>>,
    forced_upvals: Vec<((u32, u32), TypedVal)>,
    inline_params: Option<Vec<TypedVal>>,
    let_scopes: Vec<LetScope>,
}

/// One enclosing `let` frame compiled as virtual registers.
#[derive(Clone)]
struct LetScope {
    /// The binding value expressions, by slot (`ThunkAlloc` unwrapped).
    values: Vec<IrId>,
    /// The per-path computation state of each slot.
    computed: Vec<LetSlot>,
}

/// The per-path state of one `let`-binding virtual register.
#[derive(Clone, Copy)]
enum LetSlot {
    /// Not computed on this path yet; computed at its first read.
    Unevaluated,
    /// Currently being computed: a read here is a (scan-rejected) letrec
    /// reference, surfaced as a lowering error rather than a hang.
    InProgress,
    /// Computed on this path; reads reuse the typed register.
    Ready(TypedVal),
}

/// Builds the compiled chain body and returns it with its self-call count.
pub(in crate::lower::lambda_chain) fn build_inner_function(
    arena: &IrArena,
    bindings: &[IrBinding],
    scan: &JitTier2ChainScan,
    signature: Signature,
    self_upval: Option<(u32, u32)>,
    pinned: &[JitTier2PinnedCallee],
    env_boundary: JitTier2EnvBoundary,
    body: ChainInnerBody,
) -> Result<(Function, u32), JitLowerError> {
    let mut function = Function::with_name_signature(
        UserFuncName::user(
            super::super::super::lambda_rec::AOS_TIER2_LOCAL_FUNCTION_NAMESPACE,
            scan.inner_body().as_u32(),
        ),
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
    let expected = 2 + arity as usize + 1;
    if params.len() != expected {
        return Err(JitLowerError::MissingEntryBlockParameter {
            index: params.len(),
        });
    }
    let rt = params[0];
    let env = params[1];
    let mut raw_params = Vec::with_capacity(arity as usize);
    for j in 0..arity as usize {
        raw_params.push(params[2 + j]);
    }
    let budget = params[expected - 1];

    let mut ctx = ChainCtx {
        bindings,
        force,
        stack_map_runtime,
        next_safepoint: 0,
        live_words: Vec::new(),
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
        let_scopes: Vec::new(),
    };

    if let ChainInnerBody::FusedGenerator(generator_body) = body {
        // The generator body is call-free arithmetic over the raw index
        // parameter (always an inline integer supplied by the native loop). It
        // is emitted eagerly with the index fed **decoded** (a known integer by
        // construction) as its sole inline parameter; the emission is pure and
        // its only exits are a value or the shared deopt block.
        let index_word = ctx.raw_params[1];
        let index_low = cursor.ins().ireduce(types::I32, index_word);
        let index = cursor.ins().sextend(types::I64, index_low);
        let mut generator_state = EmitState {
            forced_params: vec![None; arity as usize],
            forced_upvals: Vec::new(),
            inline_params: Some(vec![TypedVal::IntDecoded(index)]),
            let_scopes: Vec::new(),
        };
        let element = emit_expr(&mut cursor, arena, &mut ctx, generator_body, &mut generator_state)?;
        // The generated element replaces the raw element parameter: it is by
        // construction already in weak head normal form, so the operator body
        // sees it forced and never round-trips through `aos_force`.
        state.forced_params[1] = Some(element);
    }

    let result = emit_expr(&mut cursor, arena, &mut ctx, scan.inner_body(), &mut state)?;
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

/// Coerces a typed value to a decoded `i64` integer (a guard site).
///
/// A `Word` gets the inline-integer guard (all-zero high half; anything else —
/// bools, boxed scalars, heap words, the sentinel — deopts) and a
/// sign-extending decode; an `IntDecoded` is already the integer.
fn to_int(cursor: &mut FuncCursor, ctx: &ChainCtx<'_>, value: TypedVal) -> ClifValue {
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
/// An `IntDecoded` re-encodes with the inline-range check, deopting when wide
/// so the tree walk re-runs and boxes it; a `Word` is already encoded.
fn to_word(cursor: &mut FuncCursor, ctx: &ChainCtx<'_>, value: TypedVal) -> ClifValue {
    match value {
        TypedVal::Word(word) => word,
        TypedVal::IntDecoded(int) => {
            let low = cursor.ins().ireduce(types::I32, int);
            let round_trip = cursor.ins().sextend(types::I64, low);
            let fits = cursor.ins().icmp(IntCC::Equal, round_trip, int);
            let encode = cursor.func.dfg.make_block();
            cursor.ins().brif(fits, encode, &[], ctx.deopt, &[]);
            cursor.insert_block(encode);
            cursor.ins().band_imm(int, 0xFFFF_FFFF)
        }
    }
}

/// Emits one grammar expression, returning its typed value.
fn emit_expr(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    id: IrId,
    state: &mut EmitState,
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
        (IrKind::LocalVar, IrData::Local { slot: 0 }) if state.inline_params.is_some() => {
            let inline = state
                .inline_params
                .as_ref()
                .ok_or(JitLowerError::MissingIrBody { body: id })?;
            let arity = inline.len();
            Ok(inline[arity - 1])
        }
        (IrKind::LocalVar, IrData::Local { slot }) if state.inline_params.is_none() => {
            emit_frame_read(cursor, arena, ctx, id, 0, slot, state)
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) if state.inline_params.is_none() => {
            emit_frame_read(cursor, arena, ctx, id, depth, slot, state)
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot: 0 }) if state.inline_params.is_some() => {
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
        (
            IrKind::Let,
            IrData::Let {
                bindings: run,
                body,
                ..
            },
        ) => {
            if state.inline_params.is_some() {
                return Err(JitLowerError::UnsupportedArithOperand {
                    operand: id,
                    kind: IrKind::Let,
                });
            }
            let start = run.start as usize;
            let Some(run_bindings) = start
                .checked_add(run.len as usize)
                .and_then(|end| ctx.bindings.get(start..end))
            else {
                return Err(JitLowerError::UnsupportedArithOperand {
                    operand: id,
                    kind: IrKind::Let,
                });
            };
            let mut values = Vec::with_capacity(run_bindings.len());
            for binding in run_bindings {
                values.push(unwrap_thunk_alloc(arena, binding.value)?);
            }
            let computed = vec![LetSlot::Unevaluated; values.len()];
            state.let_scopes.push(LetScope { values, computed });
            let result = emit_expr(cursor, arena, ctx, body, state);
            state.let_scopes.pop();
            result
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

/// Emits one frame read (`LocalVar` distance 0, `UpvalVar { depth }` distance
/// `depth`) under the current let context.
fn emit_frame_read(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    at: IrId,
    distance: u32,
    slot: u32,
    state: &mut EmitState,
) -> Result<TypedVal, JitLowerError> {
    let let_depth = state.let_scopes.len() as u32;
    if distance < let_depth {
        let scope_index = (let_depth - 1 - distance) as usize;
        return emit_let_binding(cursor, arena, ctx, at, scope_index, slot as usize, state);
    }
    let normalized = distance - let_depth;
    if normalized < ctx.arity {
        if slot != 0 {
            return Err(JitLowerError::UnsupportedArithOperand {
                operand: at,
                kind: IrKind::UpvalVar,
            });
        }
        return emit_forced_param(cursor, ctx, (ctx.arity - 1 - normalized) as usize, state);
    }
    emit_forced_upval(cursor, ctx, normalized, slot, state)
}

/// Emits a `let`-binding read as a compute-at-first-use virtual register.
///
/// The binding value is emitted at its first read on each dominating path and
/// its typed register cached; a let-bound arithmetic result therefore stays
/// decoded across every later use. The `InProgress` marker turns a
/// scan-rejected own-frame read into a lowering error rather than a hang.
fn emit_let_binding(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    at: IrId,
    scope_index: usize,
    slot: usize,
    state: &mut EmitState,
) -> Result<TypedVal, JitLowerError> {
    let reject = JitLowerError::UnsupportedArithOperand {
        operand: at,
        kind: IrKind::UpvalVar,
    };
    let Some(scope) = state.let_scopes.get(scope_index) else {
        return Err(reject);
    };
    let value = match scope.computed.get(slot).copied() {
        Some(LetSlot::Ready(typed)) => return Ok(typed),
        Some(LetSlot::InProgress) | None => return Err(reject),
        Some(LetSlot::Unevaluated) => scope.values[slot],
    };
    state.let_scopes[scope_index].computed[slot] = LetSlot::InProgress;
    let inner_scopes = state.let_scopes.split_off(scope_index + 1);
    let emitted = emit_expr(cursor, arena, ctx, value, state);
    state.let_scopes.extend(inner_scopes);
    let typed = emitted?;
    state.let_scopes[scope_index].computed[slot] = LetSlot::Ready(typed);
    Ok(typed)
}

/// Emits a chain-parameter read, forcing it at first strict use on this path.
fn emit_forced_param(
    cursor: &mut FuncCursor,
    ctx: &mut ChainCtx<'_>,
    index: usize,
    state: &mut EmitState,
) -> Result<TypedVal, JitLowerError> {
    if let Some(cached) = state.forced_params[index] {
        return Ok(cached);
    }
    let raw = ctx.raw_params[index];
    let word = emit_force_int_fast_path(cursor, ctx, raw)?;
    let typed = TypedVal::Word(word);
    state.forced_params[index] = Some(typed);
    Ok(typed)
}

/// Emits an environment read beyond the chain parameters, forced at first use.
fn emit_forced_upval(
    cursor: &mut FuncCursor,
    ctx: &mut ChainCtx<'_>,
    depth: u32,
    slot: u32,
    state: &mut EmitState,
) -> Result<TypedVal, JitLowerError> {
    if let Some((_, cached)) = state
        .forced_upvals
        .iter()
        .find(|(coordinate, _)| *coordinate == (depth, slot))
    {
        return Ok(*cached);
    }
    let Some(upval_get) = ctx.upval_get else {
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
    let [raw] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_UPVAL_GET_SYMBOL,
            expected: 1,
            actual: results.len(),
        });
    };
    let word = emit_force_int_fast_path(cursor, ctx, raw)?;
    let typed = TypedVal::Word(word);
    state.forced_upvals.push(((depth, slot), typed));
    Ok(typed)
}

/// Emits the shared inline-int-or-force join for a raw value word.
///
/// An inline integer (high half zero) skips the call; anything else
/// round-trips through `aos_force`. Word-class values live across the force
/// are threaded through the fast/slow join and reloaded from the stack-map
/// slot; decoded integers survive in SSA and are untouched.
fn emit_force_int_fast_path(
    cursor: &mut FuncCursor,
    ctx: &mut ChainCtx<'_>,
    raw: ClifValue,
) -> Result<ClifValue, JitLowerError> {
    let high = cursor.ins().ushr_imm(raw, 32);
    let is_int = cursor.ins().icmp_imm(IntCC::Equal, high, 0);
    let slow = cursor.func.dfg.make_block();
    let join = cursor.func.dfg.make_block();
    cursor.func.dfg.append_block_param(join, types::I64);
    let live_before = ctx.live_words.clone();
    for _ in &live_before {
        cursor.func.dfg.append_block_param(join, types::I64);
    }
    let mut fast_args = vec![raw.into()];
    for value in &live_before {
        fast_args.push((*value).into());
    }
    cursor.ins().brif(is_int, join, &fast_args, slow, &[]);
    cursor.insert_block(slow);
    let forced = emit_force(
        cursor,
        ctx.stack_map_runtime,
        ctx.force,
        ctx.rt,
        &mut ctx.next_safepoint,
        raw,
        &mut ctx.live_words,
    )?;
    let mut slow_args = vec![forced.into()];
    for value in &ctx.live_words {
        slow_args.push((*value).into());
    }
    cursor.ins().jump(join, &slow_args);
    cursor.insert_block(join);
    let joined = cursor.func.dfg.block_params(join).to_vec();
    for (index, value) in ctx.live_words.iter_mut().enumerate() {
        *value = joined[1 + index];
    }
    Ok(joined[0])
}

/// Emits one mapped `aos_force` call, spilling the input and every live word.
fn emit_force(
    cursor: &mut FuncCursor,
    stack_map_runtime: stack_maps::Runtime,
    force: cranelift_codegen::ir::FuncRef,
    rt: ClifValue,
    next_safepoint: &mut u32,
    input: ClifValue,
    live: &mut [ClifValue],
) -> Result<ClifValue, JitLowerError> {
    let mut values = Vec::with_capacity(live.len().saturating_add(1));
    values.push(input);
    values.extend_from_slice(live);
    let binding = stack_maps::spill_values_one_word(cursor, &values);
    let safepoint = *next_safepoint;
    *next_safepoint =
        next_safepoint
            .checked_add(1)
            .ok_or(JitLowerError::MalformedForceSafepoint {
                reason: "function contains more than u32::MAX force calls",
            })?;
    stack_maps::enter(cursor, stack_map_runtime, rt, binding, safepoint);
    let call = cursor.ins().call(force, &[rt, input]);
    stack_maps::attach_one_word(cursor, call, binding);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    stack_maps::exit(cursor, stack_map_runtime, rt, binding);
    let [word] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_FORCE_SYMBOL,
            expected: 1,
            actual: results.len(),
        });
    };
    for (index, value) in live.iter_mut().enumerate() {
        *value = stack_maps::reload_one_word(cursor, binding, index + 1);
    }
    Ok(word)
}

/// A value tracked live across a following (possibly forcing) emission.
///
/// A `Word` may be a heap reference the collector relocates, so it is pushed
/// onto the live-word stack (spilled at the next force) and named by a stack
/// index; a decoded integer survives in SSA untouched and is carried verbatim.
enum LiveSlot {
    /// A live word at this index of [`ChainCtx::live_words`].
    Word(usize),
    /// A decoded integer that survives in SSA.
    Int(ClifValue),
}

/// Pushes a value onto the live-word stack when it needs relocation tracking.
fn track_live(ctx: &mut ChainCtx<'_>, value: TypedVal) -> LiveSlot {
    match value {
        TypedVal::Word(word) => {
            let index = ctx.live_words.len();
            ctx.live_words.push(word);
            LiveSlot::Word(index)
        }
        TypedVal::IntDecoded(int) => LiveSlot::Int(int),
    }
}

/// Reads back a tracked value after the following emission, popping the stack.
fn untrack_live(ctx: &mut ChainCtx<'_>, slot: LiveSlot) -> TypedVal {
    match slot {
        LiveSlot::Word(index) => {
            let word = ctx.live_words[index];
            ctx.live_words.truncate(index);
            TypedVal::Word(word)
        }
        LiveSlot::Int(int) => TypedVal::IntDecoded(int),
    }
}

/// Emits one binary operation, mirroring the tree walk's operand order.
///
/// Operands coerce to decoded integers (a `Word` operand gets the inline guard
/// exactly once; a decoded operand joins directly), the operation runs on
/// wrapping `i64` — intermediates carry no inline-range constraint — arithmetic
/// stays decoded, and comparisons select between the two canonical boolean
/// words. The first operand is tracked live across the second's emission so a
/// heap-word operand survives any force the second operand triggers.
fn emit_binop(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    op: BinOpKind,
    lhs: IrId,
    rhs: IrId,
    state: &mut EmitState,
) -> Result<TypedVal, JitLowerError> {
    let rhs_first = matches!(op, BinOpKind::Gt | BinOpKind::Le);
    let (lhs_val, rhs_val) = if rhs_first {
        let rhs_val = emit_expr(cursor, arena, ctx, rhs, state)?;
        let tracked = track_live(ctx, rhs_val);
        let lhs_val = emit_expr(cursor, arena, ctx, lhs, state)?;
        (lhs_val, untrack_live(ctx, tracked))
    } else {
        let lhs_val = emit_expr(cursor, arena, ctx, lhs, state)?;
        let tracked = track_live(ctx, lhs_val);
        let rhs_val = emit_expr(cursor, arena, ctx, rhs, state)?;
        (untrack_live(ctx, tracked), rhs_val)
    };
    let lhs_int = to_int(cursor, ctx, lhs_val);
    let rhs_int = to_int(cursor, ctx, rhs_val);

    match op {
        BinOpKind::Add => Ok(TypedVal::IntDecoded(cursor.ins().iadd(lhs_int, rhs_int))),
        BinOpKind::Sub => Ok(TypedVal::IntDecoded(cursor.ins().isub(lhs_int, rhs_int))),
        BinOpKind::Mul => Ok(TypedVal::IntDecoded(cursor.ins().imul(lhs_int, rhs_int))),
        BinOpKind::Div => {
            let nonzero = cursor.ins().icmp_imm(IntCC::NotEqual, rhs_int, 0);
            let lhs_is_min = cursor.ins().icmp_imm(IntCC::Equal, lhs_int, i64::MIN);
            let rhs_is_neg1 = cursor.ins().icmp_imm(IntCC::Equal, rhs_int, -1);
            let is_overflow = cursor.ins().band(lhs_is_min, rhs_is_neg1);
            let not_overflow = cursor.ins().icmp_imm(IntCC::Equal, is_overflow, 0);
            let safe = cursor.ins().band(nonzero, not_overflow);
            let divide = cursor.func.dfg.make_block();
            cursor.ins().brif(safe, divide, &[], ctx.deopt, &[]);
            cursor.insert_block(divide);
            Ok(TypedVal::IntDecoded(cursor.ins().sdiv(lhs_int, rhs_int)))
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

/// Emits an integer unary negation with the tree walk's wrapping semantics.
///
/// The operand coerces to a decoded integer (a float operand deopts) and is
/// negated as `0 - x` on wrapping `i64`; the decoded result never re-encodes
/// until it materializes.
fn emit_neg(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    operand: IrId,
    state: &mut EmitState,
) -> Result<TypedVal, JitLowerError> {
    let value = emit_expr(cursor, arena, ctx, operand, state)?;
    let int = to_int(cursor, ctx, value);
    let zero = cursor.ins().iconst(types::I64, 0);
    Ok(TypedVal::IntDecoded(cursor.ins().isub(zero, int)))
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

/// Emits an `if`/`then`/`else`, joining both arms on one `i64` block param.
///
/// The join carries the unified class: an Int/Int join stays decoded across
/// the branch (the common fold pattern `if p then acc * 31 + x else acc`),
/// everything else joins as encoded words. The join parameter type is `i64`
/// in both cases; only the wrapper class changes.
fn emit_if(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    cond: IrId,
    then_id: IrId,
    else_id: IrId,
    state: &mut EmitState,
) -> Result<TypedVal, JitLowerError> {
    require_static_bool_condition(arena, cond)?;
    let cond_val = emit_expr(cursor, arena, ctx, cond, state)?;
    let cond_word = to_word(cursor, ctx, cond_val);
    let truth = cursor.ins().band_imm(cond_word, 1);

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

    let before_branch = state.clone();
    cursor.insert_block(then_block);
    let mut then_state = before_branch.clone();
    let then_val = emit_expr(cursor, arena, ctx, then_id, &mut then_state)?;
    let then_carried = match join_class {
        ExprClass::Int => to_int(cursor, ctx, then_val),
        ExprClass::Word => to_word(cursor, ctx, then_val),
    };
    cursor.ins().jump(join, &[then_carried.into()]);

    cursor.insert_block(else_block);
    let mut else_state = before_branch.clone();
    let else_val = emit_expr(cursor, arena, ctx, else_id, &mut else_state)?;
    let else_carried = match join_class {
        ExprClass::Int => to_int(cursor, ctx, else_val),
        ExprClass::Word => to_word(cursor, ctx, else_val),
    };
    cursor.ins().jump(join, &[else_carried.into()]);

    cursor.insert_block(join);
    *state = before_branch;
    let joined = cursor.func.dfg.block_params(join).to_vec();
    Ok(match join_class {
        ExprClass::Int => TypedVal::IntDecoded(joined[0]),
        ExprClass::Word => TypedVal::Word(joined[0]),
    })
}

/// Emits one full application chain: a direct self-call or a pinned inline.
fn emit_call_chain(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    id: IrId,
    state: &mut EmitState,
) -> Result<TypedVal, JitLowerError> {
    if state.inline_params.is_some() {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: id,
            kind: IrKind::Apply,
        });
    }
    let let_depth = state.let_scopes.len() as u32;
    let (raw_upval, arguments) = flatten_apply_chain(arena, id, ctx.arity + let_depth)?;
    let upval = (raw_upval.0 - let_depth, raw_upval.1);

    if ctx.self_upval == Some(upval) {
        if arguments.len() as u32 != ctx.arity {
            return Err(JitLowerError::UnsupportedArithOperand {
                operand: id,
                kind: IrKind::Apply,
            });
        }
        let mut argument_words = Vec::with_capacity(arguments.len());
        for argument in &arguments {
            let value = emit_expr(cursor, arena, ctx, *argument, state)?;
            // Materialization point: the inner ABI takes encoded words, so a
            // wide decoded argument deopts here.
            argument_words.push(to_word(cursor, ctx, value));
        }
        return emit_self_call(cursor, ctx, &argument_words);
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
    let mut argument_values = Vec::with_capacity(arguments.len());
    for argument in &arguments {
        argument_values.push(emit_expr(cursor, arena, ctx, *argument, state)?);
    }
    // Inline the pinned callee body over the evaluated arguments (kept typed,
    // so a decoded argument stays decoded through the inlined arithmetic).
    let mut inline_state = EmitState {
        forced_params: state.forced_params.clone(),
        forced_upvals: state.forced_upvals.clone(),
        inline_params: Some(argument_values),
        let_scopes: Vec::new(),
    };
    let result = emit_expr(cursor, arena, ctx, pinned.body, &mut inline_state)?;
    state.forced_params = inline_state.forced_params;
    state.forced_upvals = inline_state.forced_upvals;
    Ok(result)
}

/// Emits one direct self-call with its depth guard and sentinel propagation.
fn emit_self_call(
    cursor: &mut FuncCursor,
    ctx: &mut ChainCtx<'_>,
    argument_words: &[ClifValue],
) -> Result<TypedVal, JitLowerError> {
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
    call_arguments.extend_from_slice(argument_words);
    call_arguments.push(next_budget);
    let call = cursor.ins().call(ctx.self_ref, &call_arguments);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let [word] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: "tier2_chain_self",
            expected: 1,
            actual: results.len(),
        });
    };
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
