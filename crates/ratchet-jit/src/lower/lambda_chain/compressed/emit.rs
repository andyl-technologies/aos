//! One-word (Candidate-C) CLIF emission for the fused curried-chain grammar.
//!
//! The compressed-word sibling of [`super::super::emit`]: same grammar, same
//! recursive walk, same forced-parameter/environment/`let` discipline, direct
//! self-calls, pinned-callee inlining, and deopt guards — but every runtime
//! value is one compressed word instead of a `(tag, payload)` pair.
//!
//! # Value discipline
//!
//! Expressions uniformly produce one encoded word. An inline integer's high
//! half (kind, arena domain, forced bit) is all zero, so a binary operation
//! guards both operand words with one `or`-and-compare, decodes each by
//! sign-extending its low half, computes on wrapping `i64` (the tree walk's
//! per-step semantics), and re-encodes the result — deopting when it exceeds
//! the inline `i32` range, where the tree walk re-runs and boxes it.
//! Comparisons select between the two canonical boolean words. A parameter or
//! environment read is forced at its first strict use on each dominating path,
//! exactly like the two-word emitter and the tree walk (a force can record
//! impure observations, so its timing is load-bearing for trace parity); the
//! fast path skips the `aos_force` call when the raw word is already an inline
//! integer, which the recursion's own self-call arguments always are.
//!
//! # Live values across forces
//!
//! An operand already emitted while a later operand is still being computed is
//! *live* across any force the later operand triggers. Such a word may be a
//! heap reference the collector relocates at the force safepoint, so it is
//! spilled into the one-word stack-map slot alongside the force input and
//! reloaded afterwards, and threaded through the fast/slow join so both paths
//! agree on its post-force SSA value — the same plumbing as the two-word
//! emitter, one word wide.
//!
//! # Sentinel
//!
//! The internal deopt-unwind sentinel is a word whose kind byte is `0xFF` — no
//! valid compressed kind uses it — propagated by every self-call site and
//! translated to the canonical null word at the boundary before it could
//! materialize as a Rust `Value`.

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
use super::super::{
    JitTier2ChainScan, JitTier2EnvBoundary, JitTier2PinnedCallee,
};
use super::TIER2_DEOPT_SENTINEL_WORD;

/// A Cranelift SSA value, aliased to avoid confusion with the runtime `Value`.
type ClifValue = cranelift_codegen::ir::Value;
type Block = cranelift_codegen::ir::Block;

/// The body shape compiled into one chain inner function.
#[derive(Clone, Copy, Debug)]
pub(in crate::lower::lambda_chain) enum ChainInnerBody {
    /// The chain's own innermost body (the plain fold/apply-seam shape).
    Plain,
    /// A fused `builtins.genList` fold step: the generator body is emitted
    /// over the raw index parameter first and its result is seeded as the
    /// already-forced element parameter of the operator body.
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
    /// One-word runtime values currently live across recursive emission.
    live_values: Vec<ClifValue>,
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
    ///
    /// A body-relative read at `depth >= arity` translates to
    /// `aos_upval_get(env, depth - env_skew, slot)`; see
    /// [`JitTier2EnvBoundary`](super::super::JitTier2EnvBoundary).
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
/// `forced_params` caches the forced word of each chain parameter along the
/// current path, `forced_upvals` the forced word of each environment read
/// (keyed by **normalized**, let-free coordinates), and `let_scopes` the
/// virtual registers of the enclosing `let` frames (an `If` arm must not leak
/// its forces or binding computations past the join, so arms clone and restore
/// the whole state). `inline_params` is `Some` while emitting a pinned callee's
/// (or fused generator's) inlined body, mapping the callee's own parameter
/// reads to the already-evaluated argument words.
#[derive(Clone)]
struct EmitState {
    forced_params: Vec<Option<ClifValue>>,
    forced_upvals: Vec<((u32, u32), ClifValue)>,
    inline_params: Option<Vec<ClifValue>>,
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
    /// Computed on this path; reads reuse the register word.
    Ready(ClifValue),
}

/// Builds the compiled chain body and returns it with its self-call count.
///
/// `body` selects between the plain innermost-body emission and the fused
/// `genList` fold-step emission; `env_boundary` fixes the compile-time depth
/// translation for environment reads. The one-word sibling of
/// [`super::super::emit::build_inner_function`].
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
        live_values: Vec::new(),
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
        // parameter (always an inline integer supplied by the native loop),
        // so it is emitted eagerly with the index as its sole inline
        // parameter. This is sound even when the operator never demands its
        // element: the emission is pure and side-effect-free — its only exits
        // are a value or the shared deopt block, never a force or a call.
        let index_word = ctx.raw_params[1];
        let mut generator_state = EmitState {
            forced_params: vec![None; arity as usize],
            forced_upvals: Vec::new(),
            inline_params: Some(vec![index_word]),
            let_scopes: Vec::new(),
        };
        let element = emit_expr(&mut cursor, arena, &mut ctx, generator_body, &mut generator_state)?;
        // The generated element replaces the raw element parameter: it is by
        // construction already in weak head normal form, so the operator body
        // sees it as forced and never round-trips through `aos_force`.
        state.forced_params[1] = Some(element);
    }

    let word = emit_expr(&mut cursor, arena, &mut ctx, scan.inner_body(), &mut state)?;
    cursor.ins().return_(&[word]);

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

/// Emits one grammar expression, returning its encoded word.
fn emit_expr(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    id: IrId,
    state: &mut EmitState,
) -> Result<ClifValue, JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::Int, IrData::Int(value)) => {
            let word = CompressedValueWord::inline_int(value).map_err(|_| {
                JitLowerError::UnsupportedArithOperand {
                    operand: id,
                    kind: IrKind::Int,
                }
            })?;
            Ok(cursor.ins().iconst(types::I64, word.raw() as i64))
        }
        (IrKind::Bool, IrData::Bool(value)) => Ok(cursor
            .ins()
            .iconst(types::I64, CompressedValueWord::boolean(value).raw() as i64)),
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
        (IrKind::UpvalVar, IrData::Upval { depth, slot })
            if state.inline_params.is_none() =>
        {
            emit_frame_read(cursor, arena, ctx, id, depth, slot, state)
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
        (
            IrKind::Let,
            IrData::Let {
                bindings: run,
                body,
                ..
            },
        ) => {
            // A pinned callee (or fused generator) body is let-free by
            // validation; a let here means the classification drifted.
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

/// Emits one frame read (`LocalVar` is distance 0, `UpvalVar { depth }`
/// distance `depth`) under the current let context.
///
/// Mirrors the scan's coordinate model: a distance below the let depth is a
/// `let`-binding virtual register, the next `arity` distances are chain
/// parameters, and everything deeper is an environment read at the normalized
/// (let-free) depth.
fn emit_frame_read(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    at: IrId,
    distance: u32,
    slot: u32,
    state: &mut EmitState,
) -> Result<ClifValue, JitLowerError> {
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
        // Chain parameter j at normalized depth K-1-j: index = K-1-depth.
        return emit_forced_param(cursor, ctx, (ctx.arity - 1 - normalized) as usize, state);
    }
    emit_forced_upval(cursor, ctx, normalized, slot, state)
}

/// Emits a `let`-binding read as a compute-at-first-use virtual register.
///
/// The binding value expression is emitted — in the context of its own let
/// frame, with the inner scopes temporarily set aside — at the first read on
/// each dominating path, exactly where the interpreter would force the binding
/// thunk, and the resulting register word is cached in the path state for
/// later reads. The scan's letrec restriction guarantees the value reads no
/// slot of its own frame, so the recursion terminates; the `InProgress` marker
/// turns any drift into a lowering error rather than a hang.
fn emit_let_binding(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    at: IrId,
    scope_index: usize,
    slot: usize,
    state: &mut EmitState,
) -> Result<ClifValue, JitLowerError> {
    let reject = JitLowerError::UnsupportedArithOperand {
        operand: at,
        kind: IrKind::UpvalVar,
    };
    let Some(scope) = state.let_scopes.get(scope_index) else {
        return Err(reject);
    };
    let value = match scope.computed.get(slot).copied() {
        Some(LetSlot::Ready(word)) => return Ok(word),
        Some(LetSlot::InProgress) | None => return Err(reject),
        Some(LetSlot::Unevaluated) => scope.values[slot],
    };
    state.let_scopes[scope_index].computed[slot] = LetSlot::InProgress;
    // The binding value's coordinates count its own frame as innermost:
    // emit it with the inner scopes set aside, then restore them.
    let inner_scopes = state.let_scopes.split_off(scope_index + 1);
    let emitted = emit_expr(cursor, arena, ctx, value, state);
    state.let_scopes.extend(inner_scopes);
    let word = emitted?;
    state.let_scopes[scope_index].computed[slot] = LetSlot::Ready(word);
    Ok(word)
}

/// Emits a chain-parameter read, forcing it at first strict use on this path.
fn emit_forced_param(
    cursor: &mut FuncCursor,
    ctx: &mut ChainCtx<'_>,
    index: usize,
    state: &mut EmitState,
) -> Result<ClifValue, JitLowerError> {
    if let Some(cached) = state.forced_params[index] {
        return Ok(cached);
    }
    let raw = ctx.raw_params[index];
    let word = emit_force_int_fast_path(cursor, ctx, raw)?;
    state.forced_params[index] = Some(word);
    Ok(word)
}

/// Emits an environment read beyond the chain parameters.
///
/// `depth` is the **normalized** (let-free) body-relative depth; it is
/// translated onto the boundary `env` pointer by subtracting the seam's frame
/// skew (see [`ChainCtx::env_skew`]), read through `aos_upval_get`, and forced
/// at first strict use on this dominating path — the same discipline as chain
/// parameters, with the forced word cached per normalized `(depth, slot)`
/// coordinate so reads of one slot from different let depths share the
/// register.
fn emit_forced_upval(
    cursor: &mut FuncCursor,
    ctx: &mut ChainCtx<'_>,
    depth: u32,
    slot: u32,
    state: &mut EmitState,
) -> Result<ClifValue, JitLowerError> {
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
    let [raw] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_UPVAL_GET_SYMBOL,
            expected: 1,
            actual: results.len(),
        });
    };
    let word = emit_force_int_fast_path(cursor, ctx, raw)?;
    state.forced_upvals.push(((depth, slot), word));
    Ok(word)
}

/// Emits the shared inline-int-or-force join for a raw value word.
///
/// An inline integer (high half zero) skips the call; anything else
/// round-trips through `aos_force`, which either returns the forced word or
/// transfers an evaluator error as a trap the boundary converts to a deopt.
/// Values live across the force are threaded through the fast/slow join so
/// both paths agree on their post-force SSA words.
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
    let live_before = ctx.live_values.clone();
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
        &mut ctx.live_values,
    )?;
    let mut slow_args = vec![forced.into()];
    for value in &ctx.live_values {
        slow_args.push((*value).into());
    }
    cursor.ins().jump(join, &slow_args);
    cursor.insert_block(join);
    let joined = cursor.func.dfg.block_params(join).to_vec();
    for (index, value) in ctx.live_values.iter_mut().enumerate() {
        *value = joined[1 + index];
    }
    Ok(joined[0])
}

/// Emits one mapped `aos_force` call, spilling the input and every live value.
///
/// The one-word sibling of
/// [`ForceSafepoints::force`](super::super::super::stack_maps): the input and
/// the caller's live words are spilled after the intrusive binding header at an
/// 8-byte stride, the enter/exit helpers bracket the call, and the live words
/// are reloaded after the runtime has had an opportunity to rewrite the frame.
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

/// Emits one binary operation, mirroring the tree walk's operand order.
///
/// Both operand words are guarded to be inline integers with one combined
/// high-half check, decoded, computed on wrapping `i64`, and the result
/// re-encoded (or, for comparisons, selected between the two canonical boolean
/// words). An arithmetic result outside the inline range deopts so the tree
/// walk re-runs and boxes it.
fn emit_binop(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    op: BinOpKind,
    lhs: IrId,
    rhs: IrId,
    state: &mut EmitState,
) -> Result<ClifValue, JitLowerError> {
    let rhs_first = matches!(op, BinOpKind::Gt | BinOpKind::Le);
    let (lhs_word, rhs_word) = if rhs_first {
        let rhs_word = emit_expr(cursor, arena, ctx, rhs, state)?;
        let live_index = ctx.live_values.len();
        ctx.live_values.push(rhs_word);
        let lhs_word = emit_expr(cursor, arena, ctx, lhs, state)?;
        let rhs_word = ctx.live_values[live_index];
        ctx.live_values.truncate(live_index);
        (lhs_word, rhs_word)
    } else {
        let lhs_word = emit_expr(cursor, arena, ctx, lhs, state)?;
        let live_index = ctx.live_values.len();
        ctx.live_values.push(lhs_word);
        let rhs_word = emit_expr(cursor, arena, ctx, rhs, state)?;
        let lhs_word = ctx.live_values[live_index];
        ctx.live_values.truncate(live_index);
        (lhs_word, rhs_word)
    };

    // Both operands must be inline integers (all-zero high halves) for the
    // inline path; anything else (bools, boxed scalars, heap words, the
    // sentinel) deopts.
    let combined = cursor.ins().bor(lhs_word, rhs_word);
    let combined_high = cursor.ins().ushr_imm(combined, 32);
    let both_int = cursor.ins().icmp_imm(IntCC::Equal, combined_high, 0);
    let compute = cursor.func.dfg.make_block();
    cursor.ins().brif(both_int, compute, &[], ctx.deopt, &[]);
    cursor.insert_block(compute);

    let lhs_low = cursor.ins().ireduce(types::I32, lhs_word);
    let lhs_int = cursor.ins().sextend(types::I64, lhs_low);
    let rhs_low = cursor.ins().ireduce(types::I32, rhs_word);
    let rhs_int = cursor.ins().sextend(types::I64, rhs_low);

    match op {
        BinOpKind::Add => {
            let result = cursor.ins().iadd(lhs_int, rhs_int);
            Ok(emit_inline_int_encode(cursor, ctx, result))
        }
        BinOpKind::Sub => {
            let result = cursor.ins().isub(lhs_int, rhs_int);
            Ok(emit_inline_int_encode(cursor, ctx, result))
        }
        BinOpKind::Mul => {
            let result = cursor.ins().imul(lhs_int, rhs_int);
            Ok(emit_inline_int_encode(cursor, ctx, result))
        }
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
            let result = cursor.ins().sdiv(lhs_int, rhs_int);
            Ok(emit_inline_int_encode(cursor, ctx, result))
        }
        BinOpKind::Lt => Ok(bool_word(cursor, IntCC::SignedLessThan, lhs_int, rhs_int)),
        BinOpKind::Gt => Ok(bool_word(cursor, IntCC::SignedGreaterThan, lhs_int, rhs_int)),
        BinOpKind::Le => Ok(bool_word(
            cursor,
            IntCC::SignedLessThanOrEqual,
            lhs_int,
            rhs_int,
        )),
        BinOpKind::Ge => Ok(bool_word(
            cursor,
            IntCC::SignedGreaterThanOrEqual,
            lhs_int,
            rhs_int,
        )),
        BinOpKind::Eq => Ok(bool_word(cursor, IntCC::Equal, lhs_int, rhs_int)),
        BinOpKind::Ne => Ok(bool_word(cursor, IntCC::NotEqual, lhs_int, rhs_int)),
        op => Err(JitLowerError::UnsupportedArithOp { op }),
    }
}

/// Emits an integer unary negation with the tree walk's wrapping semantics.
///
/// The operand is guarded as an inline integer (a float operand deopts and the
/// interpreted re-run produces the tree walk's float negation), decoded, and
/// negated as `0 - x`; the result re-encodes as an inline word or deopts when
/// it leaves the inline range (`-i32::MIN` does), exactly like the tree walk
/// boxing a wide result.
fn emit_neg(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    operand: IrId,
    state: &mut EmitState,
) -> Result<ClifValue, JitLowerError> {
    let word = emit_expr(cursor, arena, ctx, operand, state)?;
    let high = cursor.ins().ushr_imm(word, 32);
    let is_int = cursor.ins().icmp_imm(IntCC::Equal, high, 0);
    let compute = cursor.func.dfg.make_block();
    cursor.ins().brif(is_int, compute, &[], ctx.deopt, &[]);
    cursor.insert_block(compute);
    let low = cursor.ins().ireduce(types::I32, word);
    let int = cursor.ins().sextend(types::I64, low);
    let zero = cursor.ins().iconst(types::I64, 0);
    let result = cursor.ins().isub(zero, int);
    Ok(emit_inline_int_encode(cursor, ctx, result))
}

/// Re-encodes a computed integer as an inline word, deopting when too wide.
fn emit_inline_int_encode(
    cursor: &mut FuncCursor,
    ctx: &ChainCtx<'_>,
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
/// The condition must be statically boolean (a comparison `BinOp` or a boolean
/// literal); its truth is the word's low bit, which is `1` exactly for the
/// canonical `true` word.
fn emit_if(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    cond: IrId,
    then_id: IrId,
    else_id: IrId,
    state: &mut EmitState,
) -> Result<ClifValue, JitLowerError> {
    require_static_bool_condition(arena, cond)?;
    let cond_word = emit_expr(cursor, arena, ctx, cond, state)?;
    let truth = cursor.ins().band_imm(cond_word, 1);

    let then_block = cursor.func.dfg.make_block();
    let else_block = cursor.func.dfg.make_block();
    let join = cursor.func.dfg.make_block();
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor.ins().brif(truth, then_block, &[], else_block, &[]);

    let before_branch = state.clone();
    cursor.insert_block(then_block);
    let mut then_state = before_branch.clone();
    let then_word = emit_expr(cursor, arena, ctx, then_id, &mut then_state)?;
    cursor.ins().jump(join, &[then_word.into()]);

    cursor.insert_block(else_block);
    let mut else_state = before_branch.clone();
    let else_word = emit_expr(cursor, arena, ctx, else_id, &mut else_state)?;
    cursor.ins().jump(join, &[else_word.into()]);

    cursor.insert_block(join);
    *state = before_branch;
    let joined = cursor.func.dfg.block_params(join).to_vec();
    Ok(joined[0])
}

/// Emits one full application chain: a direct self-call or a pinned inline.
///
/// The chain's head upvalue selects the classification recorded at lowering
/// time; argument expressions are evaluated eagerly, in call order, before the
/// self-call or the inlined callee body.
fn emit_call_chain(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    id: IrId,
    state: &mut EmitState,
) -> Result<ClifValue, JitLowerError> {
    if state.inline_params.is_some() {
        // A pinned callee body is call-free by validation; a chain here means
        // the classification drifted from the scan.
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: id,
            kind: IrKind::Apply,
        });
    }
    let let_depth = state.let_scopes.len() as u32;
    let (raw_upval, arguments) = flatten_apply_chain(arena, id, ctx.arity + let_depth)?;
    // Callee classifications are recorded in normalized (let-free) coords;
    // strip the enclosing let depth before matching.
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
            argument_words.push(emit_expr(cursor, arena, ctx, *argument, state)?);
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
    let mut argument_words = Vec::with_capacity(arguments.len());
    for argument in &arguments {
        argument_words.push(emit_expr(cursor, arena, ctx, *argument, state)?);
    }
    // Inline the pinned callee body over the evaluated arguments. The inlined
    // body reads only its own parameters (validated call-free), so the outer
    // forced-parameter caches pass through unchanged.
    let mut inline_state = EmitState {
        forced_params: state.forced_params.clone(),
        forced_upvals: state.forced_upvals.clone(),
        inline_params: Some(argument_words),
        // Pinned bodies are let-free by validation; argument emission above
        // already ran in the caller's let context.
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
) -> Result<ClifValue, JitLowerError> {
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
    Ok(word)
}
