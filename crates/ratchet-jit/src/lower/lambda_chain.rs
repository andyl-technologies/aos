//! Tier-2 CLIF lowering for fused curried lambda chains.
//!
//! [`lambda_rec`](super::lambda_rec) compiles single-formal self-recursive
//! bodies; this module compiles whole **curried chains** `p0: p1: ... pk: body`
//! as one native function of K arguments. Two workloads motivate it:
//!
//! - **Fold operators** (`acc: elem: ...` under `builtins.foldl'`): the fold
//!   loop applies the chain twice per element through fresh intermediate
//!   closures; a fused arity-2 entry replaces both applies and the closure
//!   churn with one native call per element.
//! - **Multi-argument recursions** (`tak = x: y: z: ...`): the interpreter
//!   builds two partial-application closures per recursive call; a fused
//!   arity-3 entry turns each `self a b c` chain into one direct native call.
//!
//! # Compiled shape
//!
//! One lowering produces two CLIF functions, mirroring `lambda_rec`:
//!
//! - `inner(rt, env, a0_tag, a0_pay, ..., budget) -> (tag, payload)` — the
//!   compiled innermost body with every chain parameter unboxed in registers.
//!   Full-arity self-call chains become direct calls to `inner` itself with
//!   `budget - 1`.
//! - `entry(rt, env, argv) -> Value` — the boundary adapter with the frozen
//!   [`runtime_lambda_argv_call_signature`] ABI: `argv` points to a
//!   caller-owned contiguous run of K by-value runtime values (outermost
//!   parameter first). The entry loads the pairs, seeds the depth budget, and
//!   translates the internal deopt sentinel into a valid null return.
//!
//! # Parameter coordinates
//!
//! Inside the innermost body, chain parameter `j` (0-based, outermost first)
//! is `LocalVar` slot 0 when `j == K-1` (the call frame) and `UpvalVar(depth
//! K-1-j, slot 0)` otherwise — the coordinates the resolver assigns to a chain
//! of bare formals with no intervening binders. Each parameter is forced at
//! its first strict use on each dominating path, exactly like `lambda_rec`'s
//! single parameter.
//!
//! # Callee classification
//!
//! [`scan_tier2_curried_chain`] discovers every `Apply` chain in the body
//! whose head is an upvalue read beyond the parameter frames and reports the
//! distinct `(depth, slot, arity)` callee sites. The engine classifies each
//! site as either the **self-callee** (resolves to the chain's own def-site;
//! its chains must be full arity K and lower to direct recursive calls) or a
//! **pinned callee** (a known closure whose own curried chain has a call-free
//! arithmetic body; its body is inlined at the call site and the engine
//! re-validates the pinned binding's def-site identity at every boundary
//! dispatch). Any other shape fails the scan and blacklists the def-site.
//!
//! # Deoptimization discipline
//!
//! Identical to `lambda_rec`: every guard failure (operand tag, division,
//! exhausted depth budget) records a deopt trap and unwinds to the boundary
//! through the sentinel tag; the dispatcher re-runs the boundary application
//! interpreted, which is sound because in-grammar bodies are pure except for
//! memoizing parameter forces.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, MemFlags, Signature, UserFuncName, condcodes::IntCC, types},
};
use ratchet_core::{
    IrArena, IrData, IrId, IrKind, runtime_lambda_argv_call_signature, syntax::BinOpKind,
};

use super::{
    AOS_DEOPT_SYMBOL, AOS_FORCE_SYMBOL, JitLowerError, append_entry_block_params,
    clif_external_name_for_aos_deopt, clif_external_name_for_aos_force, clif_name_for_ir_root,
    import_runtime_helper_function, verify_clif_function,
};
use super::lambda_rec::import_tier2_local_function;
use crate::abi::clif_signature_for_runtime_call;

/// A Cranelift SSA value, aliased to avoid confusion with the runtime `Value`.
type ClifValue = cranelift_codegen::ir::Value;
type Block = cranelift_codegen::ir::Block;

/// The runtime tag word for an inline integer value (`ValueTag::Int`).
const TAG_INT: i64 = 0x00;
/// The runtime tag word for an inline boolean value (`ValueTag::Bool`).
const TAG_BOOL: i64 = 0x02;
/// The runtime tag word for a null value (`ValueTag::Null`).
const TAG_NULL: i64 = 0x03;
/// The internal deopt-unwind sentinel tag (see `lambda_rec`).
const TIER2_DEOPT_SENTINEL_TAG: i64 = 0xFF;
/// The byte stride of one by-value runtime value in the entry's `argv` run.
const VALUE_STRIDE_BYTES: i32 = 16;
/// The byte offset of the payload word within one by-value runtime value.
const VALUE_PAYLOAD_OFFSET_BYTES: i32 = 8;

/// The maximum curried-chain arity the fused lowering compiles today.
pub const TIER2_MAX_CHAIN_ARITY: u32 = 3;

/// One callee site discovered by the chain scan.
///
/// Every `Apply` chain in the body whose head reads this upvalue must have
/// exactly `arity` applications; mixed arities for one upvalue fail the scan
/// (a partially applied callee could escape, which the fused grammar cannot
/// represent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitTier2ChainCalleeSite {
    /// Body-relative `(depth, slot)` of the callee upvalue.
    pub upval: (u32, u32),
    /// The consistent application-chain length at every site of this callee.
    pub arity: u32,
    /// The number of call chains headed by this callee.
    pub chain_count: u32,
}

/// The structural scan of one curried lambda chain.
///
/// Produced by [`scan_tier2_curried_chain`] before any engine-side resolution:
/// it validates the chain of bare formals, checks the innermost body against
/// the fused grammar, and reports the callee sites the engine must classify
/// into the self-callee and pinned callees before lowering.
#[derive(Clone, Debug)]
pub struct JitTier2ChainScan {
    /// The chain arity K (between 2 and [`TIER2_MAX_CHAIN_ARITY`]).
    arity: u32,
    /// The innermost lambda's parameter pattern node.
    inner_pattern: IrId,
    /// The innermost (non-lambda) body node the lowering compiles.
    inner_body: IrId,
    /// The distinct callee upvalue sites found in the body.
    callee_sites: Vec<JitTier2ChainCalleeSite>,
}

impl JitTier2ChainScan {
    /// Returns the chain arity K.
    pub const fn arity(&self) -> u32 {
        self.arity
    }

    /// Returns the innermost lambda's parameter pattern node.
    pub const fn inner_pattern(&self) -> IrId {
        self.inner_pattern
    }

    /// Returns the innermost body node the lowering compiles.
    pub const fn inner_body(&self) -> IrId {
        self.inner_body
    }

    /// Returns the distinct callee upvalue sites the engine must classify.
    pub fn callee_sites(&self) -> &[JitTier2ChainCalleeSite] {
        &self.callee_sites
    }
}

/// A pinned non-self callee resolved by the engine for inlining.
///
/// The engine resolves the callee upvalue against the promoted closure's
/// environment, validates that the resolved closure's own curried chain has a
/// call-free arithmetic body (see [`scan_tier2_pinned_callee`]), and passes
/// the callee's innermost body here so the lowering can inline it at every
/// call site. The engine re-validates the binding's def-site identity at
/// every boundary dispatch.
#[derive(Clone, Copy, Debug)]
pub struct JitTier2PinnedCallee {
    /// Body-relative `(depth, slot)` of the callee upvalue in the chain body.
    pub upval: (u32, u32),
    /// The callee's own chain arity.
    pub arity: u32,
    /// The callee's innermost (call-free) body node.
    pub body: IrId,
}

mod scan;

pub use scan::{scan_tier2_curried_chain, scan_tier2_pinned_callee};
use scan::{flatten_apply_chain, require_static_bool_condition};

/// A verified fused lowering of one curried lambda chain.
///
/// Produced by [`lower_tier2_curried_chain`]. Mirrors
/// [`JitTier2LambdaLowering`](super::JitTier2LambdaLowering) with a chain
/// arity and an optional self-callee (fold operators have none).
pub struct JitTier2ChainLowering {
    /// The boundary adapter with the frozen argv lambda-entry ABI.
    entry: Function,
    /// The compiled body with the internal unboxed-parameters signature.
    inner: Function,
    /// The innermost body IR node this lowering was compiled from.
    source: IrId,
    /// The chain arity K.
    arity: u32,
    /// The self-callee upvalue coordinates, when the body self-recurses.
    self_upval: Option<(u32, u32)>,
    /// The number of direct self-call chains compiled into the body.
    self_call_count: u32,
}

impl JitTier2ChainLowering {
    /// Returns the boundary entry function (frozen argv lambda-entry ABI).
    pub fn entry(&self) -> &Function {
        &self.entry
    }

    /// Returns the compiled body function (internal recursive signature).
    pub fn inner(&self) -> &Function {
        &self.inner
    }

    /// Returns the innermost body IR node this lowering was compiled from.
    pub const fn source(&self) -> IrId {
        self.source
    }

    /// Returns the chain arity K.
    pub const fn arity(&self) -> u32 {
        self.arity
    }

    /// Returns the self-callee upvalue coordinates, when present.
    pub const fn self_upval(&self) -> Option<(u32, u32)> {
        self.self_upval
    }

    /// Returns the number of direct self-call chains compiled into the body.
    pub const fn self_call_count(&self) -> u32 {
        self.self_call_count
    }

    /// Consumes the lowering and returns `(entry, inner)`.
    pub fn into_functions(self) -> (Function, Function) {
        (self.entry, self.inner)
    }
}

/// Shared CLIF references threaded through the fused body emitter.
struct ChainCtx {
    /// Imported `aos_force` helper (forces parameters at first strict use).
    force: cranelift_codegen::ir::FuncRef,
    /// Imported `aos_deopt` helper called by the shared deopt block.
    deopt_fn: cranelift_codegen::ir::FuncRef,
    /// The module-local self reference for direct recursive calls.
    self_ref: cranelift_codegen::ir::FuncRef,
    /// The runtime-context entry parameter.
    rt: ClifValue,
    /// The environment entry parameter (unused by the grammar, threaded for
    /// self-calls so upvalue reads can join the grammar later).
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
/// current path (an `If` arm must not leak its forces past the join, so arms
/// clone and restore the caches). `inline_params` is `Some` while emitting a
/// pinned callee's inlined body, mapping the callee's own parameter reads to
/// the already-evaluated argument pairs.
#[derive(Clone)]
struct EmitState {
    forced_params: Vec<Option<(ClifValue, ClifValue)>>,
    inline_params: Option<Vec<(ClifValue, ClifValue)>>,
}

/// Lowers a scanned curried chain into verified fused tier-2 CLIF.
///
/// `scan` is the structural scan of the chain, `self_upval` the callee site
/// the engine resolved to the chain's own def-site (its chains must be full
/// arity; `None` for a non-recursive fold operator), and `pinned` the resolved
/// pinned callees for every remaining callee site. `depth_budget` seeds the
/// entry's native self-call budget.
///
/// # Errors
///
/// Returns the scan errors of [`scan_tier2_curried_chain`] re-encountered
/// during emission, [`JitLowerError::UnsupportedArithOperand`] when a callee
/// site has neither a self nor a pinned classification (or a self chain is
/// not full arity), [`JitLowerError::Abi`] when the frozen signatures cannot
/// be lowered, and [`JitLowerError::Verifier`] when Cranelift rejects a
/// generated function.
pub fn lower_tier2_curried_chain(
    arena: &IrArena,
    scan: &JitTier2ChainScan,
    self_upval: Option<(u32, u32)>,
    pinned: &[JitTier2PinnedCallee],
    depth_budget: i64,
) -> Result<JitTier2ChainLowering, JitLowerError> {
    let entry_signature = clif_signature_for_runtime_call(runtime_lambda_argv_call_signature())?;
    let inner_signature = inner_signature_for_arity(&entry_signature, scan.arity);

    let (inner, self_call_count) = build_inner_function(
        arena,
        scan,
        inner_signature.clone(),
        self_upval,
        pinned,
    )?;
    let entry = build_entry_function(
        scan.inner_body,
        entry_signature,
        &inner_signature,
        scan.arity,
        depth_budget,
    )?;

    verify_clif_function(&inner)?;
    verify_clif_function(&entry)?;

    Ok(JitTier2ChainLowering {
        entry,
        inner,
        source: scan.inner_body,
        arity: scan.arity,
        self_upval,
        self_call_count,
    })
}

/// Builds the internal recursive signature for a K-parameter chain body.
///
/// `inner` keeps the entry's `(rt, env)` prefix, replaces the `argv` pointer
/// with `2 * K` unboxed `i64` tag/payload words, and appends one trailing
/// `i64` budget parameter.
fn inner_signature_for_arity(entry: &Signature, arity: u32) -> Signature {
    let mut signature = entry.clone();
    signature.params.truncate(2);
    for _ in 0..arity {
        signature
            .params
            .push(cranelift_codegen::ir::AbiParam::new(types::I64));
        signature
            .params
            .push(cranelift_codegen::ir::AbiParam::new(types::I64));
    }
    signature
        .params
        .push(cranelift_codegen::ir::AbiParam::new(types::I64));
    signature
}

/// Builds the compiled chain body and returns it with its self-call count.
fn build_inner_function(
    arena: &IrArena,
    scan: &JitTier2ChainScan,
    signature: Signature,
    self_upval: Option<(u32, u32)>,
    pinned: &[JitTier2PinnedCallee],
) -> Result<(Function, u32), JitLowerError> {
    let mut function = Function::with_name_signature(
        UserFuncName::user(
            super::lambda_rec::AOS_TIER2_LOCAL_FUNCTION_NAMESPACE,
            scan.inner_body.as_u32(),
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
    let self_ref = import_tier2_local_function(&mut function, &signature);

    let entry_block = append_entry_block_params(&mut function);
    let deopt = function.dfg.make_block();
    let sentinel = function.dfg.make_block();

    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let params = cursor.func.dfg.block_params(entry_block).to_vec();
    let expected = 2 + 2 * scan.arity as usize + 1;
    if params.len() != expected {
        return Err(JitLowerError::MissingEntryBlockParameter {
            index: params.len(),
        });
    }
    let rt = params[0];
    let env = params[1];
    let mut raw_params = Vec::with_capacity(scan.arity as usize);
    for j in 0..scan.arity as usize {
        raw_params.push((params[2 + 2 * j], params[2 + 2 * j + 1]));
    }
    let budget = params[expected - 1];

    let mut ctx = ChainCtx {
        force,
        deopt_fn,
        self_ref,
        rt,
        env,
        raw_params,
        budget,
        deopt,
        sentinel,
        arity: scan.arity,
        self_upval,
        pinned: pinned.to_vec(),
        self_call_count: 0,
    };
    let mut state = EmitState {
        forced_params: vec![None; scan.arity as usize],
        inline_params: None,
    };

    let (tag, payload) = emit_expr(&mut cursor, arena, &mut ctx, scan.inner_body, &mut state)?;
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

/// Builds the boundary entry adapter with the frozen argv lambda-entry ABI.
///
/// The entry loads `arity` by-value runtime values from the caller-owned
/// `argv` run (16-byte stride, tag word first), calls `inner` with the seeded
/// depth budget, and translates the internal deopt sentinel into a valid null
/// return (the recorded trap, not the value, signals the deopt).
fn build_entry_function(
    body: IrId,
    entry_signature: Signature,
    inner_signature: &Signature,
    arity: u32,
    depth_budget: i64,
) -> Result<Function, JitLowerError> {
    let mut function = Function::with_name_signature(clif_name_for_ir_root(body), entry_signature);
    let inner_ref = import_tier2_local_function(&mut function, inner_signature);

    let entry_block = append_entry_block_params(&mut function);
    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let params = cursor.func.dfg.block_params(entry_block).to_vec();
    let [rt, env, argv] = params[..] else {
        return Err(JitLowerError::MissingEntryBlockParameter {
            index: params.len(),
        });
    };
    let mut call_arguments = vec![rt, env];
    for j in 0..arity as i32 {
        let tag = cursor
            .ins()
            .load(types::I64, MemFlags::trusted(), argv, j * VALUE_STRIDE_BYTES);
        let payload = cursor.ins().load(
            types::I64,
            MemFlags::trusted(),
            argv,
            j * VALUE_STRIDE_BYTES + VALUE_PAYLOAD_OFFSET_BYTES,
        );
        call_arguments.push(tag);
        call_arguments.push(payload);
    }
    let budget = cursor.ins().iconst(types::I64, depth_budget);
    call_arguments.push(budget);
    let call = cursor.ins().call(inner_ref, &call_arguments);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let [tag, payload] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: "tier2_chain_inner",
            expected: 2,
            actual: results.len(),
        });
    };
    let is_sentinel = cursor
        .ins()
        .icmp_imm(IntCC::Equal, tag, TIER2_DEOPT_SENTINEL_TAG);
    let clean = cursor.func.dfg.make_block();
    let deopted = cursor.func.dfg.make_block();
    cursor.ins().brif(is_sentinel, deopted, &[], clean, &[]);
    cursor.insert_block(clean);
    cursor.ins().return_(&[tag, payload]);
    cursor.insert_block(deopted);
    let null_tag = cursor.ins().iconst(types::I64, TAG_NULL);
    let null_payload = cursor.ins().iconst(types::I64, 0);
    cursor.ins().return_(&[null_tag, null_payload]);
    drop(cursor);
    Ok(function)
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
    let pair = (joined[0], joined[1]);
    state.forced_params[index] = Some(pair);
    pair
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
        inline_params: Some(argument_pairs),
    };
    let result = emit_expr(cursor, arena, ctx, pinned.body, &mut inline_state)?;
    state.forced_params = inline_state.forced_params;
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

#[cfg(test)]
mod tests;
