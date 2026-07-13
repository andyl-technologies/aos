//! Tier-2 CLIF lowering for self-recursive arithmetic lambda bodies.
//!
//! Tier-1 lowers thunk *bodies* that wrap at most one runtime operation; the
//! per-dispatch harness caps it at neutral on call-dominated code. This module
//! is the first tier-2 lowering: it compiles an entire single-parameter lambda
//! body — integer arithmetic and comparisons, `if`/`then`/`else`, parameter
//! reads, and **direct self-recursive calls** — into native code that executes
//! without delegating per node. A self-recursive body amortizes the one
//! dispatch harness over the whole recursion tree: `fib 28` enters native code
//! once and performs its hundreds of thousands of recursive calls as direct
//! machine calls.
//!
//! # Compiled shape
//!
//! One lowering produces **two** CLIF functions:
//!
//! - `inner(rt, env, arg_tag, arg_payload, budget) -> (tag, payload)` — the
//!   compiled body. The lambda parameter arrives unboxed as a two-word runtime
//!   value in registers; `budget` is the remaining native call depth.
//!   Self-calls are direct calls to `inner` itself with `budget - 1`.
//! - `entry(rt, env, arg) -> Value` — the boundary adapter with the frozen
//!   [`runtime_lambda_call_signature`] ABI. It seeds `budget` with
//!   [`TIER2_NATIVE_DEPTH_BUDGET`] and translates the internal deopt sentinel
//!   into a valid null return (the recorded trap, not the value, signals the
//!   deopt to the dispatching wrapper).
//!
//! # Value discipline
//!
//! Values flow through compiled code as the frozen two-word `(tag, payload)`
//! pair. The parameter is forced at its first strict use on each path — the
//! same point the tree walk forces it — through an inline fast path: a value
//! already tagged `Int` skips the `aos_force` helper call entirely, so the hot
//! recursion (whose self-call arguments are freshly computed integers) makes no
//! helper calls at all. Arithmetic guards both operand tags and wraps on
//! overflow exactly like the tree walk's `wrapping_add`/`sub`/`mul` (the pinned
//! C++ Nix 2.24 semantics); division guards the zero divisor and `MIN / -1`.
//!
//! # Deoptimization discipline
//!
//! Every guard failure branches to a shared deopt block that records a deopt
//! trap (`aos_deopt`) and returns the internal sentinel tag
//! [`TIER2_DEOPT_SENTINEL_TAG`]; each self-call site checks for the sentinel
//! and propagates it, unwinding the entire native recursion to the boundary,
//! where the dispatcher re-runs the *boundary call* through the tree walk.
//! Re-execution is sound because everything a compiled body does is pure
//! except forcing the parameter — and forcing memoizes, so the re-run observes
//! identical values and reproduces the exact tree-walk result or error. The
//! depth guard deopts a self-call whose remaining `budget` is exhausted; the
//! dispatcher only enters native code when the interpreter's remaining
//! `max_call_depth` headroom covers the full budget, so any recursion that
//! completes natively is one the interpreter would also have completed, and
//! any deeper recursion re-runs interpreted and reproduces the interpreter's
//! own max-call-depth error (or completes, if headroom allowed).
//!
//! Any body shape outside this grammar fails to lower, which blacklists the
//! def-site: an unprovable body stays on the tree walk.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{
        AbiParam, ExtFuncData, ExternalName, Function, InstBuilder, Signature, UserExternalName,
        UserFuncName, condcodes::IntCC, types,
    },
};
use ratchet_core::{
    IrArena, IrData, IrId, IrKind, runtime_lambda_call_signature, syntax::BinOpKind,
};

use super::{
    AOS_DEOPT_SYMBOL, AOS_FORCE_SYMBOL, JitLowerError, append_entry_block_params,
    clif_external_name_for_aos_deopt, clif_external_name_for_aos_force, clif_name_for_ir_root,
    import_runtime_helper_function, stack_maps, verify_clif_function,
};
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
/// The runtime tag word for a suspended thunk (`ValueTag::Thunk`).
const TAG_THUNK: i64 = 0x20;

/// The internal deopt-unwind sentinel tag.
///
/// Returned in the tag word by a deopting `inner` frame and propagated by
/// every self-call site. It is strictly internal: the boundary `entry`
/// translates it to a valid null return before the pair crosses back into
/// Rust, because materializing an invalid `ValueTag` discriminant on the Rust
/// side would be undefined behavior. No real runtime tag uses this value.
const TIER2_DEOPT_SENTINEL_TAG: i64 = 0xFF;

/// The user-external-name namespace for tier-2 module-local function references.
///
/// A tier-2 `inner` body references itself (its recursive self-call) and the
/// `entry` adapter references `inner` through `UserExternalName` index 0 in
/// this namespace; the tier-2 define path rewrites it to the module-local
/// `FuncId` Cranelift assigned to `inner`.
pub const AOS_TIER2_LOCAL_FUNCTION_NAMESPACE: u32 = 9;

/// The native self-call depth budget a tier-2 boundary entry starts with.
///
/// Each native self-call decrements the budget; exhausting it deopts to the
/// tree walk. The dispatcher must not enter native code unless the
/// interpreter's remaining `max_call_depth` headroom is at least this budget,
/// which makes a natively-completed recursion one the interpreter would also
/// have completed (see the module docs). The value bounds the native stack:
/// tier-2 frames are small (a handful of spilled words), so 1024 nested native
/// frames stay well under typical stack limits.
pub const TIER2_NATIVE_DEPTH_BUDGET: i64 = 1024;

/// A verified tier-2 lowering of one self-recursive lambda body.
///
/// Produced by [`lower_tier2_self_recursive_lambda`]. Contains the two CLIF
/// functions described in the [module docs](self) plus the dispatch metadata
/// the engine needs: the upvalue coordinates of the self-callee (to guard, at
/// each boundary dispatch, that the callee closure's captured binding for that
/// upvalue is the applied closure itself) and the self-call count (a promotion
/// gate ingredient: only self-recursive bodies amortize the dispatch harness).
pub struct JitTier2LambdaLowering {
    /// The boundary adapter with the frozen lambda-call ABI.
    entry: Function,
    /// The compiled body with the internal unboxed-argument + budget signature.
    inner: Function,
    /// The lambda body IR node this lowering was compiled from.
    source: IrId,
    /// `(depth, slot)` of the body's self-callee upvalue, as resolved from the
    /// body environment (captured frames plus one call frame).
    self_upval: (u32, u32),
    /// The number of direct self-call sites in the body.
    self_call_count: u32,
}

impl JitTier2LambdaLowering {
    pub(crate) fn from_cached_parts(
        entry: Function,
        inner: Function,
        source: IrId,
        self_upval: (u32, u32),
        self_call_count: u32,
    ) -> Self {
        Self {
            entry,
            inner,
            source,
            self_upval,
            self_call_count,
        }
    }

    /// Returns the boundary entry function (frozen lambda-call ABI).
    pub fn entry(&self) -> &Function {
        &self.entry
    }

    /// Returns the compiled body function (internal recursive signature).
    pub fn inner(&self) -> &Function {
        &self.inner
    }

    /// Returns the lambda body IR node this lowering was compiled from.
    pub const fn source(&self) -> IrId {
        self.source
    }

    /// Returns the `(depth, slot)` coordinates of the self-callee upvalue.
    ///
    /// The coordinates are body-relative: depth counts enclosing frames from
    /// the lambda's call frame, so the dispatcher resolves them against the
    /// closure's captured environment at `captured_len - depth`.
    pub const fn self_upval(&self) -> (u32, u32) {
        self.self_upval
    }

    /// Returns the number of direct self-call sites compiled into the body.
    pub const fn self_call_count(&self) -> u32 {
        self.self_call_count
    }

    /// Consumes the lowering and returns `(entry, inner)`.
    pub fn into_functions(self) -> (Function, Function) {
        (self.entry, self.inner)
    }
}

/// Shared CLIF references threaded through the body emitter.
struct LambdaCtx {
    /// Imported `aos_force` helper (forces the parameter at first strict use).
    force: cranelift_codegen::ir::FuncRef,
    /// Compiled-frame bindings and user stack maps for slow-path forces.
    safepoints: stack_maps::ForceSafepoints,
    /// Imported `aos_deopt` helper called by the shared deopt block.
    deopt_fn: cranelift_codegen::ir::FuncRef,
    /// The module-local self reference for direct recursive calls.
    self_ref: cranelift_codegen::ir::FuncRef,
    /// The runtime-context entry parameter.
    rt: ClifValue,
    /// The environment entry parameter (unused by the current grammar, passed
    /// through to self-calls so upvalue reads can join the grammar later).
    env: ClifValue,
    /// The raw (possibly still suspended) parameter tag word.
    arg_tag: ClifValue,
    /// The raw parameter payload word.
    arg_payload: ClifValue,
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

/// Lowers a single-parameter self-recursive lambda into verified tier-2 CLIF.
///
/// `pattern` and `body` are the lambda's lowered parameter pattern and body
/// nodes (as carried by the closure's heap record). The pattern must be a bare
/// [`IrKind::Formal`] without a default (one call-frame slot, argument bound
/// at slot 0) and the body must fit the tier-2 grammar: integer/boolean
/// literals, parameter reads (`LocalVar` slot 0), integer arithmetic and
/// comparison `BinOp`s, `If` with a comparison or boolean-literal condition,
/// and `Apply` whose callee is a single consistent upvalue (the self-callee).
/// Bodies with no self-call lower too, but the engine's promotion gate
/// requires at least one (see [`JitTier2LambdaLowering::self_call_count`]).
///
/// `depth_budget` seeds the entry's native self-call budget; production
/// callers pass [`TIER2_NATIVE_DEPTH_BUDGET`], and the dispatcher must prove
/// matching interpreter headroom before every dispatch.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] / [`JitLowerError::MissingIrBody`]
/// when nodes are absent, [`JitLowerError::MismatchedIrNodeData`] for a
/// malformed payload, [`JitLowerError::UnsupportedArithOperand`] or
/// [`JitLowerError::UnsupportedArithOp`] for any body shape outside the
/// grammar, [`JitLowerError::Abi`] when the frozen signatures cannot be
/// lowered, and [`JitLowerError::Verifier`] when Cranelift rejects a generated
/// function.
pub fn lower_tier2_self_recursive_lambda(
    arena: &IrArena,
    pattern: IrId,
    body: IrId,
    depth_budget: i64,
) -> Result<JitTier2LambdaLowering, JitLowerError> {
    super::value_words::require_two_word_carrier("tier2-self-recursive-lambda")?;
    require_bare_formal_pattern(arena, pattern)?;
    let self_upval = find_single_self_callee(arena, body)?;

    let entry_signature = clif_signature_for_runtime_call(runtime_lambda_call_signature())?;
    let inner_signature = inner_signature_from_entry(&entry_signature);

    let (inner, self_call_count) =
        build_inner_function(arena, body, inner_signature.clone(), self_upval)?;
    let entry = build_entry_function(body, entry_signature, &inner_signature, depth_budget)?;

    verify_clif_function(&inner)?;
    verify_clif_function(&entry)?;

    Ok(JitTier2LambdaLowering {
        entry,
        inner,
        source: body,
        self_upval,
        self_call_count,
    })
}

/// Returns whether a lambda can possibly use the unary tier-2 body cache.
///
/// This is the allocation-free structural prefix of
/// [`lower_tier2_self_recursive_lambda`]: the parameter must be a bare formal,
/// the body must fit the unary callee-discovery traversal, and at least one
/// direct call must name one consistent upvalue. Passing is necessary but not
/// sufficient for promotion; Cranelift lowering and the native-cost gate remain
/// authoritative. Failing proves that a persistent unary record cannot exist,
/// so callers may skip disk and network probes before trying the curried-chain
/// tier.
#[must_use]
pub fn tier2_self_recursive_lambda_cache_eligible(
    arena: &IrArena,
    pattern: IrId,
    body: IrId,
) -> bool {
    require_bare_formal_pattern(arena, pattern).is_ok()
        && find_single_self_callee(arena, body).is_ok_and(|(depth, _)| depth >= 1)
}

/// Requires the lambda pattern to be a bare formal without a default.
///
/// A bare formal binds the argument at call-frame slot 0 of a one-slot frame,
/// which is exactly how the compiled body reads it (the unboxed entry
/// argument). Formal-set patterns and defaulted formals are outside the tier-2
/// grammar.
fn require_bare_formal_pattern(arena: &IrArena, pattern: IrId) -> Result<(), JitLowerError> {
    let node = arena
        .node(pattern)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: pattern })?;
    match (node.kind, node.data) {
        (IrKind::Formal, IrData::Formal { default: None, .. }) => Ok(()),
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand {
            operand: pattern,
            kind,
        }),
    }
}

/// Finds the single upvalue every `Apply` callee in the body reads.
///
/// Walks the grammar shape (without emitting code) and returns the `(depth,
/// slot)` of the callee upvalue shared by every application. A body whose
/// applications name more than one distinct upvalue, or whose callee is not an
/// upvalue read, is outside the grammar. A body with no application at all
/// reports `(0, 0)`; the caller distinguishes it through the emitted
/// self-call count.
fn find_single_self_callee(arena: &IrArena, body: IrId) -> Result<(u32, u32), JitLowerError> {
    let mut found: Option<(u32, u32)> = None;
    collect_self_callee(arena, body, &mut found)?;
    Ok(found.unwrap_or((0, 0)))
}

/// Recursive worker for [`find_single_self_callee`].
fn collect_self_callee(
    arena: &IrArena,
    id: IrId,
    found: &mut Option<(u32, u32)>,
) -> Result<(), JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::Int | IrKind::Bool, _) => Ok(()),
        (IrKind::LocalVar, _) => Ok(()),
        (IrKind::BinOp, IrData::Binary { lhs, rhs, .. }) => {
            collect_self_callee(arena, lhs, found)?;
            collect_self_callee(arena, rhs, found)
        }
        (
            IrKind::If,
            IrData::Triple {
                first,
                second,
                third,
            },
        ) => {
            collect_self_callee(arena, first, found)?;
            collect_self_callee(arena, second, found)?;
            collect_self_callee(arena, third, found)
        }
        (
            IrKind::Apply,
            IrData::Pair {
                first: callee,
                second: argument,
            },
        ) => {
            let callee_node = arena
                .node(callee)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body: callee })?;
            let coords = match (callee_node.kind, callee_node.data) {
                (IrKind::UpvalVar, IrData::Upval { depth, slot }) if depth >= 1 => (depth, slot),
                (kind, _) => {
                    return Err(JitLowerError::UnsupportedArithOperand {
                        operand: callee,
                        kind,
                    });
                }
            };
            match found {
                Some(existing) if *existing != coords => {
                    Err(JitLowerError::UnsupportedArithOperand {
                        operand: callee,
                        kind: IrKind::UpvalVar,
                    })
                }
                _ => {
                    *found = Some(coords);
                    collect_self_callee(arena, unwrap_thunk_alloc(arena, argument)?, found)
                }
            }
        }
        (IrKind::ThunkAlloc, IrData::Node(body)) => collect_self_callee(arena, body, found),
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand { operand: id, kind }),
    }
}

/// Unwraps a lazy `ThunkAlloc` wrapper around an argument expression.
///
/// The tree walk allocates a thunk for a lazy call argument; the compiled body
/// evaluates the wrapped expression eagerly, which is sound inside the grammar
/// because argument expressions are pure and can only deopt (see the module
/// docs on re-execution).
fn unwrap_thunk_alloc(arena: &IrArena, id: IrId) -> Result<IrId, JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => Ok(body),
        _ => Ok(id),
    }
}

/// Builds the internal recursive signature from the frozen entry signature.
///
/// `inner` extends the frozen lambda-call parameter list `(rt, env, arg_tag,
/// arg_payload)` with one trailing `i64` budget parameter and keeps the
/// two-word value return.
fn inner_signature_from_entry(entry: &Signature) -> Signature {
    let mut signature = entry.clone();
    signature.params.push(AbiParam::new(types::I64));
    signature
}

/// Imports the module-local tier-2 self/inner reference into `function`.
///
/// Shared with the fused curried-chain lowerer
/// ([`lambda_chain`](super::lambda_chain)), whose entry/inner pairing uses the
/// same module-local namespace protocol.
pub(super) fn import_tier2_local_function(
    function: &mut Function,
    signature: &Signature,
) -> cranelift_codegen::ir::FuncRef {
    let signature_ref = function.import_signature(signature.clone());
    let user_name = function.declare_imported_user_function(UserExternalName::new(
        AOS_TIER2_LOCAL_FUNCTION_NAMESPACE,
        0,
    ));
    function.import_function(ExtFuncData {
        name: ExternalName::user(user_name),
        signature: signature_ref,
        colocated: true,
    })
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
    let safepoints = stack_maps::ForceSafepoints::import(&mut function)?;
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
    let [rt, env, arg_tag, arg_payload, budget] = params[..] else {
        return Err(JitLowerError::MissingEntryBlockParameter {
            index: params.len(),
        });
    };
    let mut ctx = LambdaCtx {
        force,
        safepoints,
        deopt_fn,
        self_ref,
        rt,
        env,
        arg_tag,
        arg_payload,
        budget,
        deopt,
        sentinel,
        self_upval,
        self_call_count: 0,
    };

    let mut forced_param: Option<(ClifValue, ClifValue)> = None;
    let (tag, payload) = emit_expr(&mut cursor, arena, &mut ctx, body, &mut forced_param)?;
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

/// Builds the boundary entry adapter with the frozen lambda-call ABI.
fn build_entry_function(
    body: IrId,
    entry_signature: Signature,
    inner_signature: &Signature,
    depth_budget: i64,
) -> Result<Function, JitLowerError> {
    let mut function =
        Function::with_name_signature(clif_name_for_ir_root(body), entry_signature);
    let inner_ref = import_tier2_local_function(&mut function, inner_signature);

    let entry_block = append_entry_block_params(&mut function);
    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let params = cursor.func.dfg.block_params(entry_block).to_vec();
    let [rt, env, arg_tag, arg_payload] = params[..] else {
        return Err(JitLowerError::MissingEntryBlockParameter {
            index: params.len(),
        });
    };
    let budget = cursor.ins().iconst(types::I64, depth_budget);
    let call = cursor
        .ins()
        .call(inner_ref, &[rt, env, arg_tag, arg_payload, budget]);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let [tag, payload] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: "tier2_inner",
            expected: 2,
            actual: results.len(),
        });
    };
    // Translate the internal deopt sentinel into a valid null return before the
    // pair crosses into Rust: the recorded trap, not the value, carries the
    // deopt, and an invalid tag word must never materialize as a Rust `Value`.
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
///
/// `forced_param` caches the forced parameter for the current dominating path:
/// a force emitted before a branch dominates both arms, but a force inside an
/// arm must not leak past the join, so `If` emission clones the cache per arm
/// and restores the pre-branch cache afterwards.
fn emit_expr(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut LambdaCtx,
    id: IrId,
    forced_param: &mut Option<(ClifValue, ClifValue)>,
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
            emit_forced_param(cursor, ctx, forced_param)
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
/// The inline fast path skips the `aos_force` helper when the raw argument is
/// already an integer — the recursion's own self-call arguments always are —
/// so the hot path performs one compare-and-branch and no calls. Any other tag
/// (a suspended thunk, a float, a trap sentinel) takes the slow path through
/// `aos_force`, whose result feeds the operand guards exactly as the tree
/// walk's own forced value would.
fn emit_forced_param(
    cursor: &mut FuncCursor,
    ctx: &mut LambdaCtx,
    forced_param: &mut Option<(ClifValue, ClifValue)>,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    if let Some(cached) = *forced_param {
        return Ok(cached);
    }
    let is_int = cursor.ins().icmp_imm(IntCC::Equal, ctx.arg_tag, TAG_INT);
    let slow = cursor.func.dfg.make_block();
    let join = cursor.func.dfg.make_block();
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor
        .ins()
        .brif(is_int, join, &[ctx.arg_tag.into(), ctx.arg_payload.into()], slow, &[]);
    cursor.insert_block(slow);
    let force_results = ctx.safepoints.force(
        cursor,
        ctx.force,
        ctx.rt,
        [ctx.arg_tag, ctx.arg_payload],
        &mut [],
    )?;
    cursor
        .ins()
        .jump(join, &[force_results[0].into(), force_results[1].into()]);
    cursor.insert_block(join);
    let joined = cursor.func.dfg.block_params(join).to_vec();
    let pair = (joined[0], joined[1]);
    *forced_param = Some(pair);
    Ok(pair)
}

/// Emits one binary operation, mirroring the tree walk's operand order.
///
/// The tree walk evaluates `Gt` and `Le` right-operand-first (they lower onto
/// the flipped `<` comparison); every other operator evaluates left-first. The
/// operand order only matters for which guard deopts first — either way the
/// deopt re-runs the body interpreted — but mirroring it keeps the native
/// path's parameter-force point identical to the interpreter's.
fn emit_binop(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut LambdaCtx,
    op: BinOpKind,
    lhs: IrId,
    rhs: IrId,
    forced_param: &mut Option<(ClifValue, ClifValue)>,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    let rhs_first = matches!(op, BinOpKind::Gt | BinOpKind::Le);
    let (lhs_pair, rhs_pair) = if rhs_first {
        let rhs_pair = emit_expr(cursor, arena, ctx, rhs, forced_param)?;
        let lhs_pair = emit_expr(cursor, arena, ctx, lhs, forced_param)?;
        (lhs_pair, rhs_pair)
    } else {
        let lhs_pair = emit_expr(cursor, arena, ctx, lhs, forced_param)?;
        let rhs_pair = emit_expr(cursor, arena, ctx, rhs, forced_param)?;
        (lhs_pair, rhs_pair)
    };
    let (lhs_tag, lhs_payload) = lhs_pair;
    let (rhs_tag, rhs_payload) = rhs_pair;

    // Both operands must be integers for the inline path; anything else
    // (floats, strings, a trap sentinel from a failed force) deopts.
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
            // The tree walk errors on a zero divisor and on `i64::MIN / -1`;
            // both deopt rather than taking Cranelift's trapping `sdiv`.
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
///
/// The condition must be a shape the grammar statically knows produces a
/// boolean — a comparison `BinOp` or a boolean literal — so no runtime
/// boolean-tag guard is needed (a comparison's operand guards already deopt on
/// non-integers). Parameter forces emitted inside one arm do not leak into the
/// other arm or past the join.
fn emit_if(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut LambdaCtx,
    cond: IrId,
    then_id: IrId,
    else_id: IrId,
    forced_param: &mut Option<(ClifValue, ClifValue)>,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
    let cond_node = arena
        .node(cond)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: cond })?;
    let statically_boolean = match (cond_node.kind, cond_node.data) {
        (IrKind::Bool, _) => true,
        (
            IrKind::BinOp,
            IrData::Binary { op, .. },
        ) => matches!(
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
    let (_cond_tag, cond_payload) = emit_expr(cursor, arena, ctx, cond, forced_param)?;

    let then_block = cursor.func.dfg.make_block();
    let else_block = cursor.func.dfg.make_block();
    let join = cursor.func.dfg.make_block();
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor.func.dfg.append_block_param(join, types::I64);
    cursor
        .ins()
        .brif(cond_payload, then_block, &[], else_block, &[]);

    let before_branch = *forced_param;
    cursor.insert_block(then_block);
    let mut then_param = before_branch;
    let (then_tag, then_payload) = emit_expr(cursor, arena, ctx, then_id, &mut then_param)?;
    cursor
        .ins()
        .jump(join, &[then_tag.into(), then_payload.into()]);

    cursor.insert_block(else_block);
    let mut else_param = before_branch;
    let (else_tag, else_payload) = emit_expr(cursor, arena, ctx, else_id, &mut else_param)?;
    cursor
        .ins()
        .jump(join, &[else_tag.into(), else_payload.into()]);

    cursor.insert_block(join);
    *forced_param = before_branch;
    let joined = cursor.func.dfg.block_params(join).to_vec();
    Ok((joined[0], joined[1]))
}

/// Emits one direct self-call with its depth guard and sentinel propagation.
///
/// The callee must be the body's single self-callee upvalue (verified again
/// here against [`LambdaCtx::self_upval`]); the argument expression is
/// evaluated eagerly (its lazy `ThunkAlloc` wrapper unwrapped) and passed
/// unboxed. The budget guard deopts when no native depth remains; the
/// dispatcher's headroom precondition makes that deopt reproduce the
/// interpreter's own behavior (see the module docs).
fn emit_self_call(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut LambdaCtx,
    callee: IrId,
    argument: IrId,
    forced_param: &mut Option<(ClifValue, ClifValue)>,
) -> Result<(ClifValue, ClifValue), JitLowerError> {
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
    let (arg_tag, arg_payload) = emit_expr(cursor, arena, ctx, argument, forced_param)?;

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
    let call = cursor.ins().call(
        ctx.self_ref,
        &[ctx.rt, ctx.env, arg_tag, arg_payload, next_budget],
    );
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let [tag, payload] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: "tier2_self",
            expected: 2,
            actual: results.len(),
        });
    };
    // Propagate a callee deopt outward without re-recording the trap.
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

// Suppress an unused-constant lint until a future grammar reads raw thunks.
const _: i64 = TAG_THUNK;

// These tests exercise two-word-carrier codegen (tier-2 bodies, inline arith,
// candidate bridges, or two-word CLIF shape asserts), which declines on the
// one-word carrier; baseline-only until the S4b phase-2 one-word emitters land.
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests;
