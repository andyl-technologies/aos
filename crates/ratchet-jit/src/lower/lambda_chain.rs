//! Tier-2 CLIF lowering for fused curried lambda chains.
//!
//! [`lambda_rec`](super::lambda_rec) compiles single-formal self-recursive
//! bodies; this module compiles whole **curried chains** `p0: p1: ... pk: body`
//! as one native function of K arguments. Two workloads motivate it:
//!
//! - **Fold operators** (`acc: elem: ...` under `builtins.foldl'`): the fold
//!   loop applies the chain twice per element through fresh intermediate
//!   closures; a fused arity-2 entry replaces both applies and the closure
//!   churn with one native call per element. The [`lower_tier2_fold_genlist`]
//!   variant additionally fuses an in-grammar `builtins.genList` generator
//!   into the fold step, so the native loop synthesizes each element from its
//!   index instead of forcing a materialized element thunk.
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
//! single parameter. Upvalue reads at `depth >= K` are **environment reads**
//! against the boundary `env` pointer; their compile-time depth translation
//! is fixed by [`JitTier2EnvBoundary`] (see the [`emit`] module docs for the
//! recursion-invariance argument).
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
//! memoizing parameter and environment forces.

#[cfg(not(feature = "candidate_c_value"))]
use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{InstBuilder, MemFlags, Signature, condcodes::IntCC, types},
};
use cranelift_codegen::ir::Function;
#[cfg(not(feature = "candidate_c_value"))]
use ratchet_core::runtime_lambda_argv_call_signature;
use ratchet_core::{IrArena, IrBinding, IrId};

use super::JitLowerError;
#[cfg(not(feature = "candidate_c_value"))]
use super::{append_entry_block_params, clif_name_for_ir_root, verify_clif_function};
#[cfg(not(feature = "candidate_c_value"))]
use super::lambda_rec::import_tier2_local_function;
#[cfg(not(feature = "candidate_c_value"))]
use crate::abi::clif_signature_for_runtime_call;

/// The runtime tag word for an inline integer value (`ValueTag::Int`).
#[cfg(not(feature = "candidate_c_value"))]
pub(super) const TAG_INT: i64 = 0x00;
/// The runtime tag word for an inline boolean value (`ValueTag::Bool`).
#[cfg(not(feature = "candidate_c_value"))]
pub(super) const TAG_BOOL: i64 = 0x02;
/// The runtime tag word for a null value (`ValueTag::Null`).
#[cfg(not(feature = "candidate_c_value"))]
const TAG_NULL: i64 = 0x03;
/// The internal deopt-unwind sentinel tag (see `lambda_rec`).
#[cfg(not(feature = "candidate_c_value"))]
pub(super) const TIER2_DEOPT_SENTINEL_TAG: i64 = 0xFF;
/// The byte stride of one by-value runtime value in the entry's `argv` run.
#[cfg(not(feature = "candidate_c_value"))]
const VALUE_STRIDE_BYTES: i32 = 16;
/// The byte offset of the payload word within one by-value runtime value.
#[cfg(not(feature = "candidate_c_value"))]
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
    /// The chain arity K.
    ///
    /// Between 2 and [`TIER2_MAX_CHAIN_ARITY`] for a chain produced by
    /// [`scan_tier2_curried_chain`]; exactly 1 for a filter predicate
    /// produced by [`scan_tier2_unary_predicate`].
    arity: u32,
    /// The innermost lambda's parameter pattern node.
    inner_pattern: IrId,
    /// The innermost (non-lambda) body node the lowering compiles.
    inner_body: IrId,
    /// The distinct callee upvalue sites found in the body.
    callee_sites: Vec<JitTier2ChainCalleeSite>,
    /// Whether the body reads any upvalue beyond the chain parameters.
    reads_env: bool,
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

    /// Returns whether the body reads the captured environment.
    ///
    /// True when any value operand is an upvalue beyond the chain parameters;
    /// the lowering then imports `aos_upval_get` and the compiled body reads
    /// the boundary `env` pointer at runtime.
    pub const fn reads_env(&self) -> bool {
        self.reads_env
    }
}

/// How the boundary `env` pointer relates to the chain's conceptual frames.
///
/// Environment reads inside the compiled body use body-relative coordinates
/// that count the chain parameter frames; the boundary environment handed to
/// the native call omits some of those frames, and *which* frames depends on
/// the dispatching seam. The lowering bakes the translation in at compile
/// time, so an entry compiled for one seam must only be dispatched by that
/// seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JitTier2EnvBoundary {
    /// The apply seam: `env` is the innermost closure's captured environment
    /// (the chain root's environment plus the K-1 outer argument frames), so
    /// only the call frame is missing and reads translate by `depth - 1`.
    InnerLambdaEnv,
    /// The fold seam: `env` is the unapplied operator closure's captured
    /// environment with **no** parameter frames, so all K conceptual frames
    /// are missing and reads translate by `depth - K`.
    OperatorEnv,
}

impl JitTier2EnvBoundary {
    /// Returns the number of conceptual frames missing from the boundary env.
    pub(super) const fn skew(self, arity: u32) -> u32 {
        match self {
            Self::InnerLambdaEnv => 1,
            Self::OperatorEnv => arity,
        }
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

#[cfg(feature = "candidate_c_value")]
mod compressed;
#[cfg(not(feature = "candidate_c_value"))]
mod emit;
mod fold_gen;
mod scan;

pub use fold_gen::lower_tier2_fold_genlist;
pub use scan::{scan_tier2_curried_chain, scan_tier2_pinned_callee, scan_tier2_unary_predicate};

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
    pub(crate) fn from_cached_parts(
        entry: Function,
        inner: Function,
        source: IrId,
        arity: u32,
        self_upval: Option<(u32, u32)>,
        self_call_count: u32,
    ) -> Self {
        Self {
            entry,
            inner,
            source,
            arity,
            self_upval,
            self_call_count,
        }
    }

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

/// Lowers a scanned curried chain into verified fused tier-2 CLIF.
///
/// `bindings` is the compiled module's `let`-binding side-table (`Ir::bindings`,
/// read when the body contains `let` frames), `scan` the structural scan of
/// the chain, `self_upval` the callee site
/// the engine resolved to the chain's own def-site (its chains must be full
/// arity; `None` for a non-recursive fold operator), and `pinned` the resolved
/// pinned callees for every remaining callee site. `env_boundary` fixes the
/// compile-time depth translation for environment reads to the dispatching
/// seam's boundary environment, and `depth_budget` seeds the entry's native
/// self-call budget.
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
    bindings: &[IrBinding],
    scan: &JitTier2ChainScan,
    self_upval: Option<(u32, u32)>,
    pinned: &[JitTier2PinnedCallee],
    env_boundary: JitTier2EnvBoundary,
    depth_budget: i64,
) -> Result<JitTier2ChainLowering, JitLowerError> {
    // The body emitter is per-carrier codegen: this one threads (tag, payload)
    // pairs, the compressed sibling threads one-word values.
    #[cfg(feature = "candidate_c_value")]
    return compressed::lower_tier2_curried_chain_compressed(
        arena,
        bindings,
        scan,
        self_upval,
        pinned,
        env_boundary,
        depth_budget,
    );
    #[cfg(not(feature = "candidate_c_value"))]
    lower_tier2_curried_chain_two_word(
        arena,
        bindings,
        scan,
        self_upval,
        pinned,
        env_boundary,
        depth_budget,
    )
}

/// The two-word (baseline-carrier) body of [`lower_tier2_curried_chain`].
#[cfg(not(feature = "candidate_c_value"))]
fn lower_tier2_curried_chain_two_word(
    arena: &IrArena,
    bindings: &[IrBinding],
    scan: &JitTier2ChainScan,
    self_upval: Option<(u32, u32)>,
    pinned: &[JitTier2PinnedCallee],
    env_boundary: JitTier2EnvBoundary,
    depth_budget: i64,
) -> Result<JitTier2ChainLowering, JitLowerError> {
    let entry_signature = clif_signature_for_runtime_call(runtime_lambda_argv_call_signature())?;
    let inner_signature = inner_signature_for_arity(&entry_signature, scan.arity);

    let (inner, self_call_count) = emit::build_inner_function(
        arena,
        bindings,
        scan,
        inner_signature.clone(),
        self_upval,
        pinned,
        env_boundary,
        emit::ChainInnerBody::Plain,
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
#[cfg(not(feature = "candidate_c_value"))]
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

/// Builds the boundary entry adapter with the frozen argv lambda-entry ABI.
///
/// The entry loads `arity` by-value runtime values from the caller-owned
/// `argv` run (16-byte stride, tag word first), calls `inner` with the seeded
/// depth budget, and translates the internal deopt sentinel into a valid null
/// return (the recorded trap, not the value, signals the deopt).
#[cfg(not(feature = "candidate_c_value"))]
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

// These tests exercise two-word-carrier codegen (tier-2 bodies, inline arith,
// candidate bridges, or two-word CLIF shape asserts), which declines on the
// one-word carrier; baseline-only until the S4b phase-2 one-word emitters land.
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests;
