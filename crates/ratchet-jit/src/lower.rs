//! Minimal CLIF body lowering for safe JIT precursors.
//!
//! This module starts the tier-1 lowering path without executable code. It can
//! build verified Cranelift [`Function`] values for compiled thunk bodies that
//! return constant runtime [`Value`] words, perform one bounded local
//! environment-slot read through the `aos_env_get` helper, force that loaded
//! value through `aos_force`, apply two local-slot values through `aos_apply`,
//! perform one forced static attr selection through `aos_select_ic`, fall back
//! to a scalar literal `or` default after an `aos_has_attr` probe, test one
//! forced static attr presence through `aos_has_attr`, and merge two forced
//! local-slot attrsets through `aos_update`.
//! Shape-directed tier-1 selector entrypoints choose among the arena-only
//! bounded paths before Cranelift module setup. These bodies use the same
//! two-word `Value` ABI as [`crate::abi`], but they are not placed in a
//! `JITModule`, finalized, or called.
use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{
        ExtFuncData, ExternalName, Function, InstBuilder, UserExternalName, UserFuncName, types,
    },
    settings,
    verifier::verify_function,
};
use ratchet_core::{
    BindingLowering, Cardinality, ExprFacts, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData,
    IrId, IrInlineCacheSiteId, IrKind, IrNode, Strictness, ThunkSharing,
    runtime_helper_call_signature, runtime_thunk_call_signature,
    syntax::{BinOpKind, Symbol},
};
use ratchet_value::value::Value;
use crate::{
    abi::clif_signature_for_runtime_call,
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource},
    tier::JitTier,
};
mod arith_tree;
mod alloc_cons;
mod candidate_b;
mod candidate_c;
mod error;
pub mod interp;
mod lambda_chain;
mod lambda_rec;
mod stack_maps;
mod value_words;
#[cfg(all(test, feature = "candidate_c_value"))]
mod one_word_shape_tests;
pub use stack_maps::{
    AOS_JIT_STACK_MAP_ENTER_FUNCTION_INDEX, AOS_JIT_STACK_MAP_EXIT_FUNCTION_INDEX,
    clif_external_name_for_aos_jit_stack_map_enter,
    clif_external_name_for_aos_jit_stack_map_exit,
};
pub use alloc_cons::{
    AOS_ALLOC_CONS_FUNCTION_INDEX, clif_external_name_for_aos_alloc_cons,
    lower_singleton_list_ir_thunk_body_artifact,
};
pub use candidate_b::{
    JitCandidateBConstantError, lower_candidate_b_constant_ir_thunk_body_artifact, lower_candidate_b_env_get_ir_thunk_body_artifact,
};
pub use candidate_c::{
    JitCandidateCConstantError, lower_candidate_c_constant_ir_thunk_body_artifact,
};
pub use error::JitLowerError;
pub use lambda_chain::{
    JitTier2ChainCalleeSite, JitTier2ChainLowering, JitTier2ChainScan, JitTier2EnvBoundary,
    JitTier2PinnedCallee, TIER2_MAX_CHAIN_ARITY, lower_tier2_curried_chain,
    lower_tier2_fold_genlist, scan_tier2_curried_chain, scan_tier2_pinned_callee,
    scan_tier2_unary_predicate,
};
pub use lambda_rec::{
    AOS_TIER2_LOCAL_FUNCTION_NAMESPACE, JitTier2LambdaLowering, TIER2_NATIVE_DEPTH_BUDGET,
    lower_tier2_self_recursive_lambda, tier2_self_recursive_lambda_cache_eligible,
};
/// Cranelift user-function namespace reserved for Core IR root thunks.
///
/// Cranelift treats user function names as caller-owned numeric metadata. The
/// current lowerer uses this namespace with the Core [`IrId`] as the function
/// index so non-executable CLIF artifacts have deterministic per-expression
/// names before `JITModule` integration exists.
pub const AOS_IR_ROOT_FUNCTION_NAMESPACE: u32 = 7;
/// Cranelift user-external namespace reserved for imported AOS runtime helpers.
///
/// Standalone verified CLIF functions do not have a `JITModule` string symbol
/// table yet. This namespace gives pre-module helper calls deterministic numeric
/// names that tests can inspect before real relocation and symbol registration
/// are wired in.
pub const AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE: u32 = 8;
/// User-external function index reserved for the `aos_env_get` helper.
pub const AOS_ENV_GET_FUNCTION_INDEX: u32 = 0;
/// User-external function index reserved for the `aos_force` helper.
pub const AOS_FORCE_FUNCTION_INDEX: u32 = 1;
/// User-external function index reserved for the `aos_apply` helper.
pub const AOS_APPLY_FUNCTION_INDEX: u32 = 2;
/// User-external function index reserved for the `aos_has_attr` helper.
pub const AOS_HAS_ATTR_FUNCTION_INDEX: u32 = 3;
/// User-external function index reserved for the `aos_select_ic` helper.
pub const AOS_SELECT_IC_FUNCTION_INDEX: u32 = 4;
/// User-external function index reserved for the `aos_update` helper.
pub const AOS_UPDATE_FUNCTION_INDEX: u32 = 5;
/// User-external function index reserved for the `aos_deopt` helper.
pub const AOS_DEOPT_FUNCTION_INDEX: u32 = 6;

/// User-external function index reserved for the `aos_upval_get` helper.
pub const AOS_UPVAL_GET_FUNCTION_INDEX: u32 = 7;
/// User-external function index reserved for the `aos_primop_call` helper.
pub const AOS_PRIMOP_CALL_FUNCTION_INDEX: u32 = 8;

/// User-external function index reserved for the `aos_string_length` helper.
pub const AOS_STRING_LENGTH_FUNCTION_INDEX: u32 = 9;

const AOS_ENV_GET_SYMBOL: &str = "aos_env_get";
const AOS_FORCE_SYMBOL: &str = "aos_force";
const AOS_APPLY_SYMBOL: &str = "aos_apply";
const AOS_HAS_ATTR_SYMBOL: &str = "aos_has_attr";
const AOS_SELECT_IC_SYMBOL: &str = "aos_select_ic";
const AOS_UPDATE_SYMBOL: &str = "aos_update";
const AOS_DEOPT_SYMBOL: &str = "aos_deopt";
const AOS_UPVAL_GET_SYMBOL: &str = "aos_upval_get";
const AOS_PRIMOP_CALL_SYMBOL: &str = "aos_primop_call";
const AOS_STRING_LENGTH_SYMBOL: &str = "aos_string_length";

/// Returns the deterministic CLIF user-function name for a Core IR root.
pub fn clif_name_for_ir_root(root: IrId) -> UserFuncName {
    UserFuncName::user(AOS_IR_ROOT_FUNCTION_NAMESPACE, root.as_u32())
}

/// Returns the deterministic CLIF external-function name for `aos_env_get`.
pub fn clif_external_name_for_aos_env_get() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_ENV_GET_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external-function name for `aos_force`.
pub fn clif_external_name_for_aos_force() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_FORCE_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external-function name for `aos_apply`.
pub fn clif_external_name_for_aos_apply() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_APPLY_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external-function name for `aos_has_attr`.
pub fn clif_external_name_for_aos_has_attr() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_HAS_ATTR_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external-function name for `aos_select_ic`.
pub fn clif_external_name_for_aos_select_ic() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_SELECT_IC_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external-function name for `aos_update`.
pub fn clif_external_name_for_aos_update() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_UPDATE_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external-function name for `aos_deopt`.
pub fn clif_external_name_for_aos_deopt() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_DEOPT_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external-function name for `aos_primop_call`.
pub fn clif_external_name_for_aos_primop_call() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_PRIMOP_CALL_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external-function name for `aos_string_length`.
pub fn clif_external_name_for_aos_string_length() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_STRING_LENGTH_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external-function name for `aos_upval_get`.
pub fn clif_external_name_for_aos_upval_get() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_UPVAL_GET_FUNCTION_INDEX,
    )
}

/// The fact-licensed tier-1 lowering decision for one thunk allocation.
///
/// This is an address-free policy result only. It records how the current
/// strictness/cardinality/escape facts would steer a future tier-1 thunk
/// lowerer before that lowerer emits CLIF storage, helper calls, or native
/// entrypoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JitTier1ThunkFactDecision {
    /// Allocates ordinary thunk update and blackhole state.
    AllocateUpdatingThunk,
    /// Allocates a single-entry thunk representation for a frame-local thunk.
    AllocateSingleEntryThunk,
    /// Omits lazy thunk storage for a proven-absent binding.
    OmitLazyBinding,
    /// Evaluates the thunk body to WHNF without allocating thunk storage.
    EvaluateEagerWhnf,
    /// Evaluates eagerly and keeps the result eligible for non-heap scalar storage.
    EvaluateScalarValue,
}

/// Returns the tier-1 thunk decision licensed by one expression fact record.
///
/// An absent-plus-strict fact record is contradictory, so the decision keeps
/// ordinary updating thunk storage. Otherwise, strict binding-lowering facts
/// take precedence because they avoid lazy thunk allocation entirely. Sharing
/// facts only choose among lazy thunk storage shapes when the binding still
/// lowers as a thunk.
pub const fn jit_tier1_thunk_fact_decision_for_facts(
    facts: ExprFacts,
) -> JitTier1ThunkFactDecision {
    match (facts.cardinality, facts.strictness) {
        (Cardinality::Absent, Strictness::Demanded | Strictness::DemandedBeforeEffect) => {
            return JitTier1ThunkFactDecision::AllocateUpdatingThunk;
        }
        (_, _) => {}
    }

    match facts.binding_lowering() {
        BindingLowering::Eager => JitTier1ThunkFactDecision::EvaluateEagerWhnf,
        BindingLowering::Scalar => JitTier1ThunkFactDecision::EvaluateScalarValue,
        BindingLowering::Thunk => match facts.thunk_sharing() {
            ThunkSharing::Update => JitTier1ThunkFactDecision::AllocateUpdatingThunk,
            ThunkSharing::SingleEntry => JitTier1ThunkFactDecision::AllocateSingleEntryThunk,
            ThunkSharing::Omit => JitTier1ThunkFactDecision::OmitLazyBinding,
        },
    }
}

/// Address-free fact plan for a future tier-1 thunk-allocation lowerer.
///
/// The plan mirrors the current Core fact policy at a JIT crate boundary:
/// [`BindingLowering`] captures whether the thunk remains lazy, eager, or
/// scalar-eligible, [`ThunkSharing`] captures the lazy storage machinery, and
/// [`JitTier1ThunkFactDecision`] collapses those facts into the decision a
/// future CLIF lowerer can consume.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JitTier1ThunkFactPlan {
    thunk: IrId,
    body: IrId,
    facts: ExprFacts,
    binding_lowering: BindingLowering,
    thunk_sharing: ThunkSharing,
    decision: JitTier1ThunkFactDecision,
}

impl JitTier1ThunkFactPlan {
    const fn new(thunk: IrId, body: IrId, facts: ExprFacts) -> Self {
        Self {
            thunk,
            body,
            facts,
            binding_lowering: facts.binding_lowering(),
            thunk_sharing: facts.thunk_sharing(),
            decision: jit_tier1_thunk_fact_decision_for_facts(facts),
        }
    }

    /// Returns the thunk-allocation node this plan describes.
    pub const fn thunk(self) -> IrId {
        self.thunk
    }

    /// Returns the body node referenced by the thunk allocation.
    pub const fn body(self) -> IrId {
        self.body
    }

    /// Returns the expression facts consumed by the plan.
    pub const fn facts(self) -> ExprFacts {
        self.facts
    }

    /// Returns the binding-lowering policy derived from the facts.
    pub const fn binding_lowering(self) -> BindingLowering {
        self.binding_lowering
    }

    /// Returns the lazy thunk-sharing policy derived from the facts.
    pub const fn thunk_sharing(self) -> ThunkSharing {
        self.thunk_sharing
    }

    /// Returns the collapsed tier-1 thunk decision derived from the facts.
    pub const fn decision(self) -> JitTier1ThunkFactDecision {
        self.decision
    }
}

/// Builds the address-free JIT fact plan for one thunk-allocation node.
///
/// This validates that `thunk` identifies a direct [`IrKind::ThunkAlloc`] node
/// with an existing, non-self body and an attached fact record. It does not
/// generate CLIF, register runtime helpers, allocate storage, or call native
/// code.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `thunk` is not present in the
/// arena, [`JitLowerError::UnsupportedThunkFactNode`] when it is not a thunk
/// allocation, [`JitLowerError::MismatchedIrNodeData`] when the thunk payload is
/// malformed, [`JitLowerError::MissingIrBody`] when the referenced body is not
/// present, [`JitLowerError::SelfReferentialThunkBody`] when the thunk points at
/// itself, or [`JitLowerError::MismatchedIrFactTable`] when the fact table does
/// not have exactly one record per arena node.
pub fn jit_tier1_thunk_fact_plan(
    ir: &Ir,
    thunk: IrId,
) -> Result<JitTier1ThunkFactPlan, JitLowerError> {
    let node_count = ir.arena.nodes().len();
    let fact_count = ir.facts.len();
    if fact_count != node_count {
        return Err(JitLowerError::MismatchedIrFactTable {
            node_count,
            fact_count,
        });
    }

    let node = ir
        .arena
        .node(thunk)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root: thunk })?;
    let body = match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => body,
        (IrKind::ThunkAlloc, data) => {
            return Err(JitLowerError::MismatchedIrNodeData {
                kind: IrKind::ThunkAlloc,
                data,
                expected: "body node",
            });
        }
        (kind, _) => return Err(JitLowerError::UnsupportedThunkFactNode { id: thunk, kind }),
    };

    ir.arena
        .node(body)
        .ok_or(JitLowerError::MissingIrBody { body })?;
    if body == thunk {
        return Err(JitLowerError::SelfReferentialThunkBody { thunk });
    }

    let facts = ir
        .node_facts(thunk)
        .ok_or(JitLowerError::MismatchedIrFactTable {
            node_count,
            fact_count,
        })?;
    Ok(JitTier1ThunkFactPlan::new(thunk, body, facts))
}

/// Lowers a constant runtime value into a verified compiled-thunk CLIF body.
///
/// The returned function has the frozen compiled-thunk runtime signature:
/// `rt`, `env`, and a two-word runtime `Value` return. The current body ignores
/// the runtime and environment parameters and emits two `iconst.i64`
/// instructions for the value tag and payload words. This smoke-test entrypoint
/// uses Cranelift's default user-function name because it is not tied to a Core
/// IR root.
///
/// # Errors
///
/// Returns [`JitLowerError::UnsupportedHeapConstant`] for a heap-backed value,
/// [`JitLowerError::Abi`] for an invalid runtime signature, or
/// [`JitLowerError::Verifier`] when Cranelift rejects the generated function.
pub fn lower_constant_thunk_body(value: Value) -> Result<Function, JitLowerError> {
    lower_constant_thunk_body_with_name(value, UserFuncName::default())
}

/// Lowers a constant runtime value into a non-executable CLIF artifact.
///
/// The artifact records tier-1 thunk-body metadata around the same verified
/// CLIF function returned by [`lower_constant_thunk_body`].
///
/// # Errors
///
/// Returns [`JitLowerError::UnsupportedHeapConstant`] for a heap-backed value,
/// [`JitLowerError::Abi`] for an invalid runtime signature, or
/// [`JitLowerError::Verifier`] when Cranelift rejects the generated function.
pub fn lower_constant_thunk_body_artifact(value: Value) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_constant_thunk_body(value)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::ConstantSmoke,
        function,
    ))
}

fn lower_constant_thunk_body_with_name(
    value: Value,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    error::validate_embedded_constant(value)?;
    let constant_words = value_words::embedded_constant_words(value)?;
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let entry_block = append_entry_block_params(&mut function);
    emit_value_return(&mut function, entry_block, constant_words);
    verify_clif_function(&function)?;
    Ok(function)
}

/// Lowers a literal IR root into a verified compiled-thunk CLIF body.
///
/// This is the first Core-IR entrypoint for the tier-1 lowerer. It accepts
/// literal `Int`, `Float`, `Bool`, and `Null` roots plus one direct
/// [`IrKind::ThunkAlloc`] wrapper around those literal roots, then reuses
/// the constant thunk body path to build the single-block CLIF body. The
/// returned function name is deterministic: [`AOS_IR_ROOT_FUNCTION_NAMESPACE`]
/// plus the raw Core [`IrId`] root as the Cranelift user-function index.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `root` is not present in
/// `arena`. Returns [`JitLowerError::UnsupportedIrRoot`] when `root` is not one
/// of the supported constant forms. Returns
/// [`JitLowerError::MismatchedConstantData`] when a literal node carries a
/// payload variant that does not match its kind. Returns
/// [`JitLowerError::MissingIrBody`], [`JitLowerError::UnsupportedIrBody`], or
/// [`JitLowerError::MismatchedBodyConstantData`] for malformed direct thunk
/// bodies. Returns
/// [`JitLowerError::MismatchedIrNodeData`] when a supported wrapper node carries
/// the wrong payload shape. Also returns the errors from [`lower_constant_thunk_body`].
pub fn lower_constant_ir_thunk_body(
    arena: &IrArena,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let value = constant_value_for_root(arena, root)?;
    lower_constant_thunk_body_with_name(value, clif_name_for_ir_root(root))
}

/// Lowers a literal IR root into a non-executable CLIF artifact.
///
/// The artifact records the Core IR root id as source metadata and contains the
/// same verified CLIF function returned by [`lower_constant_ir_thunk_body`].
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `root` is not present in
/// `arena`. Returns [`JitLowerError::UnsupportedIrRoot`] when `root` is not one
/// of the supported constant forms. Returns
/// [`JitLowerError::MismatchedConstantData`] when a literal node carries a
/// payload variant that does not match its kind. Returns
/// [`JitLowerError::MissingIrBody`], [`JitLowerError::UnsupportedIrBody`], or
/// [`JitLowerError::MismatchedBodyConstantData`] for malformed direct thunk
/// bodies. Returns
/// [`JitLowerError::MismatchedIrNodeData`] when a supported wrapper node carries
/// the wrong payload shape. Also returns the errors from [`lower_constant_thunk_body`].
pub fn lower_constant_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_constant_ir_thunk_body(arena, root)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers the root of a lowered IR artifact into a compiled-thunk CLIF body.
///
/// This is the normal Core-IR entrypoint for the current literal-only lowerer.
/// It delegates to [`lower_constant_ir_thunk_body`] using the artifact's root id
/// and arena, so callers do not have to split the root out manually.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `ir.root` is not present in
/// `ir.arena`. Returns [`JitLowerError::UnsupportedIrRoot`] when the root is not
/// one of the supported constant forms. Returns
/// [`JitLowerError::MismatchedConstantData`] when a literal node carries a
/// payload variant that does not match its kind. Returns
/// [`JitLowerError::MissingIrBody`], [`JitLowerError::UnsupportedIrBody`], or
/// [`JitLowerError::MismatchedBodyConstantData`] for malformed direct thunk
/// bodies. Returns
/// [`JitLowerError::MismatchedIrNodeData`] when a supported wrapper node carries
/// the wrong payload shape. Also returns the errors from [`lower_constant_thunk_body`].
pub fn lower_constant_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_constant_ir_thunk_body(&ir.arena, ir.root)
}

/// Lowers the root of a lowered IR artifact into a non-executable CLIF artifact.
///
/// The artifact records `ir.root` as source metadata and contains the same
/// verified CLIF function returned by [`lower_constant_ir_root_thunk_body`].
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `ir.root` is not present in
/// `ir.arena`. Returns [`JitLowerError::UnsupportedIrRoot`] when the root is not
/// one of the supported constant forms. Returns
/// [`JitLowerError::MismatchedConstantData`] when a literal node carries a
/// payload variant that does not match its kind. Returns
/// [`JitLowerError::MissingIrBody`], [`JitLowerError::UnsupportedIrBody`], or
/// [`JitLowerError::MismatchedBodyConstantData`] for malformed direct thunk
/// bodies. Returns
/// [`JitLowerError::MismatchedIrNodeData`] when a supported wrapper node carries
/// the wrong payload shape. Also returns the errors from [`lower_constant_thunk_body`].
pub fn lower_constant_ir_root_thunk_body_artifact(
    ir: &Ir,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_constant_ir_thunk_body_artifact(&ir.arena, ir.root)
}

/// Lowers a local-slot IR root into a verified compiled-thunk CLIF body.
///
/// This bounded environment-access precursor accepts a direct
/// [`IrKind::LocalVar`] root plus one direct [`IrKind::ThunkAlloc`] wrapper
/// around a local variable. The generated function imports `aos_env_get` through
/// deterministic user-external CLIF metadata, passes the compiled thunk `env`
/// parameter and the local slot as `i32`, and returns the two runtime `Value`
/// words produced by that helper call.
///
/// The returned function remains non-executable CLIF only. It is not placed in a
/// `JITModule`, linked against a native helper address, finalized, or called.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `root` is not present in
/// `arena`. Returns [`JitLowerError::UnsupportedEnvRoot`] when the root is not a
/// supported local-slot access form. Returns
/// [`JitLowerError::MissingIrBody`] or [`JitLowerError::UnsupportedEnvBody`] for
/// malformed direct thunk bodies. Returns [`JitLowerError::MismatchedIrNodeData`]
/// when a supported root or wrapper carries the wrong payload shape. Also
/// returns runtime ABI signature-conversion and verifier errors.
pub fn lower_env_get_ir_thunk_body(arena: &IrArena, root: IrId) -> Result<Function, JitLowerError> {
    let slot = env_slot_for_root(arena, root)?;
    lower_env_get_slot_thunk_body_with_name(slot, clif_name_for_ir_root(root))
}

/// Lowers a local-slot IR root into a non-executable CLIF artifact.
///
/// The artifact records the Core IR root id as source metadata and contains the
/// same verified CLIF function returned by [`lower_env_get_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_env_get_ir_thunk_body`].
pub fn lower_env_get_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_env_get_ir_thunk_body(arena, root)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers the root of a lowered IR artifact as a local-slot access.
///
/// This delegates to [`lower_env_get_ir_thunk_body`] using the artifact's root id
/// and arena.
///
/// # Errors
///
/// Returns the same errors as [`lower_env_get_ir_thunk_body`].
pub fn lower_env_get_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_env_get_ir_thunk_body(&ir.arena, ir.root)
}

/// Lowers the root of a lowered IR artifact as a local-slot CLIF artifact.
///
/// # Errors
///
/// Returns the same errors as [`lower_env_get_ir_root_thunk_body`].
pub fn lower_env_get_ir_root_thunk_body_artifact(
    ir: &Ir,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_env_get_ir_thunk_body_artifact(&ir.arena, ir.root)
}

/// Lowers a local-slot IR root and forces the loaded value in CLIF.
///
/// This bounded force-call precursor accepts the same direct [`IrKind::LocalVar`]
/// root plus one direct [`IrKind::ThunkAlloc`] wrapper as
/// [`lower_env_get_ir_thunk_body`]. The generated function imports
/// `aos_env_get`, imports `aos_force`, reads the local slot, passes the loaded
/// two-word `Value` with the compiled thunk `rt` parameter to `aos_force`, and
/// returns the forced two-word `Value`.
///
/// The returned function remains non-executable CLIF only. It is not placed in a
/// `JITModule`, linked against native helper addresses, finalized, or called.
///
/// # Errors
///
/// Returns the same IR-shape errors as [`lower_env_get_ir_thunk_body`]. Also
/// returns runtime ABI signature-conversion and verifier errors for either
/// imported helper.
pub fn lower_forced_env_get_ir_thunk_body(
    arena: &IrArena,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let slot = env_slot_for_root(arena, root)?;
    lower_forced_env_get_slot_thunk_body_with_name(slot, clif_name_for_ir_root(root))
}

/// Lowers a forced local-slot IR root into a non-executable CLIF artifact.
///
/// The artifact records the Core IR root id as source metadata and contains the
/// same verified CLIF function returned by [`lower_forced_env_get_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_forced_env_get_ir_thunk_body`].
pub fn lower_forced_env_get_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_forced_env_get_ir_thunk_body(arena, root)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers the root of a lowered IR artifact as a forced local-slot access.
///
/// This delegates to [`lower_forced_env_get_ir_thunk_body`] using the artifact's
/// root id and arena.
///
/// # Errors
///
/// Returns the same errors as [`lower_forced_env_get_ir_thunk_body`].
pub fn lower_forced_env_get_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_forced_env_get_ir_thunk_body(&ir.arena, ir.root)
}

/// Lowers the root of a lowered IR artifact as a forced local-slot CLIF artifact.
///
/// # Errors
///
/// Returns the same errors as [`lower_forced_env_get_ir_root_thunk_body`].
pub fn lower_forced_env_get_ir_root_thunk_body_artifact(
    ir: &Ir,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_forced_env_get_ir_thunk_body_artifact(&ir.arena, ir.root)
}

/// Lowers an upvalue-slot IR root into a verified compiled-thunk CLIF body.
///
/// This bounded environment-access precursor accepts a direct
/// [`IrKind::UpvalVar`] root plus one direct [`IrKind::ThunkAlloc`] wrapper around
/// an upvalue read. The generated function imports `aos_upval_get` through
/// deterministic user-external CLIF metadata, passes the compiled thunk `env`
/// parameter with the upvalue `depth` and `slot` as `i32`, and returns the two
/// runtime `Value` words produced by that helper call.
///
/// The returned function remains non-executable CLIF only. It is not placed in a
/// `JITModule`, linked against a native helper address, finalized, or called.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `root` is not present in
/// `arena`. Returns [`JitLowerError::UnsupportedEnvRoot`] when the root is not a
/// supported upvalue-access form. Returns [`JitLowerError::MissingIrBody`] or
/// [`JitLowerError::UnsupportedEnvBody`] for malformed direct thunk bodies.
/// Returns [`JitLowerError::MismatchedIrNodeData`] when a supported root or
/// wrapper carries the wrong payload shape. Also returns runtime ABI
/// signature-conversion and verifier errors.
pub fn lower_upval_get_ir_thunk_body(
    arena: &IrArena,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let (depth, slot) = upval_depth_slot_for_root(arena, root)?;
    lower_upval_get_slot_thunk_body_with_name(depth, slot, clif_name_for_ir_root(root))
}

/// Lowers an upvalue-slot IR root into a non-executable CLIF artifact.
///
/// The artifact records the Core IR root id as source metadata and contains the
/// same verified CLIF function returned by [`lower_upval_get_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_upval_get_ir_thunk_body`].
pub fn lower_upval_get_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_upval_get_ir_thunk_body(arena, root)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers the root of a lowered IR artifact as an upvalue-slot access.
///
/// # Errors
///
/// Returns the same errors as [`lower_upval_get_ir_thunk_body`].
pub fn lower_upval_get_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_upval_get_ir_thunk_body(&ir.arena, ir.root)
}

/// Lowers the root of a lowered IR artifact as an upvalue-slot CLIF artifact.
///
/// # Errors
///
/// Returns the same errors as [`lower_upval_get_ir_root_thunk_body`].
pub fn lower_upval_get_ir_root_thunk_body_artifact(
    ir: &Ir,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_upval_get_ir_thunk_body_artifact(&ir.arena, ir.root)
}

/// Lowers an upvalue-slot IR root and forces the loaded value in CLIF.
///
/// This bounded force-call precursor accepts the same direct [`IrKind::UpvalVar`]
/// root plus one direct [`IrKind::ThunkAlloc`] wrapper as
/// [`lower_upval_get_ir_thunk_body`]. The generated function imports
/// `aos_upval_get`, imports `aos_force`, reads the upvalue slot, passes the
/// loaded two-word `Value` with the compiled thunk `rt` parameter to `aos_force`,
/// and returns the forced two-word `Value`.
///
/// The returned function remains non-executable CLIF only. It is not placed in a
/// `JITModule`, linked against native helper addresses, finalized, or called.
///
/// # Errors
///
/// Returns the same IR-shape errors as [`lower_upval_get_ir_thunk_body`]. Also
/// returns runtime ABI signature-conversion and verifier errors for either
/// imported helper.
pub fn lower_forced_upval_get_ir_thunk_body(
    arena: &IrArena,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let (depth, slot) = upval_depth_slot_for_root(arena, root)?;
    lower_forced_upval_get_slot_thunk_body_with_name(depth, slot, clif_name_for_ir_root(root))
}

/// Lowers a forced upvalue-slot IR root into a non-executable CLIF artifact.
///
/// # Errors
///
/// Returns the same errors as [`lower_forced_upval_get_ir_thunk_body`].
pub fn lower_forced_upval_get_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_forced_upval_get_ir_thunk_body(arena, root)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers the root of a lowered IR artifact as a forced upvalue-slot access.
///
/// # Errors
///
/// Returns the same errors as [`lower_forced_upval_get_ir_thunk_body`].
pub fn lower_forced_upval_get_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_forced_upval_get_ir_thunk_body(&ir.arena, ir.root)
}

/// Lowers the root of a lowered IR artifact as a forced upvalue-slot CLIF artifact.
///
/// # Errors
///
/// Returns the same errors as [`lower_forced_upval_get_ir_root_thunk_body`].
pub fn lower_forced_upval_get_ir_root_thunk_body_artifact(
    ir: &Ir,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_forced_upval_get_ir_thunk_body_artifact(&ir.arena, ir.root)
}

/// Lowers a force-aware tier-1 thunk body, dispatching primop bodies natively.
///
/// This is the module-aware entry the tier-1 engine uses when it knows the
/// def-site body's owning `module_id`. When `root` resolves (through at most one
/// [`IrKind::ThunkAlloc`] wrapper) to an [`IrKind::PrimOp`] body it lowers the
/// delegating `aos_primop_call` trampoline with the primop node's `module_id`
/// and node id baked in as `i32` operands; otherwise it defers to the
/// module-agnostic [`lower_force_aware_tier1_ir_thunk_body_artifact_for_ir`].
///
/// The compiled trampoline never re-implements a builtin: it re-enters the tree
/// walk, which keeps every impure observation on the same trace an ordinary
/// force would record.
///
/// # Errors
///
/// Returns the same errors as [`lower_primop_call_ir_thunk_body_artifact`] for a
/// primop body, and the same errors as
/// [`lower_force_aware_tier1_ir_thunk_body_artifact_for_ir`] otherwise.
pub fn lower_force_aware_tier1_ir_thunk_body_artifact_for_ir_in_module(
    ir: &Ir,
    root: IrId,
    module_id: u32,
) -> Result<JitClifArtifact, JitLowerError> {
    match primop_node_id_for_root(&ir.arena, root) {
        Some(primop_node) => lower_primop_call_ir_thunk_body_artifact(root, module_id, primop_node),
        None => lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(ir, root),
    }
}

/// Lowers a primop thunk body into a verified `aos_primop_call` CLIF body.
///
/// The generated function has the frozen compiled-thunk runtime signature. It
/// imports `aos_primop_call`, passes the compiled thunk `rt` and `env`
/// parameters plus the primop `module_id` and `node_id` as `i32` operands, and
/// returns the two runtime `Value` words produced by that trampoline. `root`
/// names the CLIF function after the def-site body; `node_id` is the primop node
/// the trampoline re-enters the tree walk to force.
///
/// The returned function remains non-executable CLIF only. It is not placed in a
/// `JITModule`, linked against a native helper address, finalized, or called.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingEntryBlockParameter`] when the entry block
/// lacks the runtime or environment parameter, and
/// [`JitLowerError::InvalidRuntimeCallResultArity`] if the trampoline call does
/// not yield the two-word runtime `Value`. Also returns runtime ABI
/// signature-conversion and verifier errors.
pub fn lower_primop_call_ir_thunk_body(
    root: IrId,
    module_id: u32,
    node_id: IrId,
) -> Result<Function, JitLowerError> {
    lower_primop_call_thunk_body_with_name(module_id, node_id, clif_name_for_ir_root(root))
}

/// Lowers a primop thunk body into a non-executable `aos_primop_call` artifact.
///
/// The artifact records the def-site Core IR `root` id as source metadata and
/// contains the same verified CLIF function returned by
/// [`lower_primop_call_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_primop_call_ir_thunk_body`].
pub fn lower_primop_call_ir_thunk_body_artifact(
    root: IrId,
    module_id: u32,
    node_id: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_primop_call_ir_thunk_body(root, module_id, node_id)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers a `builtins.stringLength` primop body into a native inline CLIF artifact.
///
/// This is the tier-1 inline for `stringLength`: the caller (the engine) has
/// already resolved the primop node's builtin to `stringLength` against the
/// evaluator symbol table, so this lowering only extracts the single argument
/// slot operand and emits native code that loads it, forces it through
/// `aos_force`, and returns its byte length as an integer [`Value`] through the
/// leaf `aos_string_length` helper. When the forced argument is not a string the
/// helper traps and the dispatcher deoptimizes to the tree walk, which reproduces
/// the coercing `stringLength` semantics exactly.
///
/// Only a single [`IrKind::LocalVar`] or [`IrKind::UpvalVar`] argument is
/// supported; any other argument shape yields an error so the engine leaves the
/// def-site delegated.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`], [`JitLowerError::MissingIrBody`],
/// [`JitLowerError::MismatchedIrNodeData`], [`JitLowerError::UnsupportedApplyRoot`],
/// or [`JitLowerError::UnsupportedApplyChild`] when `root` is not a single-slot
/// `stringLength` primop body, plus runtime ABI signature-conversion and verifier
/// errors for the imported helpers.
pub fn lower_string_length_inline_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let operand = string_length_operand_for_root(arena, root)?;
    let function =
        lower_string_length_inline_thunk_body_with_name(operand, clif_name_for_ir_root(root))?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Returns the single slot-operand argument of a `stringLength` primop `root`.
///
/// Unwraps at most one [`IrKind::ThunkAlloc`] wrapper, requires an
/// [`IrKind::PrimOp`] body with exactly one argument, and requires that argument
/// to be a [`IrKind::LocalVar`] or [`IrKind::UpvalVar`] read.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`], [`JitLowerError::MissingIrBody`],
/// [`JitLowerError::MismatchedIrNodeData`], [`JitLowerError::UnsupportedApplyRoot`],
/// or [`JitLowerError::UnsupportedApplyChild`] when the body is not a single-slot
/// primop.
fn string_length_operand_for_root(
    arena: &IrArena,
    root: IrId,
) -> Result<Tier1SlotOperand, JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;
    let primop = match (node.kind, node.data) {
        (IrKind::PrimOp, _) => node,
        (IrKind::ThunkAlloc, IrData::Node(body)) => arena
            .node(body)
            .copied()
            .ok_or(JitLowerError::MissingIrBody { body })?,
        (kind, _) => return Err(JitLowerError::UnsupportedApplyRoot { kind }),
    };
    let args = match (primop.kind, primop.data) {
        (IrKind::PrimOp, IrData::PrimOp { args, .. }) => args,
        (kind, _) => return Err(JitLowerError::UnsupportedApplyRoot { kind }),
    };
    if args.len() != 1 {
        return Err(JitLowerError::UnsupportedApplyRoot {
            kind: IrKind::PrimOp,
        });
    }
    let arg_id = arena
        .child_slice(args)
        .and_then(|children| children.first().copied())
        .ok_or(JitLowerError::UnsupportedApplyRoot {
            kind: IrKind::PrimOp,
        })?;
    let arg_node = arena
        .node(arg_id)
        .copied()
        .ok_or(JitLowerError::MissingApplyChild { child: arg_id })?;
    slot_operand_for_operand_node(arg_node).ok_or(JitLowerError::UnsupportedApplyChild {
        child: arg_id,
        kind: arg_node.kind,
    })
}

/// Lowers a direct local-slot application into a verified compiled-thunk CLIF body.
///
/// This bounded call-control precursor accepts a direct [`IrKind::Apply`] root
/// plus one direct [`IrKind::ThunkAlloc`] wrapper around such an apply. The
/// application's function and argument children must both be direct
/// [`IrKind::LocalVar`] reads. The generated function imports `aos_env_get`,
/// imports `aos_apply`, loads the function and argument values from the compiled
/// thunk `env` parameter, calls `aos_apply` with the compiled thunk `rt`
/// parameter, and returns the two runtime `Value` words produced by that helper.
///
/// The returned function remains non-executable CLIF only. It is not placed in a
/// `JITModule`, linked against native helper addresses, finalized, or called.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `root` is not present in
/// `arena`. Returns [`JitLowerError::UnsupportedApplyRoot`] when the root is not
/// a supported local-slot application form. Returns
/// [`JitLowerError::MissingIrBody`] or [`JitLowerError::UnsupportedApplyBody`]
/// for malformed direct thunk bodies. Returns
/// [`JitLowerError::MissingApplyChild`],
/// [`JitLowerError::UnsupportedApplyChild`], or
/// [`JitLowerError::MismatchedIrNodeData`] when the apply payload or either
/// direct child is malformed. Also returns runtime ABI signature-conversion and
/// verifier errors for imported helpers.
pub fn lower_apply_local_slots_ir_thunk_body(
    arena: &IrArena,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let (function_operand, argument_operand) = apply_local_slots_for_root(arena, root)?;
    lower_apply_local_slots_thunk_body_with_name(
        function_operand,
        argument_operand,
        clif_name_for_ir_root(root),
    )
}

/// Lowers a direct local-slot application into a non-executable CLIF artifact.
///
/// The artifact records the Core IR root id as source metadata and contains the
/// same verified CLIF function returned by [`lower_apply_local_slots_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_apply_local_slots_ir_thunk_body`].
pub fn lower_apply_local_slots_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_apply_local_slots_ir_thunk_body(arena, root)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers the root of a lowered IR artifact as a direct local-slot application.
///
/// This delegates to [`lower_apply_local_slots_ir_thunk_body`] using the
/// artifact's root id and arena.
///
/// # Errors
///
/// Returns the same errors as [`lower_apply_local_slots_ir_thunk_body`].
pub fn lower_apply_local_slots_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_apply_local_slots_ir_thunk_body(&ir.arena, ir.root)
}

/// Lowers the root of a lowered IR artifact as a direct local-slot application artifact.
///
/// # Errors
///
/// Returns the same errors as [`lower_apply_local_slots_ir_root_thunk_body`].
pub fn lower_apply_local_slots_ir_root_thunk_body_artifact(
    ir: &Ir,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_apply_local_slots_ir_thunk_body_artifact(&ir.arena, ir.root)
}

/// Lowers a direct static attr selection into a verified thunk CLIF body.
///
/// This bounded attr-access precursor accepts a direct [`IrKind::Select`] root
/// plus one direct [`IrKind::ThunkAlloc`] wrapper around such a selection. The
/// receiver must be a direct [`IrKind::LocalVar`] read and the attr path must
/// contain exactly one static segment. `or` defaults are supported only when
/// the default expression is in the current scalar literal/default-thunk subset:
/// `Int`, `Float`, `Bool`, and `Null`. The no-default path imports
/// `aos_env_get`, `aos_force`, and `aos_select_ic`; the default path also
/// imports `aos_has_attr`, probes the forced receiver, selects when present,
/// and otherwise returns the scalar default `Value` words.
///
/// The returned function remains non-executable CLIF only. It is not placed in a
/// `JITModule`, linked against native helper addresses, finalized, or called.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `root` is not present in
/// `ir.arena`. Returns [`JitLowerError::MissingIrBody`] for missing direct
/// thunk bodies. Returns attr-specific unsupported-shape errors when the root,
/// body, receiver, path, or default is outside the current bounded subset. Also
/// returns runtime ABI signature-conversion and verifier errors for imported
/// helpers.
pub fn lower_select_local_slot_ir_thunk_body(
    ir: &Ir,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let lookup = attr_lookup_for_root(ir, root, AttrLookupLowering::SelectIc)?;
    lower_attr_lookup_local_slot_thunk_body_with_name(
        lookup,
        AttrLookupLowering::SelectIc,
        clif_name_for_ir_root(root),
    )
}

/// Lowers a direct static attr selection into a non-executable CLIF artifact.
///
/// The artifact records the Core IR root id as source metadata and contains the
/// same verified CLIF function returned by [`lower_select_local_slot_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_select_local_slot_ir_thunk_body`].
pub fn lower_select_local_slot_ir_thunk_body_artifact(
    ir: &Ir,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_select_local_slot_ir_thunk_body(ir, root)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers the root of a lowered IR artifact as a static attr selection.
///
/// # Errors
///
/// Returns the same errors as [`lower_select_local_slot_ir_thunk_body`].
pub fn lower_select_local_slot_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_select_local_slot_ir_thunk_body(ir, ir.root)
}

/// Lowers the root static attr selection into a non-executable CLIF artifact.
///
/// # Errors
///
/// Returns the same errors as [`lower_select_local_slot_ir_root_thunk_body`].
pub fn lower_select_local_slot_ir_root_thunk_body_artifact(
    ir: &Ir,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_select_local_slot_ir_thunk_body_artifact(ir, ir.root)
}

/// Lowers a direct static attr presence test into a verified thunk CLIF body.
///
/// This bounded attr-access precursor accepts a direct [`IrKind::HasAttr`] root
/// plus one direct [`IrKind::ThunkAlloc`] wrapper around such a test. The
/// receiver must be a direct [`IrKind::LocalVar`] read and the attr path must
/// contain exactly one static segment. The generated function imports
/// `aos_env_get`, `aos_force`, and `aos_has_attr`, loads the receiver from the
/// compiled thunk `env` parameter, forces it to WHNF, passes the static symbol
/// id and inline-cache site id as `i32` immediates, and returns the helper's two
/// runtime `Value` words. The helper owns the single-key `?` behavior for
/// non-attr receivers by returning false.
///
/// The returned function remains non-executable CLIF only. It is not placed in a
/// `JITModule`, linked against native helper addresses, finalized, or called.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `root` is not present in
/// `ir.arena`. Returns [`JitLowerError::MissingIrBody`] for missing direct
/// thunk bodies. Returns attr-specific unsupported-shape errors when the root,
/// body, receiver, or path is outside the current bounded subset. Also returns
/// runtime ABI signature-conversion and verifier errors for imported helpers.
pub fn lower_has_attr_local_slot_ir_thunk_body(
    ir: &Ir,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let lookup = attr_lookup_for_root(ir, root, AttrLookupLowering::HasAttr)?;
    lower_attr_lookup_local_slot_thunk_body_with_name(
        lookup,
        AttrLookupLowering::HasAttr,
        clif_name_for_ir_root(root),
    )
}

/// Lowers a direct static attr presence test into a non-executable CLIF artifact.
///
/// The artifact records the Core IR root id as source metadata and contains the
/// same verified CLIF function returned by [`lower_has_attr_local_slot_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_has_attr_local_slot_ir_thunk_body`].
pub fn lower_has_attr_local_slot_ir_thunk_body_artifact(
    ir: &Ir,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_has_attr_local_slot_ir_thunk_body(ir, root)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers the root of a lowered IR artifact as a static attr presence test.
///
/// # Errors
///
/// Returns the same errors as [`lower_has_attr_local_slot_ir_thunk_body`].
pub fn lower_has_attr_local_slot_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_has_attr_local_slot_ir_thunk_body(ir, ir.root)
}

/// Lowers the root static attr presence test into a non-executable CLIF artifact.
///
/// # Errors
///
/// Returns the same errors as [`lower_has_attr_local_slot_ir_root_thunk_body`].
pub fn lower_has_attr_local_slot_ir_root_thunk_body_artifact(
    ir: &Ir,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_has_attr_local_slot_ir_thunk_body_artifact(ir, ir.root)
}

/// Lowers a direct local-slot attr update into a verified thunk CLIF body.
///
/// This bounded attr-access precursor accepts a direct [`IrKind::BinOp`] root
/// carrying [`BinOpKind::Update`], plus one direct [`IrKind::ThunkAlloc`]
/// wrapper around such an update. Both operands must be direct
/// [`IrKind::LocalVar`] reads. The generated function imports `aos_env_get`,
/// `aos_force`, and `aos_update`, loads the left operand from the compiled
/// thunk `env` parameter, forces it, then loads and forces the right operand
/// before calling `aos_update(rt, left, right)`. The helper owns the shallow
/// right-biased merge and attrset type checks.
///
/// The returned function remains non-executable CLIF only. It is not placed in a
/// `JITModule`, linked against native helper addresses, finalized, or called.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `root` is not present in
/// `arena`. Returns [`JitLowerError::MissingIrBody`] for missing direct thunk
/// bodies. Returns update-specific unsupported-shape errors when the root, body,
/// operator, or either operand is outside the current bounded subset. Also
/// returns runtime ABI signature-conversion and verifier errors for imported
/// helpers.
pub fn lower_update_local_slots_ir_thunk_body(
    arena: &IrArena,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let (left_operand, right_operand) = update_local_slots_for_root(arena, root)?;
    lower_update_local_slots_thunk_body_with_name(
        left_operand,
        right_operand,
        clif_name_for_ir_root(root),
    )
}

/// Lowers a direct local-slot attr update into a non-executable CLIF artifact.
///
/// The artifact records the Core IR root id as source metadata and contains the
/// same verified CLIF function returned by [`lower_update_local_slots_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_update_local_slots_ir_thunk_body`].
pub fn lower_update_local_slots_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let function = lower_update_local_slots_ir_thunk_body(arena, root)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

/// Lowers the root of a lowered IR artifact as a direct local-slot attr update.
///
/// # Errors
///
/// Returns the same errors as [`lower_update_local_slots_ir_thunk_body`].
pub fn lower_update_local_slots_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_update_local_slots_ir_thunk_body(&ir.arena, ir.root)
}

/// Lowers the root local-slot attr update into a non-executable CLIF artifact.
///
/// # Errors
///
/// Returns the same errors as [`lower_update_local_slots_ir_root_thunk_body`].
pub fn lower_update_local_slots_ir_root_thunk_body_artifact(
    ir: &Ir,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_update_local_slots_ir_thunk_body_artifact(&ir.arena, ir.root)
}

/// Lowers a currently supported tier-1 IR thunk body.
///
/// This shape-directed selector accepts literal roots, local-slot roots, direct
/// local-slot application roots, and local-slot attr update roots, plus one
/// direct [`IrKind::ThunkAlloc`] wrapper around any supported shape. Literal
/// roots lower through [`lower_constant_ir_thunk_body`], local-slot roots lower
/// through [`lower_env_get_ir_thunk_body`], direct local-slot applications lower
/// through [`lower_apply_local_slots_ir_thunk_body`], and local-slot attr
/// updates lower through [`lower_update_local_slots_ir_thunk_body`].
/// Static attr selections and static attr presence tests require full
/// lowered-IR side tables, so they are accepted by
/// [`lower_tier1_ir_thunk_body_for_ir`] instead of this arena-only entrypoint.
///
/// # Errors
///
/// Returns the same errors as the selected bounded lowerer, including
/// [`JitLowerError::UnsupportedIrRoot`] or [`JitLowerError::UnsupportedIrBody`]
/// for roots outside the current tier-1 subset.
pub fn lower_tier1_ir_thunk_body(arena: &IrArena, root: IrId) -> Result<Function, JitLowerError> {
    let artifact = lower_tier1_ir_thunk_body_artifact(arena, root)?;
    Ok(artifact.into_function())
}

/// Lowers a currently supported tier-1 IR thunk body into artifact metadata.
///
/// The returned artifact records the Core IR root id and contains the same
/// verified CLIF function returned by [`lower_tier1_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_tier1_ir_thunk_body`].
pub fn lower_tier1_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_tier1_ir_thunk_body_artifact_with_local_slot_lowering(
        arena,
        root,
        Tier1LocalSlotLowering::EnvGet,
    )
}

/// Lowers a currently supported full-IR tier-1 thunk body.
///
/// This selector accepts the same arena-only roots as
/// [`lower_tier1_ir_thunk_body`], including bounded local-slot attr updates,
/// and additionally accepts a direct static attr selection or static attr
/// presence root plus one direct
/// [`IrKind::ThunkAlloc`] wrapper around either shape when it can be validated
/// against the lowered IR's attr-path side table.
///
/// # Errors
///
/// Returns the same errors as the selected bounded lowerer, including
/// [`JitLowerError::UnsupportedIrRoot`], [`JitLowerError::UnsupportedIrBody`],
/// or static attr-access validation failures for roots outside the current
/// tier-1 subset.
pub fn lower_tier1_ir_thunk_body_for_ir(ir: &Ir, root: IrId) -> Result<Function, JitLowerError> {
    let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(ir, root)?;
    Ok(artifact.into_function())
}

/// Lowers a currently supported full-IR tier-1 thunk body into artifact metadata.
///
/// The returned artifact records the Core IR root id and contains the same
/// verified CLIF function returned by [`lower_tier1_ir_thunk_body_for_ir`].
///
/// # Errors
///
/// Returns the same errors as [`lower_tier1_ir_thunk_body_for_ir`].
pub fn lower_tier1_ir_thunk_body_artifact_for_ir(
    ir: &Ir,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_tier1_ir_thunk_body_artifact_for_ir_with_local_slot_lowering(
        ir,
        root,
        Tier1LocalSlotLowering::EnvGet,
    )
}

/// Lowers a currently supported force-aware tier-1 IR thunk body.
///
/// This selector preserves the literal-root lowering path, but lowers local-slot
/// roots through [`lower_forced_env_get_ir_thunk_body`] so the loaded value is
/// forced by `aos_force` before returning. Direct local-slot applications lower
/// through [`lower_apply_local_slots_ir_thunk_body`] because `aos_apply` owns the
/// function-call forcing boundary. Local-slot attr updates lower through
/// [`lower_update_local_slots_ir_thunk_body`] because the update lowerer owns
/// operand forcing before `aos_update`.
/// Static attr selections and static attr presence tests require full
/// lowered-IR side tables, so they are accepted by
/// [`lower_force_aware_tier1_ir_thunk_body_for_ir`] instead of this arena-only
/// entrypoint.
///
/// # Errors
///
/// Returns the same errors as the selected bounded lowerer, including
/// [`JitLowerError::UnsupportedIrRoot`] or [`JitLowerError::UnsupportedIrBody`]
/// for roots outside the current tier-1 subset.
pub fn lower_force_aware_tier1_ir_thunk_body(
    arena: &IrArena,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact(arena, root)?;
    Ok(artifact.into_function())
}

/// Lowers a currently supported force-aware tier-1 IR thunk body into artifact metadata.
///
/// The returned artifact records the Core IR root id and contains the same
/// verified CLIF function returned by [`lower_force_aware_tier1_ir_thunk_body`].
///
/// # Errors
///
/// Returns the same errors as [`lower_force_aware_tier1_ir_thunk_body`].
pub fn lower_force_aware_tier1_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_tier1_ir_thunk_body_artifact_with_local_slot_lowering(
        arena,
        root,
        Tier1LocalSlotLowering::ForceEnvGet,
    )
}

/// Lowers a currently supported full-IR force-aware tier-1 thunk body.
///
/// This selector accepts the same arena-only roots as
/// [`lower_force_aware_tier1_ir_thunk_body`], including bounded local-slot attr
/// updates, and additionally accepts a direct static attr selection or static
/// attr presence root plus one direct
/// [`IrKind::ThunkAlloc`] wrapper around either shape when it can be validated
/// against the lowered IR's attr-path side table. Static attr access already
/// forces its receiver before calling `aos_select_ic` or `aos_has_attr`, so it
/// uses the same CLIF as the ordinary tier-1 full-IR selector.
///
/// # Errors
///
/// Returns the same errors as the selected bounded lowerer, including
/// [`JitLowerError::UnsupportedIrRoot`], [`JitLowerError::UnsupportedIrBody`],
/// or static attr-access validation failures for roots outside the current
/// tier-1 subset.
pub fn lower_force_aware_tier1_ir_thunk_body_for_ir(
    ir: &Ir,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(ir, root)?;
    Ok(artifact.into_function())
}

/// Lowers a currently supported full-IR force-aware tier-1 thunk body into artifact metadata.
///
/// The returned artifact records the Core IR root id and contains the same
/// verified CLIF function returned by
/// [`lower_force_aware_tier1_ir_thunk_body_for_ir`].
///
/// # Errors
///
/// Returns the same errors as [`lower_force_aware_tier1_ir_thunk_body_for_ir`].
pub fn lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(
    ir: &Ir,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    lower_tier1_ir_thunk_body_artifact_for_ir_with_local_slot_lowering(
        ir,
        root,
        Tier1LocalSlotLowering::ForceEnvGet,
    )
}

fn constant_value_for_root(arena: &IrArena, root: IrId) -> Result<Value, JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            constant_value_for_body(body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => constant_value_for_node(node),
    }
}

fn constant_value_for_body(node: IrNode) -> Result<Value, JitLowerError> {
    match (node.kind, node.data) {
        // The one-word carrier can only construct inline-range integers
        // context-free; wider integers box through the evaluator heap.
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Int, IrData::Int(value)) => {
            if i32::try_from(value).is_ok() {
                Ok(Value::int(value))
            } else {
                Err(JitLowerError::ArenaBackedConstant {
                    tag: ratchet_value::value::ValueTag::Int,
                })
            }
        }
        // The Candidate-C carrier has no context-free float constructor (floats
        // box through the evaluator heap); the tier-1 JIT is unreachable by
        // construction under that variant, so this arm is dead there.
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Float, IrData::Float(_)) => Err(JitLowerError::UnsupportedIrBody {
            kind: IrKind::Float,
        }),
        (IrKind::Bool, IrData::Bool(value)) => Ok(Value::bool(value)),
        (IrKind::Null, IrData::None) => Ok(Value::null()),
        (kind @ (IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null), data) => {
            Err(JitLowerError::MismatchedBodyConstantData { kind, data })
        }
        (kind, _) => Err(JitLowerError::UnsupportedIrBody { kind }),
    }
}

fn constant_value_for_node(node: IrNode) -> Result<Value, JitLowerError> {
    match (node.kind, node.data) {
        // See constant_value_for_body: inline-range integers only on the
        // one-word carrier.
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Int, IrData::Int(value)) => {
            if i32::try_from(value).is_ok() {
                Ok(Value::int(value))
            } else {
                Err(JitLowerError::ArenaBackedConstant {
                    tag: ratchet_value::value::ValueTag::Int,
                })
            }
        }
        // Dead under the Candidate-C variant (JIT off; no float constructor).
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Float, IrData::Float(_)) => Err(JitLowerError::UnsupportedIrRoot {
            kind: IrKind::Float,
        }),
        (IrKind::Bool, IrData::Bool(value)) => Ok(Value::bool(value)),
        (IrKind::Null, IrData::None) => Ok(Value::null()),
        (kind @ (IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null), data) => {
            Err(JitLowerError::MismatchedConstantData { kind, data })
        }
        (kind, _) => Err(JitLowerError::UnsupportedIrRoot { kind }),
    }
}

fn env_slot_for_root(arena: &IrArena, root: IrId) -> Result<u32, JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            env_slot_for_body(body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => env_slot_for_node(node),
    }
}

fn env_slot_for_body(node: IrNode) -> Result<u32, JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(slot),
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedEnvBody { kind }),
    }
}

fn env_slot_for_node(node: IrNode) -> Result<u32, JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(slot),
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedEnvRoot { kind }),
    }
}

fn upval_depth_slot_for_root(arena: &IrArena, root: IrId) -> Result<(u32, u32), JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            upval_depth_slot_for_body(body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => upval_depth_slot_for_node(node),
    }
}

fn upval_depth_slot_for_body(node: IrNode) -> Result<(u32, u32), JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => Ok((depth, slot)),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedEnvBody { kind }),
    }
}

fn upval_depth_slot_for_node(node: IrNode) -> Result<(u32, u32), JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => Ok((depth, slot)),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedEnvRoot { kind }),
    }
}

/// Returns the primop node id for a def-site body `root`, if it is a primop.
///
/// The tier-1 dispatcher hands the lowerer a thunk body node that is either an
/// [`IrKind::PrimOp`] directly or a single [`IrKind::ThunkAlloc`] wrapping one.
/// This unwraps at most one `ThunkAlloc` and returns the inner primop node id,
/// or `None` when the body is any other shape.
fn primop_node_id_for_root(arena: &IrArena, root: IrId) -> Option<IrId> {
    let node = arena.node(root).copied()?;
    match (node.kind, node.data) {
        (IrKind::PrimOp, _) => Some(root),
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body_node = arena.node(body).copied()?;
            (body_node.kind == IrKind::PrimOp).then_some(body)
        }
        _ => None,
    }
}

fn apply_local_slots_for_root(arena: &IrArena, root: IrId) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            apply_local_slots_for_body(arena, body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => apply_local_slots_for_node(arena, node),
    }
}

fn apply_local_slots_for_body(arena: &IrArena, node: IrNode) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::Apply, IrData::Pair { first, second }) => Ok((
            apply_local_child_slot(arena, first)?,
            apply_local_child_slot(arena, second)?,
        )),
        (IrKind::Apply, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::Apply,
            data,
            expected: "application pair payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedApplyBody { kind }),
    }
}

fn apply_local_slots_for_node(arena: &IrArena, node: IrNode) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::Apply, IrData::Pair { first, second }) => Ok((
            apply_local_child_slot(arena, first)?,
            apply_local_child_slot(arena, second)?,
        )),
        (IrKind::Apply, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::Apply,
            data,
            expected: "application pair payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedApplyRoot { kind }),
    }
}

fn apply_local_child_slot(arena: &IrArena, child: IrId) -> Result<Tier1SlotOperand, JitLowerError> {
    let node = arena
        .node(child)
        .copied()
        .ok_or(JitLowerError::MissingApplyChild { child })?;

    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(Tier1SlotOperand::Local { slot }),
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            Ok(Tier1SlotOperand::Upval { depth, slot })
        }
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedApplyChild { child, kind }),
    }
}

fn update_local_slots_for_root(arena: &IrArena, root: IrId) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            update_local_slots_for_body(arena, body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => update_local_slots_for_node(arena, node),
    }
}

fn update_local_slots_for_body(arena: &IrArena, node: IrNode) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    match (node.kind, node.data) {
        (
            IrKind::BinOp,
            IrData::Binary {
                op: BinOpKind::Update,
                lhs,
                rhs,
            },
        ) => Ok((
            update_local_operand_slot(arena, lhs)?,
            update_local_operand_slot(arena, rhs)?,
        )),
        (IrKind::BinOp, IrData::Binary { op, .. }) => {
            Err(JitLowerError::UnsupportedUpdateOp { op })
        }
        (IrKind::BinOp, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::BinOp,
            data,
            expected: "attr update binary payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedUpdateBody { kind }),
    }
}

fn update_local_slots_for_node(arena: &IrArena, node: IrNode) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    match (node.kind, node.data) {
        (
            IrKind::BinOp,
            IrData::Binary {
                op: BinOpKind::Update,
                lhs,
                rhs,
            },
        ) => Ok((
            update_local_operand_slot(arena, lhs)?,
            update_local_operand_slot(arena, rhs)?,
        )),
        (IrKind::BinOp, IrData::Binary { op, .. }) => {
            Err(JitLowerError::UnsupportedUpdateOp { op })
        }
        (IrKind::BinOp, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::BinOp,
            data,
            expected: "attr update binary payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedUpdateRoot { kind }),
    }
}

fn update_local_operand_slot(
    arena: &IrArena,
    operand: IrId,
) -> Result<Tier1SlotOperand, JitLowerError> {
    let node = arena
        .node(operand)
        .copied()
        .ok_or(JitLowerError::MissingUpdateOperand { operand })?;

    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(Tier1SlotOperand::Local { slot }),
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            Ok(Tier1SlotOperand::Upval { depth, slot })
        }
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedUpdateOperand { operand, kind }),
    }
}

#[derive(Clone, Copy)]
struct AttrLookup {
    receiver: Tier1SlotOperand,
    symbol: Symbol,
    site: IrInlineCacheSiteId,
    default: Option<Value>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttrLookupLowering {
    HasAttr,
    SelectIc,
}

impl AttrLookupLowering {
    const fn expected_kind(self) -> IrKind {
        match self {
            Self::HasAttr => IrKind::HasAttr,
            Self::SelectIc => IrKind::Select,
        }
    }

    const fn symbol_name(self) -> &'static str {
        match self {
            Self::HasAttr => AOS_HAS_ATTR_SYMBOL,
            Self::SelectIc => AOS_SELECT_IC_SYMBOL,
        }
    }

    fn external_name(self) -> UserExternalName {
        match self {
            Self::HasAttr => clif_external_name_for_aos_has_attr(),
            Self::SelectIc => clif_external_name_for_aos_select_ic(),
        }
    }
}

fn attr_lookup_for_root(
    ir: &Ir,
    root: IrId,
    lowering: AttrLookupLowering,
) -> Result<AttrLookup, JitLowerError> {
    let node = ir
        .arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body_node = ir
                .arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            attr_lookup_for_node(ir, body_node, lowering, true)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => attr_lookup_for_node(ir, node, lowering, false),
    }
}

fn attr_lookup_for_node(
    ir: &Ir,
    node: IrNode,
    lowering: AttrLookupLowering,
    is_thunk_body: bool,
) -> Result<AttrLookup, JitLowerError> {
    if node.kind != lowering.expected_kind() {
        if is_thunk_body {
            return Err(JitLowerError::UnsupportedAttrBody { kind: node.kind });
        }
        return Err(JitLowerError::UnsupportedAttrRoot { kind: node.kind });
    }

    match (lowering, node.data) {
        (
            AttrLookupLowering::HasAttr,
            IrData::HasAttr {
                receiver,
                path,
                site,
            },
        ) => attr_lookup(ir, receiver, path, site, None),
        (
            AttrLookupLowering::SelectIc,
            IrData::Select {
                receiver,
                path,
                site,
                default: None,
            },
        ) => attr_lookup(ir, receiver, path, site, None),
        (
            AttrLookupLowering::SelectIc,
            IrData::Select {
                default: Some(default),
                receiver,
                path,
                site,
                ..
            },
        ) => {
            let default_value = constant_value_for_root(&ir.arena, default)
                .map_err(|_| JitLowerError::UnsupportedSelectDefault { default })?;
            attr_lookup(ir, receiver, path, site, Some(default_value))
        }
        (_, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: lowering.expected_kind(),
            data,
            expected: "static attr lookup payload",
        }),
    }
}

fn attr_lookup(
    ir: &Ir,
    receiver: IrId,
    path: IrAttrPathId,
    site: IrInlineCacheSiteId,
    default: Option<Value>,
) -> Result<AttrLookup, JitLowerError> {
    Ok(AttrLookup {
        receiver: attr_receiver_slot(ir, receiver)?,
        symbol: single_static_attr_path_symbol(ir, path)?,
        site,
        default,
    })
}

fn attr_receiver_slot(ir: &Ir, receiver: IrId) -> Result<Tier1SlotOperand, JitLowerError> {
    let node = ir
        .arena
        .node(receiver)
        .copied()
        .ok_or(JitLowerError::MissingAttrReceiver { receiver })?;

    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(Tier1SlotOperand::Local { slot }),
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            Ok(Tier1SlotOperand::Upval { depth, slot })
        }
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedAttrReceiver { receiver, kind }),
    }
}

fn single_static_attr_path_symbol(ir: &Ir, path: IrAttrPathId) -> Result<Symbol, JitLowerError> {
    let segments = ir
        .attr_paths
        .get(path.index())
        .ok_or(JitLowerError::MissingAttrPath { path })?;

    if segments.len() != 1 {
        return Err(JitLowerError::UnsupportedAttrPathLength {
            path,
            len: segments.len(),
        });
    }

    match segments[0] {
        IrAttrPathSegment::Static(symbol) => Ok(symbol),
        segment => Err(JitLowerError::UnsupportedAttrPathSegment {
            path,
            index: 0,
            segment,
        }),
    }
}

#[derive(Clone, Copy)]
enum Tier1LocalSlotLowering {
    EnvGet,
    ForceEnvGet,
}

fn lower_tier1_ir_thunk_body_artifact_with_local_slot_lowering(
    arena: &IrArena,
    root: IrId,
    local_slot_lowering: Tier1LocalSlotLowering,
) -> Result<JitClifArtifact, JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body_node = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            lower_tier1_ir_thunk_body_artifact_for_kind(
                arena,
                root,
                body_node.kind,
                local_slot_lowering,
                true,
            )
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        (kind, _) => lower_tier1_ir_thunk_body_artifact_for_kind(
            arena,
            root,
            kind,
            local_slot_lowering,
            false,
        ),
    }
}

fn lower_tier1_ir_thunk_body_artifact_for_ir_with_local_slot_lowering(
    ir: &Ir,
    root: IrId,
    local_slot_lowering: Tier1LocalSlotLowering,
) -> Result<JitClifArtifact, JitLowerError> {
    let node = ir
        .arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body_node = ir
                .arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            lower_tier1_ir_thunk_body_artifact_for_kind_with_ir(
                ir,
                root,
                body_node.kind,
                local_slot_lowering,
                true,
            )
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        (kind, _) => lower_tier1_ir_thunk_body_artifact_for_kind_with_ir(
            ir,
            root,
            kind,
            local_slot_lowering,
            false,
        ),
    }
}

fn lower_tier1_ir_thunk_body_artifact_for_kind(
    arena: &IrArena,
    root: IrId,
    kind: IrKind,
    local_slot_lowering: Tier1LocalSlotLowering,
    is_thunk_body: bool,
) -> Result<JitClifArtifact, JitLowerError> {
    match kind {
        IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null => {
            lower_constant_ir_thunk_body_artifact(arena, root)
        }
        IrKind::LocalVar => match local_slot_lowering {
            Tier1LocalSlotLowering::EnvGet => lower_env_get_ir_thunk_body_artifact(arena, root),
            Tier1LocalSlotLowering::ForceEnvGet => {
                lower_forced_env_get_ir_thunk_body_artifact(arena, root)
            }
        },
        IrKind::UpvalVar => match local_slot_lowering {
            Tier1LocalSlotLowering::EnvGet => lower_upval_get_ir_thunk_body_artifact(arena, root),
            Tier1LocalSlotLowering::ForceEnvGet => {
                lower_forced_upval_get_ir_thunk_body_artifact(arena, root)
            }
        },
        IrKind::Apply => lower_apply_local_slots_ir_thunk_body_artifact(arena, root),
        // The arith lowerer declines non-Update ops on the one-word carrier
        // itself (Update routes to the delegating aos_update path); cons
        // cells compose a heap value from a raw allocation pointer, which is
        // two-word-carrier codegen, so the one-word carrier declines them.
        IrKind::BinOp => arith_tree::lower_binop_ir_thunk_body_artifact(arena, root),
        IrKind::List => {
            value_words::require_two_word_carrier("alloc-cons")?;
            alloc_cons::lower_singleton_list_ir_thunk_body_artifact(arena, root)
        }
        kind if is_thunk_body => Err(JitLowerError::UnsupportedIrBody { kind }),
        kind => Err(JitLowerError::UnsupportedIrRoot { kind }),
    }
}

fn lower_tier1_ir_thunk_body_artifact_for_kind_with_ir(
    ir: &Ir,
    root: IrId,
    kind: IrKind,
    local_slot_lowering: Tier1LocalSlotLowering,
    is_thunk_body: bool,
) -> Result<JitClifArtifact, JitLowerError> {
    match kind {
        IrKind::HasAttr => lower_has_attr_local_slot_ir_thunk_body_artifact(ir, root),
        IrKind::Select => lower_select_local_slot_ir_thunk_body_artifact(ir, root),
        // The arith lowerer declines non-Update ops on the one-word carrier
        // itself; Update routes to the delegating aos_update path.
        IrKind::BinOp => arith_tree::lower_binop_ir_thunk_body_artifact(&ir.arena, root),
        _ => lower_tier1_ir_thunk_body_artifact_for_kind(
            &ir.arena,
            root,
            kind,
            local_slot_lowering,
            is_thunk_body,
        ),
    }
}

fn lower_env_get_slot_thunk_body_with_name(
    slot: u32,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let env_get = import_env_get_function(&mut function)?;
    let entry_block = append_entry_block_params(&mut function);
    emit_env_get_return(&mut function, entry_block, env_get, slot)?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_forced_env_get_slot_thunk_body_with_name(
    slot: u32,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let env_get = import_env_get_function(&mut function)?;
    let force = import_runtime_helper_function(
        &mut function,
        AOS_FORCE_SYMBOL,
        clif_external_name_for_aos_force(),
    )?;
    let stack_map_runtime = stack_maps::import_runtime(&mut function)?;
    let entry_block = append_entry_block_params(&mut function);
    stack_maps::emit_forced_env_get_return(
        &mut function,
        entry_block,
        env_get,
        force,
        stack_map_runtime,
        slot,
    )?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_upval_get_slot_thunk_body_with_name(
    depth: u32,
    slot: u32,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let upval_get = import_upval_get_function(&mut function)?;
    let entry_block = append_entry_block_params(&mut function);
    emit_upval_get_return(&mut function, entry_block, upval_get, depth, slot)?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_forced_upval_get_slot_thunk_body_with_name(
    depth: u32,
    slot: u32,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let upval_get = import_upval_get_function(&mut function)?;
    let force = import_runtime_helper_function(
        &mut function,
        AOS_FORCE_SYMBOL,
        clif_external_name_for_aos_force(),
    )?;
    let stack_map_runtime = stack_maps::import_runtime(&mut function)?;
    let entry_block = append_entry_block_params(&mut function);
    emit_forced_upval_get_return(
        &mut function,
        entry_block,
        upval_get,
        force,
        stack_map_runtime,
        depth,
        slot,
    )?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_primop_call_thunk_body_with_name(
    module_id: u32,
    node_id: IrId,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let primop_call = import_primop_call_function(&mut function)?;
    let entry_block = append_entry_block_params(&mut function);
    emit_primop_call_return(&mut function, entry_block, primop_call, module_id, node_id)?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_string_length_inline_thunk_body_with_name(
    operand: Tier1SlotOperand,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let env_get = import_env_get_function(&mut function)?;
    let upval_get = maybe_import_upval_get_function(&mut function, [operand])?;
    let force = import_runtime_helper_function(
        &mut function,
        AOS_FORCE_SYMBOL,
        clif_external_name_for_aos_force(),
    )?;
    let stack_map_runtime = stack_maps::import_runtime(&mut function)?;
    let string_length = import_string_length_function(&mut function)?;
    let entry_block = append_entry_block_params(&mut function);
    emit_string_length_inline_return(
        &mut function,
        entry_block,
        env_get,
        upval_get,
        force,
        stack_map_runtime,
        string_length,
        operand,
    )?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_apply_local_slots_thunk_body_with_name(
    function_operand: Tier1SlotOperand,
    argument_operand: Tier1SlotOperand,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let env_get = import_env_get_function(&mut function)?;
    let upval_get = maybe_import_upval_get_function(
        &mut function,
        [function_operand, argument_operand],
    )?;
    let apply = import_runtime_helper_function(
        &mut function,
        AOS_APPLY_SYMBOL,
        clif_external_name_for_aos_apply(),
    )?;
    let entry_block = append_entry_block_params(&mut function);
    emit_apply_local_slots_return(
        &mut function,
        entry_block,
        env_get,
        upval_get,
        apply,
        function_operand,
        argument_operand,
    )?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_update_local_slots_thunk_body_with_name(
    left_operand: Tier1SlotOperand,
    right_operand: Tier1SlotOperand,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let env_get = import_env_get_function(&mut function)?;
    let upval_get =
        maybe_import_upval_get_function(&mut function, [left_operand, right_operand])?;
    let force = import_runtime_helper_function(
        &mut function,
        AOS_FORCE_SYMBOL,
        clif_external_name_for_aos_force(),
    )?;
    let stack_map_runtime = stack_maps::import_runtime(&mut function)?;
    let update = import_runtime_helper_function(
        &mut function,
        AOS_UPDATE_SYMBOL,
        clif_external_name_for_aos_update(),
    )?;
    let entry_block = append_entry_block_params(&mut function);
    emit_update_local_slots_return(
        &mut function,
        entry_block,
        env_get,
        upval_get,
        force,
        stack_map_runtime,
        update,
        left_operand,
        right_operand,
    )?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_attr_lookup_local_slot_thunk_body_with_name(
    lookup: AttrLookup,
    lowering: AttrLookupLowering,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let env_get = import_env_get_function(&mut function)?;
    let upval_get = maybe_import_upval_get_function(&mut function, [lookup.receiver])?;
    let force = import_runtime_helper_function(
        &mut function,
        AOS_FORCE_SYMBOL,
        clif_external_name_for_aos_force(),
    )?;
    let stack_map_runtime = stack_maps::import_runtime(&mut function)?;
    let entry_block = append_entry_block_params(&mut function);
    if lowering == AttrLookupLowering::SelectIc {
        if let Some(default_value) = lookup.default {
            let has_attr = import_runtime_helper_function(
                &mut function,
                AOS_HAS_ATTR_SYMBOL,
                clif_external_name_for_aos_has_attr(),
            )?;
            let select_ic = import_runtime_helper_function(
                &mut function,
                AOS_SELECT_IC_SYMBOL,
                clif_external_name_for_aos_select_ic(),
            )?;
            emit_attr_select_default_local_slot_return(
                &mut function,
                entry_block,
                env_get,
                upval_get,
                force,
                stack_map_runtime,
                has_attr,
                select_ic,
                lookup,
                default_value,
            )?;
        } else {
            let select_ic = import_runtime_helper_function(
                &mut function,
                AOS_SELECT_IC_SYMBOL,
                clif_external_name_for_aos_select_ic(),
            )?;
            emit_attr_lookup_local_slot_return(
                &mut function,
                entry_block,
                env_get,
                upval_get,
                force,
                stack_map_runtime,
                select_ic,
                lookup,
                lowering,
            )?;
        }
    } else {
        let attr_helper = import_runtime_helper_function(
            &mut function,
            lowering.symbol_name(),
            lowering.external_name(),
        )?;
        emit_attr_lookup_local_slot_return(
            &mut function,
            entry_block,
            env_get,
            upval_get,
            force,
            stack_map_runtime,
            attr_helper,
            lookup,
            lowering,
        )?;
    }
    verify_clif_function(&function)?;
    Ok(function)
}

fn import_env_get_function(
    function: &mut Function,
) -> Result<cranelift_codegen::ir::FuncRef, JitLowerError> {
    import_runtime_helper_function(
        function,
        AOS_ENV_GET_SYMBOL,
        clif_external_name_for_aos_env_get(),
    )
}

fn import_primop_call_function(
    function: &mut Function,
) -> Result<cranelift_codegen::ir::FuncRef, JitLowerError> {
    import_runtime_helper_function(
        function,
        AOS_PRIMOP_CALL_SYMBOL,
        clif_external_name_for_aos_primop_call(),
    )
}

fn import_upval_get_function(
    function: &mut Function,
) -> Result<cranelift_codegen::ir::FuncRef, JitLowerError> {
    import_runtime_helper_function(
        function,
        AOS_UPVAL_GET_SYMBOL,
        clif_external_name_for_aos_upval_get(),
    )
}

fn import_string_length_function(
    function: &mut Function,
) -> Result<cranelift_codegen::ir::FuncRef, JitLowerError> {
    import_runtime_helper_function(
        function,
        AOS_STRING_LENGTH_SYMBOL,
        clif_external_name_for_aos_string_length(),
    )
}

/// Imports `aos_upval_get` only when at least one `operand` reads an upvalue.
///
/// Keeping the import conditional means a body whose operands are all local
/// reads declares no `aos_upval_get` import, so its module import set and
/// finalized code stay byte-identical to the pre-upvalue operand lowering.
fn maybe_import_upval_get_function(
    function: &mut Function,
    operands: impl IntoIterator<Item = Tier1SlotOperand>,
) -> Result<Option<cranelift_codegen::ir::FuncRef>, JitLowerError> {
    if operands.into_iter().any(Tier1SlotOperand::is_upval) {
        Ok(Some(import_upval_get_function(function)?))
    } else {
        Ok(None)
    }
}

fn import_runtime_helper_function(
    function: &mut Function,
    symbol_name: &'static str,
    external_name: UserExternalName,
) -> Result<cranelift_codegen::ir::FuncRef, JitLowerError> {
    let runtime_signature = runtime_helper_call_signature(symbol_name)
        .ok_or(JitLowerError::MissingRuntimeHelperSignature { symbol_name })?;
    let signature = clif_signature_for_runtime_call(runtime_signature)?;
    let signature_ref = function.import_signature(signature);
    let user_name = function.declare_imported_user_function(external_name);

    Ok(function.import_function(ExtFuncData {
        name: ExternalName::user(user_name),
        signature: signature_ref,
        colocated: false,
    }))
}

fn thunk_body_artifact(source: JitClifArtifactSource, function: Function) -> JitClifArtifact {
    JitClifArtifact::new(
        JitTier::Tier1Baseline,
        JitClifArtifactKind::ThunkBody,
        source,
        function,
    )
}

fn append_entry_block_params(function: &mut Function) -> cranelift_codegen::ir::Block {
    let entry_block = function.dfg.make_block();
    let parameter_types = function
        .signature
        .params
        .iter()
        .map(|parameter| parameter.value_type)
        .collect::<Vec<_>>();

    for parameter_type in parameter_types {
        function.dfg.append_block_param(entry_block, parameter_type);
    }

    let mut cursor = FuncCursor::new(function);
    cursor.insert_block(entry_block);

    entry_block
}

fn emit_value_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    constant_words: [i64; value_words::VALUE_WORDS],
) {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let words = value_words::iconst_words(&mut cursor, constant_words);
    cursor.ins().return_(&words);
}
fn emit_env_get_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    slot: u32,
) -> Result<(), JitLowerError> {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let entry_params = cursor.func.dfg.block_params(entry_block);
    let env = entry_params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let slot = cursor.ins().iconst(types::I32, i64::from(slot));
    let call = cursor.ins().call(env_get, &[env, slot]);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let words = value_words::expect_value_words(AOS_ENV_GET_SYMBOL, &results)?;

    cursor.ins().return_(&words);
    Ok(())
}

fn emit_upval_get_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    upval_get: cranelift_codegen::ir::FuncRef,
    depth: u32,
    slot: u32,
) -> Result<(), JitLowerError> {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let entry_params = cursor.func.dfg.block_params(entry_block);
    let env = entry_params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let depth = cursor.ins().iconst(types::I32, i64::from(depth));
    let slot = cursor.ins().iconst(types::I32, i64::from(slot));
    let call = cursor.ins().call(upval_get, &[env, depth, slot]);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let words = value_words::expect_value_words(AOS_UPVAL_GET_SYMBOL, &results)?;

    cursor.ins().return_(&words);
    Ok(())
}

fn emit_forced_upval_get_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    upval_get: cranelift_codegen::ir::FuncRef,
    force: cranelift_codegen::ir::FuncRef,
    stack_map_runtime: stack_maps::Runtime,
    depth: u32,
    slot: u32,
) -> Result<(), JitLowerError> {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let entry_params = cursor.func.dfg.block_params(entry_block);
    let rt = entry_params
        .first()
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 0 })?;
    let env = entry_params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let depth = cursor.ins().iconst(types::I32, i64::from(depth));
    let slot = cursor.ins().iconst(types::I32, i64::from(slot));
    let upval_get_call = cursor.ins().call(upval_get, &[env, depth, slot]);
    let upval_get_results = cursor.func.dfg.inst_results(upval_get_call).to_vec();
    let upval_get_words = value_words::expect_value_words(AOS_UPVAL_GET_SYMBOL, &upval_get_results)?;

    let force_input_slot = value_words::spill(&mut cursor, &[upval_get_words]);
    stack_maps::enter(&mut cursor, stack_map_runtime, rt, force_input_slot, 0);
    let mut force_args = vec![rt];
    value_words::push_words(&mut force_args, upval_get_words);
    let force_call = cursor.ins().call(force, &force_args);
    value_words::attach(&mut cursor, force_call, force_input_slot);
    let force_results = cursor.func.dfg.inst_results(force_call).to_vec();
    stack_maps::exit(&mut cursor, stack_map_runtime, rt, force_input_slot);
    let force_words = value_words::expect_value_words(AOS_FORCE_SYMBOL, &force_results)?;

    cursor.ins().return_(&force_words);
    Ok(())
}

fn emit_primop_call_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    primop_call: cranelift_codegen::ir::FuncRef,
    module_id: u32,
    node_id: IrId,
) -> Result<(), JitLowerError> {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let entry_params = cursor.func.dfg.block_params(entry_block);
    let rt = entry_params
        .first()
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 0 })?;
    let env = entry_params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let module_id = cursor.ins().iconst(types::I32, i64::from(module_id));
    let node_id = cursor.ins().iconst(types::I32, i64::from(node_id.as_u32()));
    let call = cursor.ins().call(primop_call, &[rt, env, module_id, node_id]);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let words = value_words::expect_value_words(AOS_PRIMOP_CALL_SYMBOL, &results)?;

    cursor.ins().return_(&words);
    Ok(())
}

fn emit_string_length_inline_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    upval_get: Option<cranelift_codegen::ir::FuncRef>,
    force: cranelift_codegen::ir::FuncRef,
    stack_map_runtime: stack_maps::Runtime,
    string_length: cranelift_codegen::ir::FuncRef,
    operand: Tier1SlotOperand,
) -> Result<(), JitLowerError> {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let entry_params = cursor.func.dfg.block_params(entry_block);
    let rt = entry_params
        .first()
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 0 })?;
    let env = entry_params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let argument = emit_slot_operand_load(&mut cursor, env, env_get, upval_get, operand)?;

    let force_input_slot = value_words::spill(&mut cursor, &[argument]);
    stack_maps::enter(&mut cursor, stack_map_runtime, rt, force_input_slot, 0);
    let mut force_args = vec![rt];
    value_words::push_words(&mut force_args, argument);
    let force_call = cursor.ins().call(force, &force_args);
    value_words::attach(&mut cursor, force_call, force_input_slot);
    let force_results = cursor.func.dfg.inst_results(force_call).to_vec();
    stack_maps::exit(&mut cursor, stack_map_runtime, rt, force_input_slot);
    let force_words = value_words::expect_value_words(AOS_FORCE_SYMBOL, &force_results)?;

    let mut length_args = vec![rt];
    value_words::push_words(&mut length_args, force_words);
    let length_call = cursor.ins().call(string_length, &length_args);
    let length_results = cursor.func.dfg.inst_results(length_call).to_vec();
    let length_words =
        value_words::expect_value_words(AOS_STRING_LENGTH_SYMBOL, &length_results)?;

    cursor.ins().return_(&length_words);
    Ok(())
}

/// A tier-1 lowerable operand: a lexical slot read resolved at run time.
///
/// A [`Tier1SlotOperand::Local`] reads the innermost captured frame through
/// `aos_env_get(env, slot)`; a [`Tier1SlotOperand::Upval`] reads a frame `depth`
/// levels above through `aos_upval_get(env, depth, slot)`. The apply, update,
/// select, and arithmetic shapes accept either operand form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier1SlotOperand {
    /// A slot in the innermost captured frame.
    Local {
        /// The frame slot index.
        slot: u32,
    },
    /// A slot `depth` frames above the innermost captured frame.
    Upval {
        /// The number of parent frames to walk.
        depth: u32,
        /// The slot inside the target frame.
        slot: u32,
    },
}

impl Tier1SlotOperand {
    /// Returns true when this operand needs the `aos_upval_get` helper.
    const fn is_upval(self) -> bool {
        matches!(self, Self::Upval { .. })
    }
}

/// Returns the operand form for a direct local or upvalue slot-read node.
///
/// Returns `None` for any other node kind, so a caller can map the miss to its
/// shape-specific unsupported-operand error.
fn slot_operand_for_operand_node(node: IrNode) -> Option<Tier1SlotOperand> {
    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Some(Tier1SlotOperand::Local { slot }),
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            Some(Tier1SlotOperand::Upval { depth, slot })
        }
        _ => None,
    }
}

/// Emits the runtime load of `operand`'s `Value` words from `env`.
///
/// A [`Tier1SlotOperand::Local`] lowers to an `aos_env_get(env, slot)` call and a
/// [`Tier1SlotOperand::Upval`] to an `aos_upval_get(env, depth, slot)` call.
/// `upval_get` must be `Some` whenever an [`Tier1SlotOperand::Upval`] is emitted;
/// the caller imports it only when an operand needs it, so a `None` here is a
/// caller invariant violation and lowers to a helper-signature error (a safe
/// blacklist), never a miscompilation.
fn emit_slot_operand_load(
    cursor: &mut FuncCursor,
    env: cranelift_codegen::ir::Value,
    env_get: cranelift_codegen::ir::FuncRef,
    upval_get: Option<cranelift_codegen::ir::FuncRef>,
    operand: Tier1SlotOperand,
) -> Result<value_words::ValueWords, JitLowerError> {
    let (helper, symbol_name, args) = match operand {
        Tier1SlotOperand::Local { slot } => {
            let slot = cursor.ins().iconst(types::I32, i64::from(slot));
            (env_get, AOS_ENV_GET_SYMBOL, vec![env, slot])
        }
        Tier1SlotOperand::Upval { depth, slot } => {
            let upval_get = upval_get.ok_or(JitLowerError::MissingRuntimeHelperSignature {
                symbol_name: AOS_UPVAL_GET_SYMBOL,
            })?;
            let depth = cursor.ins().iconst(types::I32, i64::from(depth));
            let slot = cursor.ins().iconst(types::I32, i64::from(slot));
            (upval_get, AOS_UPVAL_GET_SYMBOL, vec![env, depth, slot])
        }
    };
    let call = cursor.ins().call(helper, &args);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    value_words::expect_value_words(symbol_name, &results)
}

fn emit_apply_local_slots_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    upval_get: Option<cranelift_codegen::ir::FuncRef>,
    apply: cranelift_codegen::ir::FuncRef,
    function_operand: Tier1SlotOperand,
    argument_operand: Tier1SlotOperand,
) -> Result<(), JitLowerError> {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let entry_params = cursor.func.dfg.block_params(entry_block);
    let rt = entry_params
        .first()
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 0 })?;
    let env = entry_params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let function_value = emit_slot_operand_load(&mut cursor, env, env_get, upval_get, function_operand)?;
    let argument_value = emit_slot_operand_load(&mut cursor, env, env_get, upval_get, argument_operand)?;

    let mut apply_args = vec![rt];
    value_words::push_words(&mut apply_args, function_value);
    value_words::push_words(&mut apply_args, argument_value);
    let apply_call = cursor.ins().call(apply, &apply_args);
    let apply_results = cursor.func.dfg.inst_results(apply_call).to_vec();
    let apply_words = value_words::expect_value_words(AOS_APPLY_SYMBOL, &apply_results)?;

    cursor.ins().return_(&apply_words);
    Ok(())
}

fn emit_update_local_slots_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    upval_get: Option<cranelift_codegen::ir::FuncRef>,
    force: cranelift_codegen::ir::FuncRef,
    stack_map_runtime: stack_maps::Runtime,
    update: cranelift_codegen::ir::FuncRef,
    left_operand: Tier1SlotOperand,
    right_operand: Tier1SlotOperand,
) -> Result<(), JitLowerError> {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let entry_params = cursor.func.dfg.block_params(entry_block);
    let rt = entry_params
        .first()
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 0 })?;
    let env = entry_params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;

    let left_value = emit_slot_operand_load(&mut cursor, env, env_get, upval_get, left_operand)?;

    let left_input_slot = value_words::spill(&mut cursor, &[left_value]);
    stack_maps::enter(&mut cursor, stack_map_runtime, rt, left_input_slot, 0);
    let mut left_force_args = vec![rt];
    value_words::push_words(&mut left_force_args, left_value);
    let left_force_call = cursor.ins().call(force, &left_force_args);
    value_words::attach(&mut cursor, left_force_call, left_input_slot);
    let left_force_results = cursor.func.dfg.inst_results(left_force_call).to_vec();
    stack_maps::exit(&mut cursor, stack_map_runtime, rt, left_input_slot);
    let left_force_words =
        value_words::expect_value_words(AOS_FORCE_SYMBOL, &left_force_results)?;

    let right_value = emit_slot_operand_load(&mut cursor, env, env_get, upval_get, right_operand)?;

    let right_force_binding =
        value_words::spill(&mut cursor, &[left_force_words, right_value]);
    stack_maps::enter(&mut cursor, stack_map_runtime, rt, right_force_binding, 1);
    let mut right_force_args = vec![rt];
    value_words::push_words(&mut right_force_args, right_value);
    let right_force_call = cursor.ins().call(force, &right_force_args);
    value_words::attach(&mut cursor, right_force_call, right_force_binding);
    let right_force_results = cursor.func.dfg.inst_results(right_force_call).to_vec();
    stack_maps::exit(&mut cursor, stack_map_runtime, rt, right_force_binding);
    let right_force_words =
        value_words::expect_value_words(AOS_FORCE_SYMBOL, &right_force_results)?;

    let left_force_words = value_words::reload(&mut cursor, right_force_binding, 0);
    let mut update_args = vec![rt];
    value_words::push_words(&mut update_args, left_force_words);
    value_words::push_words(&mut update_args, right_force_words);
    let update_call = cursor.ins().call(update, &update_args);
    let update_results = cursor.func.dfg.inst_results(update_call).to_vec();
    let update_words = value_words::expect_value_words(AOS_UPDATE_SYMBOL, &update_results)?;

    cursor.ins().return_(&update_words);
    Ok(())
}

fn emit_attr_lookup_local_slot_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    upval_get: Option<cranelift_codegen::ir::FuncRef>,
    force: cranelift_codegen::ir::FuncRef,
    stack_map_runtime: stack_maps::Runtime,
    attr_helper: cranelift_codegen::ir::FuncRef,
    lookup: AttrLookup,
    lowering: AttrLookupLowering,
) -> Result<(), JitLowerError> {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let entry_params = cursor.func.dfg.block_params(entry_block);
    let rt = entry_params
        .first()
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 0 })?;
    let env = entry_params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let receiver_value =
        emit_slot_operand_load(&mut cursor, env, env_get, upval_get, lookup.receiver)?;

    let force_input_slot = value_words::spill(&mut cursor, &[receiver_value]);
    stack_maps::enter(&mut cursor, stack_map_runtime, rt, force_input_slot, 0);
    let mut force_args = vec![rt];
    value_words::push_words(&mut force_args, receiver_value);
    let force_call = cursor.ins().call(force, &force_args);
    value_words::attach(&mut cursor, force_call, force_input_slot);
    let force_results = cursor.func.dfg.inst_results(force_call).to_vec();
    stack_maps::exit(&mut cursor, stack_map_runtime, rt, force_input_slot);
    let force_words = value_words::expect_value_words(AOS_FORCE_SYMBOL, &force_results)?;

    let symbol = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.symbol.as_u32()));
    let site = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.site.as_u32()));
    let mut attr_args = vec![rt];
    value_words::push_words(&mut attr_args, force_words);
    attr_args.push(symbol);
    attr_args.push(site);
    let attr_call = cursor.ins().call(attr_helper, &attr_args);
    let attr_results = cursor.func.dfg.inst_results(attr_call).to_vec();
    let attr_words = value_words::expect_value_words(lowering.symbol_name(), &attr_results)?;

    cursor.ins().return_(&attr_words);
    Ok(())
}

fn emit_attr_select_default_local_slot_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    upval_get: Option<cranelift_codegen::ir::FuncRef>,
    force: cranelift_codegen::ir::FuncRef,
    stack_map_runtime: stack_maps::Runtime,
    has_attr: cranelift_codegen::ir::FuncRef,
    select_ic: cranelift_codegen::ir::FuncRef,
    lookup: AttrLookup,
    default_value: Value,
) -> Result<(), JitLowerError> {
    error::validate_embedded_constant(default_value)?;
    let default_words = value_words::embedded_constant_words(default_value)?;
    let select_block = function.dfg.make_block();
    let default_block = function.dfg.make_block();
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let entry_params = cursor.func.dfg.block_params(entry_block);
    let rt = entry_params
        .first()
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 0 })?;
    let env = entry_params
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let receiver_value =
        emit_slot_operand_load(&mut cursor, env, env_get, upval_get, lookup.receiver)?;

    let force_input_slot = value_words::spill(&mut cursor, &[receiver_value]);
    stack_maps::enter(&mut cursor, stack_map_runtime, rt, force_input_slot, 0);
    let mut force_args = vec![rt];
    value_words::push_words(&mut force_args, receiver_value);
    let force_call = cursor.ins().call(force, &force_args);
    value_words::attach(&mut cursor, force_call, force_input_slot);
    let force_results = cursor.func.dfg.inst_results(force_call).to_vec();
    stack_maps::exit(&mut cursor, stack_map_runtime, rt, force_input_slot);
    let force_words = value_words::expect_value_words(AOS_FORCE_SYMBOL, &force_results)?;

    let symbol = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.symbol.as_u32()));
    let site = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.site.as_u32()));
    let mut has_attr_args = vec![rt];
    value_words::push_words(&mut has_attr_args, force_words);
    has_attr_args.push(symbol);
    has_attr_args.push(site);
    let has_attr_call = cursor.ins().call(has_attr, &has_attr_args);
    let has_attr_results = cursor.func.dfg.inst_results(has_attr_call).to_vec();
    let has_attr_words =
        value_words::expect_value_words(AOS_HAS_ATTR_SYMBOL, &has_attr_results)?;

    let is_present = value_words::truthy_test(&mut cursor, has_attr_words);
    cursor
        .ins()
        .brif(is_present, select_block, &[], default_block, &[]);

    cursor.insert_block(select_block);
    let symbol = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.symbol.as_u32()));
    let site = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.site.as_u32()));
    let mut select_args = vec![rt];
    value_words::push_words(&mut select_args, force_words);
    select_args.push(symbol);
    select_args.push(site);
    let select_call = cursor.ins().call(select_ic, &select_args);
    let select_results = cursor.func.dfg.inst_results(select_call).to_vec();
    let select_words = value_words::expect_value_words(AOS_SELECT_IC_SYMBOL, &select_results)?;
    cursor.ins().return_(&select_words);

    cursor.insert_block(default_block);
    let default_consts = value_words::iconst_words(&mut cursor, default_words);
    cursor.ins().return_(&default_consts);

    Ok(())
}
pub(crate) fn verify_clif_function(function: &Function) -> Result<(), JitLowerError> {
    let flags = settings::Flags::new(settings::builder());
    verify_function(function, &flags).map_err(JitLowerError::Verifier)
}

// These tests exercise two-word-carrier codegen (tier-2 bodies, inline arith,
// candidate bridges, or two-word CLIF shape asserts), which declines on the
// one-word carrier; baseline-only until the S4b phase-2 one-word emitters land.
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests;
