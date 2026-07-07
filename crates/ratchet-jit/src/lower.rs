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

use std::{error::Error, fmt};

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{
        ExtFuncData, ExternalName, Function, InstBuilder, UserExternalName, UserFuncName,
        condcodes::IntCC, types,
    },
    settings,
    verifier::{VerifierErrors, verify_function},
};
use ratchet_core::{
    BindingLowering, Cardinality, ExprFacts, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData,
    IrId, IrInlineCacheSiteId, IrKind, IrNode, Strictness, ThunkSharing,
    runtime_helper_call_signature, runtime_thunk_call_signature,
    syntax::{BinOpKind, Symbol},
};
use ratchet_value::value::Value;

use crate::{
    abi::{JitClifSignatureError, clif_signature_for_runtime_call},
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource},
    tier::JitTier,
};

mod arith_tree;

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

const AOS_ENV_GET_SYMBOL: &str = "aos_env_get";
const AOS_FORCE_SYMBOL: &str = "aos_force";
const AOS_APPLY_SYMBOL: &str = "aos_apply";
const AOS_HAS_ATTR_SYMBOL: &str = "aos_has_attr";
const AOS_SELECT_IC_SYMBOL: &str = "aos_select_ic";
const AOS_UPDATE_SYMBOL: &str = "aos_update";
const AOS_DEOPT_SYMBOL: &str = "aos_deopt";

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
        (Cardinality::Absent, Strictness::Strict) => {
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
/// Returns [`JitLowerError::Abi`] if the runtime thunk signature cannot be
/// lowered to a CLIF signature. Returns [`JitLowerError::Verifier`] if Cranelift
/// rejects the generated single-block function.
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
/// Returns [`JitLowerError::Abi`] if the runtime thunk signature cannot be
/// lowered to a CLIF signature. Returns [`JitLowerError::Verifier`] if Cranelift
/// rejects the generated single-block function.
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
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let entry_block = append_entry_block_params(&mut function);
    emit_value_return(&mut function, entry_block, value);
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
    let (function_slot, argument_slot) = apply_local_slots_for_root(arena, root)?;
    lower_apply_local_slots_thunk_body_with_name(
        function_slot,
        argument_slot,
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
    let (left_slot, right_slot) = update_local_slots_for_root(arena, root)?;
    lower_update_local_slots_thunk_body_with_name(
        left_slot,
        right_slot,
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

/// A failure while lowering safe metadata into CLIF.
#[derive(Debug)]
pub enum JitLowerError {
    /// Runtime ABI metadata could not be converted to a CLIF signature.
    Abi(JitClifSignatureError),
    /// Core no longer exposes the runtime helper signature required by lowering.
    MissingRuntimeHelperSignature {
        /// The helper symbol whose frozen runtime-call signature was missing.
        symbol_name: &'static str,
    },
    /// Cranelift rejected the generated CLIF function body.
    Verifier(VerifierErrors),
    /// The generated thunk function did not have the expected entry parameter.
    MissingEntryBlockParameter {
        /// The expected entry-block parameter index.
        index: usize,
    },
    /// A generated runtime call did not return the expected number of values.
    InvalidRuntimeCallResultArity {
        /// The helper symbol that was called.
        symbol_name: &'static str,
        /// The expected number of CLIF result values.
        expected: usize,
        /// The actual number of CLIF result values.
        actual: usize,
    },
    /// The requested IR root was not present in the arena.
    MissingIrNode {
        /// The missing IR root id.
        root: IrId,
    },
    /// The direct thunk-allocation body was not present in the arena.
    MissingIrBody {
        /// The missing IR body id.
        body: IrId,
    },
    /// The requested IR root is outside this precursor's supported subset.
    UnsupportedIrRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is outside this precursor's supported subset.
    UnsupportedIrBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// The requested IR root is not a local-slot read this precursor can lower.
    UnsupportedEnvRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is not a local-slot read this precursor can lower.
    UnsupportedEnvBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// The requested IR root is not a local-slot application this precursor can lower.
    UnsupportedApplyRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is not a local-slot application this precursor can lower.
    UnsupportedApplyBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// A direct application child was not present in the arena.
    MissingApplyChild {
        /// The missing application child id.
        child: IrId,
    },
    /// A direct application child is not a local-slot read this precursor can lower.
    UnsupportedApplyChild {
        /// The unsupported application child id.
        child: IrId,
        /// The unsupported child node kind.
        kind: IrKind,
    },
    /// The requested IR root is not an attr update this precursor can lower.
    UnsupportedUpdateRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is not an attr update this precursor can lower.
    UnsupportedUpdateBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// A binary operator root was not the attr update operator.
    UnsupportedUpdateOp {
        /// The unsupported binary operator.
        op: BinOpKind,
    },
    /// A direct attr update operand was not present in the arena.
    MissingUpdateOperand {
        /// The missing update operand id.
        operand: IrId,
    },
    /// A direct attr update operand is not a local-slot read this precursor can lower.
    UnsupportedUpdateOperand {
        /// The unsupported update operand id.
        operand: IrId,
        /// The unsupported operand node kind.
        kind: IrKind,
    },
    /// The requested IR root is not an attr lookup this precursor can lower.
    UnsupportedAttrRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is not an attr lookup this precursor can lower.
    UnsupportedAttrBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// The attr lookup receiver was not present in the arena.
    MissingAttrReceiver {
        /// The missing receiver node id.
        receiver: IrId,
    },
    /// The attr lookup receiver is not a local-slot read this precursor can lower.
    UnsupportedAttrReceiver {
        /// The unsupported receiver node id.
        receiver: IrId,
        /// The unsupported receiver node kind.
        kind: IrKind,
    },
    /// The attr lookup path was not present in the IR side table.
    MissingAttrPath {
        /// The missing attr-path id.
        path: IrAttrPathId,
    },
    /// The attr lookup path was outside the current single-segment subset.
    UnsupportedAttrPathLength {
        /// The unsupported attr-path id.
        path: IrAttrPathId,
        /// The number of segments found in the attr path.
        len: usize,
    },
    /// The attr lookup path contained a dynamic segment.
    UnsupportedAttrPathSegment {
        /// The unsupported attr-path id.
        path: IrAttrPathId,
        /// The unsupported segment index.
        index: usize,
        /// The unsupported segment.
        segment: IrAttrPathSegment,
    },
    /// Static attr selection with an `or` default is not lowered yet.
    UnsupportedSelectDefault {
        /// The lowered default thunk node.
        default: IrId,
    },
    /// The requested node is not a thunk allocation fact planning can consume.
    UnsupportedThunkFactNode {
        /// The requested node id.
        id: IrId,
        /// The unsupported node kind.
        kind: IrKind,
    },
    /// The IR fact table does not match the arena node count.
    MismatchedIrFactTable {
        /// The number of nodes in the arena.
        node_count: usize,
        /// The number of fact records attached to the IR.
        fact_count: usize,
    },
    /// A thunk allocation points at itself as its body.
    SelfReferentialThunkBody {
        /// The self-referential thunk-allocation node.
        thunk: IrId,
    },
    /// A literal IR node carried payload data that did not match its kind.
    MismatchedConstantData {
        /// The literal node kind.
        kind: IrKind,
        /// The unexpected payload data.
        data: IrData,
    },
    /// A direct thunk-allocation body carried payload data that did not match its kind.
    MismatchedBodyConstantData {
        /// The literal body node kind.
        kind: IrKind,
        /// The unexpected payload data.
        data: IrData,
    },
    /// A supported IR wrapper node carried payload data with the wrong shape.
    MismatchedIrNodeData {
        /// The wrapper node kind.
        kind: IrKind,
        /// The unexpected payload data.
        data: IrData,
        /// The expected payload shape.
        expected: &'static str,
    },
    /// A binary operator is not one the scalar arithmetic tree lowerer handles.
    UnsupportedArithOp {
        /// The unsupported binary operator.
        op: BinOpKind,
    },
    /// A scalar arithmetic tree operand was not present in the arena.
    MissingArithOperand {
        /// The missing operand id.
        operand: IrId,
    },
    /// A scalar arithmetic tree operand shape is not lowerable inline.
    UnsupportedArithOperand {
        /// The unsupported operand id.
        operand: IrId,
        /// The unsupported operand node kind.
        kind: IrKind,
    },
}

impl fmt::Display for JitLowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abi(error) => write!(formatter, "{error}"),
            Self::MissingRuntimeHelperSignature { symbol_name } => write!(
                formatter,
                "runtime helper {symbol_name:?} does not have a frozen call signature"
            ),
            Self::Verifier(error) => {
                write!(formatter, "generated CLIF failed verification: {error}")
            }
            Self::MissingEntryBlockParameter { index } => write!(
                formatter,
                "generated thunk function is missing entry-block parameter {index}"
            ),
            Self::InvalidRuntimeCallResultArity {
                symbol_name,
                expected,
                actual,
            } => write!(
                formatter,
                "runtime helper {symbol_name:?} produced {actual} CLIF results, expected {expected}"
            ),
            Self::MissingIrNode { root } => {
                write!(formatter, "IR root {root:?} is not present in the arena")
            }
            Self::MissingIrBody { body } => {
                write!(
                    formatter,
                    "IR thunk body {body:?} is not present in the arena"
                )
            }
            Self::UnsupportedIrRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by this lowerer"
                )
            }
            Self::UnsupportedIrBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by this lowerer"
                )
            }
            Self::UnsupportedEnvRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by the environment-access lowerer"
                )
            }
            Self::UnsupportedEnvBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by the environment-access lowerer"
                )
            }
            Self::UnsupportedApplyRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by the direct-apply lowerer"
                )
            }
            Self::UnsupportedApplyBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by the direct-apply lowerer"
                )
            }
            Self::MissingApplyChild { child } => {
                write!(
                    formatter,
                    "IR apply child {child:?} is not present in the arena"
                )
            }
            Self::UnsupportedApplyChild { child, kind } => {
                write!(
                    formatter,
                    "IR apply child {child:?} with kind {kind:?} is not a local-slot read this lowerer can consume"
                )
            }
            Self::UnsupportedUpdateRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by the local-slot attr-update lowerer"
                )
            }
            Self::UnsupportedUpdateBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by the local-slot attr-update lowerer"
                )
            }
            Self::UnsupportedUpdateOp { op } => {
                write!(
                    formatter,
                    "IR binary operator {op:?} is not supported by the local-slot attr-update lowerer"
                )
            }
            Self::MissingUpdateOperand { operand } => {
                write!(
                    formatter,
                    "IR attr-update operand {operand:?} is not present in the arena"
                )
            }
            Self::UnsupportedUpdateOperand { operand, kind } => {
                write!(
                    formatter,
                    "IR attr-update operand {operand:?} with kind {kind:?} is not a local-slot read this lowerer can consume"
                )
            }
            Self::UnsupportedAttrRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by the static attr-access lowerer"
                )
            }
            Self::UnsupportedAttrBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by the static attr-access lowerer"
                )
            }
            Self::MissingAttrReceiver { receiver } => {
                write!(
                    formatter,
                    "IR attr receiver {receiver:?} is not present in the arena"
                )
            }
            Self::UnsupportedAttrReceiver { receiver, kind } => {
                write!(
                    formatter,
                    "IR attr receiver {receiver:?} with kind {kind:?} is not a local-slot read this lowerer can consume"
                )
            }
            Self::MissingAttrPath { path } => {
                write!(formatter, "IR attr path {path:?} is not present")
            }
            Self::UnsupportedAttrPathLength { path, len } => {
                write!(
                    formatter,
                    "IR attr path {path:?} has {len} segments, expected exactly one static segment"
                )
            }
            Self::UnsupportedAttrPathSegment {
                path,
                index,
                segment,
            } => {
                write!(
                    formatter,
                    "IR attr path {path:?} segment {index} is unsupported by the static attr-access lowerer: {segment:?}"
                )
            }
            Self::UnsupportedSelectDefault { default } => {
                write!(
                    formatter,
                    "IR select default {default:?} is not supported by the static attr-access lowerer"
                )
            }
            Self::UnsupportedThunkFactNode { id, kind } => {
                write!(
                    formatter,
                    "IR node {id:?} with kind {kind:?} is not a thunk allocation fact planning can consume"
                )
            }
            Self::MismatchedIrFactTable {
                node_count,
                fact_count,
            } => {
                write!(
                    formatter,
                    "IR fact table has {fact_count} records for {node_count} arena nodes"
                )
            }
            Self::SelfReferentialThunkBody { thunk } => {
                write!(formatter, "IR thunk allocation {thunk:?} points at itself")
            }
            Self::MismatchedConstantData { kind, data } => write!(
                formatter,
                "IR root kind {kind:?} carried incompatible constant payload {data:?}"
            ),
            Self::MismatchedBodyConstantData { kind, data } => write!(
                formatter,
                "IR thunk body kind {kind:?} carried incompatible constant payload {data:?}"
            ),
            Self::MismatchedIrNodeData {
                kind,
                data,
                expected,
            } => write!(
                formatter,
                "IR root kind {kind:?} carried incompatible payload {data:?}, expected {expected}"
            ),
            Self::UnsupportedArithOp { op } => write!(
                formatter,
                "IR binary operator {op:?} is not supported by the scalar arithmetic tree lowerer"
            ),
            Self::MissingArithOperand { operand } => write!(
                formatter,
                "IR arithmetic operand {operand:?} is not present in the arena"
            ),
            Self::UnsupportedArithOperand { operand, kind } => write!(
                formatter,
                "IR arithmetic operand {operand:?} with kind {kind:?} is not lowerable inline"
            ),
        }
    }
}

impl Error for JitLowerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Abi(error) => Some(error),
            Self::Verifier(error) => Some(error),
            Self::MissingRuntimeHelperSignature { .. }
            | Self::MissingEntryBlockParameter { .. }
            | Self::InvalidRuntimeCallResultArity { .. }
            | Self::MissingIrNode { .. }
            | Self::MissingIrBody { .. }
            | Self::UnsupportedIrRoot { .. }
            | Self::UnsupportedIrBody { .. }
            | Self::UnsupportedEnvRoot { .. }
            | Self::UnsupportedEnvBody { .. }
            | Self::UnsupportedApplyRoot { .. }
            | Self::UnsupportedApplyBody { .. }
            | Self::MissingApplyChild { .. }
            | Self::UnsupportedApplyChild { .. }
            | Self::UnsupportedUpdateRoot { .. }
            | Self::UnsupportedUpdateBody { .. }
            | Self::UnsupportedUpdateOp { .. }
            | Self::MissingUpdateOperand { .. }
            | Self::UnsupportedUpdateOperand { .. }
            | Self::UnsupportedAttrRoot { .. }
            | Self::UnsupportedAttrBody { .. }
            | Self::MissingAttrReceiver { .. }
            | Self::UnsupportedAttrReceiver { .. }
            | Self::MissingAttrPath { .. }
            | Self::UnsupportedAttrPathLength { .. }
            | Self::UnsupportedAttrPathSegment { .. }
            | Self::UnsupportedSelectDefault { .. }
            | Self::UnsupportedThunkFactNode { .. }
            | Self::MismatchedIrFactTable { .. }
            | Self::SelfReferentialThunkBody { .. }
            | Self::MismatchedConstantData { .. }
            | Self::MismatchedBodyConstantData { .. }
            | Self::MismatchedIrNodeData { .. }
            | Self::UnsupportedArithOp { .. }
            | Self::MissingArithOperand { .. }
            | Self::UnsupportedArithOperand { .. } => None,
        }
    }
}

impl From<JitClifSignatureError> for JitLowerError {
    fn from(error: JitClifSignatureError) -> Self {
        Self::Abi(error)
    }
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
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
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
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
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

fn apply_local_slots_for_root(arena: &IrArena, root: IrId) -> Result<(u32, u32), JitLowerError> {
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

fn apply_local_slots_for_body(arena: &IrArena, node: IrNode) -> Result<(u32, u32), JitLowerError> {
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

fn apply_local_slots_for_node(arena: &IrArena, node: IrNode) -> Result<(u32, u32), JitLowerError> {
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

fn apply_local_child_slot(arena: &IrArena, child: IrId) -> Result<u32, JitLowerError> {
    let node = arena
        .node(child)
        .copied()
        .ok_or(JitLowerError::MissingApplyChild { child })?;

    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(slot),
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedApplyChild { child, kind }),
    }
}

fn update_local_slots_for_root(arena: &IrArena, root: IrId) -> Result<(u32, u32), JitLowerError> {
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

fn update_local_slots_for_body(arena: &IrArena, node: IrNode) -> Result<(u32, u32), JitLowerError> {
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

fn update_local_slots_for_node(arena: &IrArena, node: IrNode) -> Result<(u32, u32), JitLowerError> {
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

fn update_local_operand_slot(arena: &IrArena, operand: IrId) -> Result<u32, JitLowerError> {
    let node = arena
        .node(operand)
        .copied()
        .ok_or(JitLowerError::MissingUpdateOperand { operand })?;

    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(slot),
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedUpdateOperand { operand, kind }),
    }
}

#[derive(Clone, Copy)]
struct AttrLookup {
    receiver_slot: u32,
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
        receiver_slot: attr_receiver_slot(ir, receiver)?,
        symbol: single_static_attr_path_symbol(ir, path)?,
        site,
        default,
    })
}

fn attr_receiver_slot(ir: &Ir, receiver: IrId) -> Result<u32, JitLowerError> {
    let node = ir
        .arena
        .node(receiver)
        .copied()
        .ok_or(JitLowerError::MissingAttrReceiver { receiver })?;

    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(slot),
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
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
        IrKind::Apply => lower_apply_local_slots_ir_thunk_body_artifact(arena, root),
        IrKind::BinOp => arith_tree::lower_binop_ir_thunk_body_artifact(arena, root),
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
    let entry_block = append_entry_block_params(&mut function);
    emit_forced_env_get_return(&mut function, entry_block, env_get, force, slot)?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_apply_local_slots_thunk_body_with_name(
    function_slot: u32,
    argument_slot: u32,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let env_get = import_env_get_function(&mut function)?;
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
        apply,
        function_slot,
        argument_slot,
    )?;
    verify_clif_function(&function)?;
    Ok(function)
}

fn lower_update_local_slots_thunk_body_with_name(
    left_slot: u32,
    right_slot: u32,
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
        force,
        update,
        left_slot,
        right_slot,
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
    let force = import_runtime_helper_function(
        &mut function,
        AOS_FORCE_SYMBOL,
        clif_external_name_for_aos_force(),
    )?;
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
                force,
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
                force,
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
            force,
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
    value: Value,
) {
    let tag_word = value.tag() as u64;
    let payload_word = value.payload_bits();
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let tag = cursor.ins().iconst(types::I64, tag_word as i64);
    let payload = cursor.ins().iconst(types::I64, payload_word as i64);
    cursor.ins().return_(&[tag, payload]);
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

    if results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ENV_GET_SYMBOL,
            expected: 2,
            actual: results.len(),
        });
    }

    cursor.ins().return_(&results);
    Ok(())
}

fn emit_forced_env_get_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    force: cranelift_codegen::ir::FuncRef,
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
    let slot = cursor.ins().iconst(types::I32, i64::from(slot));
    let env_get_call = cursor.ins().call(env_get, &[env, slot]);
    let env_get_results = cursor.func.dfg.inst_results(env_get_call).to_vec();

    if env_get_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ENV_GET_SYMBOL,
            expected: 2,
            actual: env_get_results.len(),
        });
    }

    let force_call = cursor
        .ins()
        .call(force, &[rt, env_get_results[0], env_get_results[1]]);
    let force_results = cursor.func.dfg.inst_results(force_call).to_vec();

    if force_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_FORCE_SYMBOL,
            expected: 2,
            actual: force_results.len(),
        });
    }

    cursor.ins().return_(&force_results);
    Ok(())
}

fn emit_apply_local_slots_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    apply: cranelift_codegen::ir::FuncRef,
    function_slot: u32,
    argument_slot: u32,
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
    let function_slot = cursor.ins().iconst(types::I32, i64::from(function_slot));
    let function_env_get_call = cursor.ins().call(env_get, &[env, function_slot]);
    let function_env_get_results = cursor.func.dfg.inst_results(function_env_get_call).to_vec();

    if function_env_get_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ENV_GET_SYMBOL,
            expected: 2,
            actual: function_env_get_results.len(),
        });
    }

    let argument_slot = cursor.ins().iconst(types::I32, i64::from(argument_slot));
    let argument_env_get_call = cursor.ins().call(env_get, &[env, argument_slot]);
    let argument_env_get_results = cursor.func.dfg.inst_results(argument_env_get_call).to_vec();

    if argument_env_get_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ENV_GET_SYMBOL,
            expected: 2,
            actual: argument_env_get_results.len(),
        });
    }

    let apply_call = cursor.ins().call(
        apply,
        &[
            rt,
            function_env_get_results[0],
            function_env_get_results[1],
            argument_env_get_results[0],
            argument_env_get_results[1],
        ],
    );
    let apply_results = cursor.func.dfg.inst_results(apply_call).to_vec();

    if apply_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_APPLY_SYMBOL,
            expected: 2,
            actual: apply_results.len(),
        });
    }

    cursor.ins().return_(&apply_results);
    Ok(())
}

fn emit_update_local_slots_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    force: cranelift_codegen::ir::FuncRef,
    update: cranelift_codegen::ir::FuncRef,
    left_slot: u32,
    right_slot: u32,
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

    let left_slot = cursor.ins().iconst(types::I32, i64::from(left_slot));
    let left_env_get_call = cursor.ins().call(env_get, &[env, left_slot]);
    let left_env_get_results = cursor.func.dfg.inst_results(left_env_get_call).to_vec();

    if left_env_get_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ENV_GET_SYMBOL,
            expected: 2,
            actual: left_env_get_results.len(),
        });
    }

    let left_force_call = cursor.ins().call(
        force,
        &[rt, left_env_get_results[0], left_env_get_results[1]],
    );
    let left_force_results = cursor.func.dfg.inst_results(left_force_call).to_vec();

    if left_force_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_FORCE_SYMBOL,
            expected: 2,
            actual: left_force_results.len(),
        });
    }

    let right_slot = cursor.ins().iconst(types::I32, i64::from(right_slot));
    let right_env_get_call = cursor.ins().call(env_get, &[env, right_slot]);
    let right_env_get_results = cursor.func.dfg.inst_results(right_env_get_call).to_vec();

    if right_env_get_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ENV_GET_SYMBOL,
            expected: 2,
            actual: right_env_get_results.len(),
        });
    }

    let right_force_call = cursor.ins().call(
        force,
        &[rt, right_env_get_results[0], right_env_get_results[1]],
    );
    let right_force_results = cursor.func.dfg.inst_results(right_force_call).to_vec();

    if right_force_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_FORCE_SYMBOL,
            expected: 2,
            actual: right_force_results.len(),
        });
    }

    let update_call = cursor.ins().call(
        update,
        &[
            rt,
            left_force_results[0],
            left_force_results[1],
            right_force_results[0],
            right_force_results[1],
        ],
    );
    let update_results = cursor.func.dfg.inst_results(update_call).to_vec();

    if update_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_UPDATE_SYMBOL,
            expected: 2,
            actual: update_results.len(),
        });
    }

    cursor.ins().return_(&update_results);
    Ok(())
}

fn emit_attr_lookup_local_slot_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    force: cranelift_codegen::ir::FuncRef,
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
    let slot = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.receiver_slot));
    let env_get_call = cursor.ins().call(env_get, &[env, slot]);
    let env_get_results = cursor.func.dfg.inst_results(env_get_call).to_vec();

    if env_get_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ENV_GET_SYMBOL,
            expected: 2,
            actual: env_get_results.len(),
        });
    }

    let force_call = cursor
        .ins()
        .call(force, &[rt, env_get_results[0], env_get_results[1]]);
    let force_results = cursor.func.dfg.inst_results(force_call).to_vec();

    if force_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_FORCE_SYMBOL,
            expected: 2,
            actual: force_results.len(),
        });
    }

    let symbol = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.symbol.as_u32()));
    let site = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.site.as_u32()));
    let attr_call = cursor.ins().call(
        attr_helper,
        &[rt, force_results[0], force_results[1], symbol, site],
    );
    let attr_results = cursor.func.dfg.inst_results(attr_call).to_vec();

    if attr_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: lowering.symbol_name(),
            expected: 2,
            actual: attr_results.len(),
        });
    }

    cursor.ins().return_(&attr_results);
    Ok(())
}

fn emit_attr_select_default_local_slot_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    force: cranelift_codegen::ir::FuncRef,
    has_attr: cranelift_codegen::ir::FuncRef,
    select_ic: cranelift_codegen::ir::FuncRef,
    lookup: AttrLookup,
    default_value: Value,
) -> Result<(), JitLowerError> {
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
    let slot = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.receiver_slot));
    let env_get_call = cursor.ins().call(env_get, &[env, slot]);
    let env_get_results = cursor.func.dfg.inst_results(env_get_call).to_vec();

    if env_get_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ENV_GET_SYMBOL,
            expected: 2,
            actual: env_get_results.len(),
        });
    }

    let force_call = cursor
        .ins()
        .call(force, &[rt, env_get_results[0], env_get_results[1]]);
    let force_results = cursor.func.dfg.inst_results(force_call).to_vec();

    if force_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_FORCE_SYMBOL,
            expected: 2,
            actual: force_results.len(),
        });
    }

    let symbol = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.symbol.as_u32()));
    let site = cursor
        .ins()
        .iconst(types::I32, i64::from(lookup.site.as_u32()));
    let has_attr_call = cursor.ins().call(
        has_attr,
        &[rt, force_results[0], force_results[1], symbol, site],
    );
    let has_attr_results = cursor.func.dfg.inst_results(has_attr_call).to_vec();

    if has_attr_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_HAS_ATTR_SYMBOL,
            expected: 2,
            actual: has_attr_results.len(),
        });
    }

    let is_present = cursor
        .ins()
        .icmp_imm(IntCC::NotEqual, has_attr_results[1], 0);
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
    let select_call = cursor.ins().call(
        select_ic,
        &[rt, force_results[0], force_results[1], symbol, site],
    );
    let select_results = cursor.func.dfg.inst_results(select_call).to_vec();

    if select_results.len() != 2 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_SELECT_IC_SYMBOL,
            expected: 2,
            actual: select_results.len(),
        });
    }
    cursor.ins().return_(&select_results);

    cursor.insert_block(default_block);
    let tag = cursor
        .ins()
        .iconst(types::I64, default_value.tag() as u64 as i64);
    let payload = cursor
        .ins()
        .iconst(types::I64, default_value.payload_bits() as i64);
    cursor.ins().return_(&[tag, payload]);

    Ok(())
}

fn verify_clif_function(function: &Function) -> Result<(), JitLowerError> {
    let flags = settings::Flags::new(settings::builder());
    verify_function(function, &flags).map_err(JitLowerError::Verifier)
}

#[cfg(test)]
mod tests {
    use cranelift_codegen::ir::{
        ExtFuncData, ExternalName, FuncRef, InstructionData, Opcode, Type, types,
    };
    use ratchet_core::{
        BindingLowering, Cardinality, EffectClass, Escape, Ir, IrFacts, IrNode, Strictness,
        ThunkSharing, lower, resolve,
        syntax::{Span, SymbolTable, parse_str},
    };
    use ratchet_value::value::ValueTag;

    use super::*;
    use crate::abi::clif_signature_for_runtime_call;

    #[test]
    fn constant_thunk_body_uses_frozen_thunk_signature() {
        let function =
            lower_constant_thunk_body(Value::null()).expect("constant null thunk body lowers");
        let expected_signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())
            .expect("thunk signature lowers");

        assert_eq!(function.name, UserFuncName::default());
        assert_eq!(function.signature, expected_signature);
        assert_eq!(
            entry_block_param_types(&function),
            param_types(&expected_signature)
        );
    }

    #[test]
    fn ir_root_function_name_uses_reserved_namespace_and_root_index() {
        let name = clif_name_for_ir_root(IrId::new(42));
        let user_name = name
            .get_user()
            .expect("IR root CLIF names use user-function metadata");

        assert_eq!(user_name.namespace, AOS_IR_ROOT_FUNCTION_NAMESPACE);
        assert_eq!(user_name.index, 42);
    }

    #[test]
    fn env_get_external_name_uses_reserved_namespace_and_index() {
        let name = clif_external_name_for_aos_env_get();

        assert_eq!(name.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
        assert_eq!(name.index, AOS_ENV_GET_FUNCTION_INDEX);
    }

    #[test]
    fn force_external_name_uses_reserved_namespace_and_index() {
        let name = clif_external_name_for_aos_force();

        assert_eq!(name.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
        assert_eq!(name.index, AOS_FORCE_FUNCTION_INDEX);
    }

    #[test]
    fn apply_external_name_uses_reserved_namespace_and_index() {
        let name = clif_external_name_for_aos_apply();

        assert_eq!(name.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
        assert_eq!(name.index, AOS_APPLY_FUNCTION_INDEX);
    }

    #[test]
    fn tier1_thunk_fact_decision_maps_core_fact_lattice() {
        let cases = [
            (
                ExprFacts::conservative(),
                BindingLowering::Thunk,
                ThunkSharing::Update,
                JitTier1ThunkFactDecision::AllocateUpdatingThunk,
            ),
            (
                ExprFacts {
                    strictness: Strictness::Strict,
                    cardinality: Cardinality::Many,
                    escape: Escape::Escapes,
                },
                BindingLowering::Eager,
                ThunkSharing::Update,
                JitTier1ThunkFactDecision::EvaluateEagerWhnf,
            ),
            (
                ExprFacts {
                    strictness: Strictness::Strict,
                    cardinality: Cardinality::Many,
                    escape: Escape::NoEscape,
                },
                BindingLowering::Scalar,
                ThunkSharing::Update,
                JitTier1ThunkFactDecision::EvaluateScalarValue,
            ),
            (
                ExprFacts {
                    strictness: Strictness::Strict,
                    cardinality: Cardinality::Absent,
                    escape: Escape::NoEscape,
                },
                BindingLowering::Scalar,
                ThunkSharing::Update,
                JitTier1ThunkFactDecision::AllocateUpdatingThunk,
            ),
            (
                ExprFacts {
                    strictness: Strictness::Unknown,
                    cardinality: Cardinality::Once,
                    escape: Escape::NoEscape,
                },
                BindingLowering::Thunk,
                ThunkSharing::SingleEntry,
                JitTier1ThunkFactDecision::AllocateSingleEntryThunk,
            ),
            (
                ExprFacts {
                    strictness: Strictness::Unknown,
                    cardinality: Cardinality::Absent,
                    escape: Escape::Escapes,
                },
                BindingLowering::Thunk,
                ThunkSharing::Omit,
                JitTier1ThunkFactDecision::OmitLazyBinding,
            ),
        ];

        for (facts, expected_lowering, expected_sharing, expected_decision) in cases {
            assert_eq!(facts.binding_lowering(), expected_lowering);
            assert_eq!(facts.thunk_sharing(), expected_sharing);
            assert_eq!(
                jit_tier1_thunk_fact_decision_for_facts(facts),
                expected_decision
            );
        }
    }

    #[test]
    fn tier1_thunk_fact_plan_reads_thunk_alloc_facts_without_lowering_clif() {
        let facts = ExprFacts {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Once,
            escape: Escape::NoEscape,
        };
        let ir = direct_thunk_ir_with_facts(facts);

        let plan = jit_tier1_thunk_fact_plan(&ir, IrId::new(1)).expect("thunk fact plan is built");

        assert_eq!(plan.thunk(), IrId::new(1));
        assert_eq!(plan.body(), IrId::new(0));
        assert_eq!(plan.facts(), facts);
        assert_eq!(plan.binding_lowering(), BindingLowering::Thunk);
        assert_eq!(plan.thunk_sharing(), ThunkSharing::SingleEntry);
        assert_eq!(
            plan.decision(),
            JitTier1ThunkFactDecision::AllocateSingleEntryThunk
        );
    }

    #[test]
    fn tier1_thunk_fact_plan_preserves_absent_strict_contradiction_guard() {
        let facts = ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Absent,
            escape: Escape::NoEscape,
        };
        let ir = direct_thunk_ir_with_facts(facts);

        let plan = jit_tier1_thunk_fact_plan(&ir, IrId::new(1)).expect("thunk fact plan is built");

        assert_eq!(plan.binding_lowering(), BindingLowering::Scalar);
        assert_eq!(plan.thunk_sharing(), ThunkSharing::Update);
        assert_eq!(
            plan.decision(),
            JitTier1ThunkFactDecision::AllocateUpdatingThunk
        );
    }

    #[test]
    fn tier1_thunk_fact_plan_rejects_malformed_thunk_nodes() {
        let missing_root_ir = minimal_ir(IrId::new(0), IrArena::new());
        let non_thunk_ir = minimal_ir(
            IrId::new(0),
            IrArena::from_raw_parts(
                vec![IrNode::new(
                    IrKind::Int,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Int(1),
                )],
                Vec::new(),
            ),
        );
        let missing_body_ir = minimal_ir(
            IrId::new(0),
            IrArena::from_raw_parts(
                vec![IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(9)),
                )],
                Vec::new(),
            ),
        );
        let malformed_payload_ir = minimal_ir(
            IrId::new(0),
            IrArena::from_raw_parts(
                vec![IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::None,
                )],
                Vec::new(),
            ),
        );
        let self_referential_ir = minimal_ir(
            IrId::new(0),
            IrArena::from_raw_parts(
                vec![IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                )],
                Vec::new(),
            ),
        );

        let missing_root_error = jit_tier1_thunk_fact_plan(&missing_root_ir, IrId::new(7))
            .expect_err("missing thunk node is rejected");
        let non_thunk_error = jit_tier1_thunk_fact_plan(&non_thunk_ir, IrId::new(0))
            .expect_err("non-thunk root is rejected");
        let missing_body_error = jit_tier1_thunk_fact_plan(&missing_body_ir, IrId::new(0))
            .expect_err("missing thunk body is rejected");
        let malformed_payload_error =
            jit_tier1_thunk_fact_plan(&malformed_payload_ir, IrId::new(0))
                .expect_err("malformed thunk payload is rejected");
        let self_referential_error = jit_tier1_thunk_fact_plan(&self_referential_ir, IrId::new(0))
            .expect_err("self-referential thunk body is rejected");

        assert!(
            matches!(missing_root_error, JitLowerError::MissingIrNode { root } if root == IrId::new(7))
        );
        assert!(matches!(
            non_thunk_error,
            JitLowerError::UnsupportedThunkFactNode {
                id,
                kind: IrKind::Int,
            } if id == IrId::new(0)
        ));
        assert!(
            matches!(missing_body_error, JitLowerError::MissingIrBody { body } if body == IrId::new(9))
        );
        assert!(matches!(
            malformed_payload_error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::ThunkAlloc,
                data: IrData::None,
                expected: "body node",
            }
        ));
        assert!(matches!(
            self_referential_error,
            JitLowerError::SelfReferentialThunkBody { thunk } if thunk == IrId::new(0)
        ));
    }

    #[test]
    fn tier1_thunk_fact_plan_rejects_fact_table_node_count_mismatch() {
        let arena = direct_thunk_arena();
        let mut facts = IrFacts::conservative(3);
        *facts
            .get_mut(IrId::new(1))
            .expect("overlong fixture still has a thunk fact slot") = ExprFacts {
            strictness: Strictness::Strict,
            cardinality: Cardinality::Many,
            escape: Escape::NoEscape,
        };
        let ir = Ir {
            root: IrId::new(1),
            arena,
            facts,
            symbols: SymbolTable::new(),
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        };

        let error = jit_tier1_thunk_fact_plan(&ir, IrId::new(1))
            .expect_err("fact table length mismatch is rejected");

        assert!(matches!(
            error,
            JitLowerError::MismatchedIrFactTable {
                node_count: 2,
                fact_count: 3,
            }
        ));
    }

    #[test]
    fn constant_thunk_body_artifact_records_smoke_metadata() {
        let artifact = lower_constant_thunk_body_artifact(Value::bool(false))
            .expect("constant bool thunk artifact lowers");

        assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
        assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
        assert_eq!(artifact.source(), JitClifArtifactSource::ConstantSmoke);
        assert_eq!(artifact.function_name(), &UserFuncName::default());
        assert_eq!(
            iconst_words(artifact.function()),
            vec![ValueTag::Bool as u64, Value::bool(false).payload_bits()]
        );

        let function = artifact.into_function();
        assert_eq!(function.name, UserFuncName::default());
    }

    #[test]
    fn constant_thunk_body_returns_int_value_words() {
        let function =
            lower_constant_thunk_body(Value::int(-7)).expect("constant int thunk body lowers");

        assert_eq!(
            iconst_words(&function),
            vec![ValueTag::Int as u64, Value::int(-7).payload_bits()]
        );
    }

    #[test]
    fn constant_thunk_body_returns_bool_and_null_value_words() {
        let bool_function =
            lower_constant_thunk_body(Value::bool(true)).expect("constant bool thunk body lowers");
        let null_function =
            lower_constant_thunk_body(Value::null()).expect("constant null thunk body lowers");

        assert_eq!(
            iconst_words(&bool_function),
            vec![ValueTag::Bool as u64, Value::bool(true).payload_bits()]
        );
        assert_eq!(
            iconst_words(&null_function),
            vec![ValueTag::Null as u64, Value::null().payload_bits()]
        );
    }

    #[test]
    fn constant_thunk_body_is_verified_clif_without_jit_module() {
        let function = lower_constant_thunk_body(Value::float(-13.25))
            .expect("constant float thunk body lowers");

        let emitted_constants = iconst_values(&function)
            .into_iter()
            .map(|(value, _word)| value)
            .collect::<Vec<_>>();
        assert_eq!(return_operands(&function), emitted_constants);
        assert_eq!(opcodes(&function).last(), Some(&Opcode::Return));
        verify_clif_function(&function).expect("lowered function verifies independently");
    }

    #[test]
    fn constant_ir_thunk_body_lowers_supported_literal_roots() {
        let cases = [
            (
                IrNode::new(
                    IrKind::Int,
                    Span::new(0, 2),
                    EffectClass::pure(),
                    IrData::Int(-9),
                ),
                Value::int(-9),
            ),
            (
                IrNode::new(
                    IrKind::Float,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::Float(2.5),
                ),
                Value::float(2.5),
            ),
            (
                IrNode::new(
                    IrKind::Bool,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::Bool(false),
                ),
                Value::bool(false),
            ),
            (
                IrNode::new(
                    IrKind::Null,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::None,
                ),
                Value::null(),
            ),
        ];

        for (node, expected_value) in cases {
            let arena = IrArena::from_raw_parts(vec![node], Vec::new());
            let function =
                lower_constant_ir_thunk_body(&arena, IrId::new(0)).expect("literal IR root lowers");

            assert_eq!(
                iconst_words(&function),
                vec![expected_value.tag() as u64, expected_value.payload_bits()]
            );
        }
    }

    #[test]
    fn constant_ir_thunk_body_lowers_direct_literal_thunk_alloc_root() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Int,
                    Span::new(4, 6),
                    EffectClass::pure(),
                    IrData::Int(17),
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let function = lower_constant_ir_thunk_body(&arena, IrId::new(1))
            .expect("direct literal thunk allocation lowers");

        assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
        assert_eq!(
            iconst_words(&function),
            vec![ValueTag::Int as u64, Value::int(17).payload_bits()]
        );
    }

    #[test]
    fn constant_ir_thunk_body_artifact_records_root_source() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Int,
                    Span::new(4, 6),
                    EffectClass::pure(),
                    IrData::Int(23),
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(1))
            .expect("direct literal thunk allocation artifact lowers");

        assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
        assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
        assert_eq!(
            artifact.source(),
            JitClifArtifactSource::IrRoot(IrId::new(1))
        );
        assert_eq!(
            artifact.function_name(),
            &clif_name_for_ir_root(IrId::new(1))
        );
        assert_eq!(
            iconst_words(artifact.function()),
            vec![ValueTag::Int as u64, Value::int(23).payload_bits()]
        );
    }

    #[test]
    fn constant_ir_thunk_body_rejects_missing_root() {
        let arena = IrArena::new();

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(7))
            .expect_err("missing root is rejected");

        assert!(matches!(error, JitLowerError::MissingIrNode { root } if root == IrId::new(7)));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_unsupported_root_kind() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("string root is not covered by the constant lowerer");

        assert!(matches!(error, JitLowerError::UnsupportedIrRoot { kind } if kind == IrKind::Str));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_mismatched_literal_payload() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("int root without int payload is malformed");

        assert!(matches!(
            error,
            JitLowerError::MismatchedConstantData {
                kind: IrKind::Int,
                data: IrData::None,
            }
        ));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_missing_thunk_body() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Node(IrId::new(9)),
            )],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("missing thunk body is rejected");

        assert!(matches!(error, JitLowerError::MissingIrBody { body } if body == IrId::new(9)));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_unsupported_thunk_body_kind() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Str,
                    Span::new(4, 9),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 9),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(1))
            .expect_err("unsupported thunk body kind is rejected");

        assert!(matches!(error, JitLowerError::UnsupportedIrBody { kind } if kind == IrKind::Str));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_mismatched_thunk_body_payload() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Int,
                    Span::new(4, 9),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 9),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(1))
            .expect_err("mismatched thunk body payload is rejected");

        assert!(matches!(
            error,
            JitLowerError::MismatchedBodyConstantData {
                kind: IrKind::Int,
                data: IrData::None,
            }
        ));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_malformed_thunk_alloc_payload() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("thunk allocation without body node is malformed");

        assert!(matches!(
            error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::ThunkAlloc,
                data: IrData::None,
                expected: "body node",
            }
        ));
    }

    #[test]
    fn constant_ir_root_thunk_body_lowers_real_literal_ir_artifacts() {
        let cases = [
            ("42", Value::int(42)),
            ("2.5", Value::float(2.5)),
            ("false", Value::bool(false)),
            ("null", Value::null()),
        ];

        for (source, expected_value) in cases {
            let ir = lowered_ir(source);
            let function =
                lower_constant_ir_root_thunk_body(&ir).expect("literal IR artifact lowers");

            assert_eq!(
                iconst_words(&function),
                vec![expected_value.tag() as u64, expected_value.payload_bits()]
            );
        }
    }

    #[test]
    fn constant_ir_root_thunk_body_uses_nonzero_artifact_root() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Str,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::Int,
                    Span::new(7, 9),
                    EffectClass::pure(),
                    IrData::Int(11),
                ),
            ],
            Vec::new(),
        );
        let ir = minimal_ir(IrId::new(1), arena);

        let function = lower_constant_ir_root_thunk_body(&ir).expect("nonzero literal root lowers");

        assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
        assert_eq!(
            iconst_words(&function),
            vec![ValueTag::Int as u64, Value::int(11).payload_bits()]
        );
    }

    #[test]
    fn constant_ir_root_thunk_body_artifact_records_nonzero_artifact_root() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Str,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::Int,
                    Span::new(7, 9),
                    EffectClass::pure(),
                    IrData::Int(13),
                ),
            ],
            Vec::new(),
        );
        let ir = minimal_ir(IrId::new(1), arena);

        let artifact =
            lower_constant_ir_root_thunk_body_artifact(&ir).expect("IR root artifact lowers");

        assert_eq!(
            artifact.source(),
            JitClifArtifactSource::IrRoot(IrId::new(1))
        );
        assert_eq!(
            artifact.function_name(),
            &clif_name_for_ir_root(IrId::new(1))
        );
        assert_eq!(
            iconst_words(artifact.function()),
            vec![ValueTag::Int as u64, Value::int(13).payload_bits()]
        );
    }

    #[test]
    fn constant_ir_root_thunk_body_rejects_missing_artifact_root() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            )],
            Vec::new(),
        );
        let ir = minimal_ir(IrId::new(5), arena);

        let error =
            lower_constant_ir_root_thunk_body(&ir).expect_err("missing artifact root is rejected");

        assert!(matches!(error, JitLowerError::MissingIrNode { root } if root == IrId::new(5)));
    }

    #[test]
    fn env_get_ir_thunk_body_imports_env_helper_signature() {
        let arena = IrArena::from_raw_parts(vec![local_var_node(3)], Vec::new());

        let function =
            lower_env_get_ir_thunk_body(&arena, IrId::new(0)).expect("local var root lowers");
        let (_func_ref, import) = single_imported_function(&function);
        let expected_signature = clif_signature_for_runtime_call(
            runtime_helper_call_signature(AOS_ENV_GET_SYMBOL)
                .expect("env-get helper signature is core-owned"),
        )
        .expect("env-get signature lowers to CLIF");

        assert_eq!(function.name, clif_name_for_ir_root(IrId::new(0)));
        assert_eq!(
            imported_user_external_name(&function, import),
            clif_external_name_for_aos_env_get()
        );
        assert_eq!(
            function.dfg.signatures[import.signature],
            expected_signature
        );
        assert!(!import.colocated);
    }

    #[test]
    fn env_get_ir_thunk_body_calls_env_helper_with_entry_env_and_slot() {
        let arena = IrArena::from_raw_parts(vec![local_var_node(5)], Vec::new());

        let function =
            lower_env_get_ir_thunk_body(&arena, IrId::new(0)).expect("local var root lowers");
        let (env_get, _import) = single_imported_function(&function);
        let call = single_call_inst(&function);
        let InstructionData::Call { func_ref, .. } = function.dfg.insts[call] else {
            panic!("lowered env-get function emits a direct call");
        };

        assert_eq!(func_ref, env_get);
        assert_eq!(
            opcodes(&function),
            vec![Opcode::Iconst, Opcode::Call, Opcode::Return]
        );
        assert_eq!(
            function.dfg.inst_args(call)[0],
            entry_block_values(&function)[1]
        );
        assert_eq!(
            function.dfg.value_type(function.dfg.inst_args(call)[1]),
            types::I32
        );
        assert_eq!(iconst_words(&function), vec![5]);
        assert_eq!(return_operands(&function), function.dfg.inst_results(call));
        verify_clif_function(&function).expect("env-get function verifies independently");
    }

    #[test]
    fn env_get_ir_thunk_body_lowers_direct_local_thunk_alloc_root() {
        let arena = IrArena::from_raw_parts(
            vec![
                local_var_node(7),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let artifact = lower_env_get_ir_thunk_body_artifact(&arena, IrId::new(1))
            .expect("direct local thunk allocation lowers");

        assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
        assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
        assert_eq!(
            artifact.source(),
            JitClifArtifactSource::IrRoot(IrId::new(1))
        );
        assert_eq!(
            artifact.function_name(),
            &clif_name_for_ir_root(IrId::new(1))
        );
        assert_eq!(iconst_words(artifact.function()), vec![7]);
    }

    #[test]
    fn env_get_ir_thunk_body_rejects_mismatched_local_payload() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let error = lower_env_get_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("local var without local payload is malformed");

        assert!(matches!(
            error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::LocalVar,
                data: IrData::None,
                expected: "local slot payload",
            }
        ));
    }

    #[test]
    fn env_get_ir_thunk_body_rejects_unsupported_roots_and_bodies() {
        let root_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            )],
            Vec::new(),
        );
        let body_arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Int,
                    Span::new(1, 2),
                    EffectClass::pure(),
                    IrData::Int(1),
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 2),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let root_error = lower_env_get_ir_thunk_body(&root_arena, IrId::new(0))
            .expect_err("non-local root is not covered by env-get lowering");
        let body_error = lower_env_get_ir_thunk_body(&body_arena, IrId::new(1))
            .expect_err("non-local thunk body is not covered by env-get lowering");

        assert!(
            matches!(root_error, JitLowerError::UnsupportedEnvRoot { kind } if kind == IrKind::Int)
        );
        assert!(
            matches!(body_error, JitLowerError::UnsupportedEnvBody { kind } if kind == IrKind::Int)
        );
    }

    #[test]
    fn env_get_ir_thunk_body_rejects_missing_thunk_body() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(9)),
            )],
            Vec::new(),
        );

        let error = lower_env_get_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("missing local thunk body is rejected");

        assert!(matches!(error, JitLowerError::MissingIrBody { body } if body == IrId::new(9)));
    }

    #[test]
    fn env_get_ir_thunk_body_rejects_malformed_thunk_alloc_payload() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let error = lower_env_get_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("local thunk allocation without body node is malformed");

        assert!(matches!(
            error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::ThunkAlloc,
                data: IrData::None,
                expected: "body node",
            }
        ));
    }

    #[test]
    fn forced_env_get_ir_thunk_body_imports_env_get_and_force_signatures() {
        let arena = IrArena::from_raw_parts(vec![local_var_node(11)], Vec::new());

        let function = lower_forced_env_get_ir_thunk_body(&arena, IrId::new(0))
            .expect("forced local var root lowers");
        let env_get_import = imported_function_by_user_external_name(
            &function,
            clif_external_name_for_aos_env_get(),
        );
        let force_import =
            imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
        let expected_env_get_signature = clif_signature_for_runtime_call(
            runtime_helper_call_signature(AOS_ENV_GET_SYMBOL)
                .expect("env-get helper signature is core-owned"),
        )
        .expect("env-get signature lowers to CLIF");
        let expected_force_signature = clif_signature_for_runtime_call(
            runtime_helper_call_signature(AOS_FORCE_SYMBOL)
                .expect("force helper signature is core-owned"),
        )
        .expect("force signature lowers to CLIF");

        assert_eq!(
            function.dfg.signatures[env_get_import.1.signature],
            expected_env_get_signature
        );
        assert_eq!(
            function.dfg.signatures[force_import.1.signature],
            expected_force_signature
        );
    }

    #[test]
    fn forced_env_get_ir_thunk_body_calls_env_get_then_force_with_entry_rt() {
        let arena = IrArena::from_raw_parts(vec![local_var_node(13)], Vec::new());

        let function = lower_forced_env_get_ir_thunk_body(&arena, IrId::new(0))
            .expect("forced local var root lowers");
        let (env_get, _) = imported_function_by_user_external_name(
            &function,
            clif_external_name_for_aos_env_get(),
        );
        let (force, _) =
            imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
        let calls = call_insts(&function);
        assert_eq!(calls.len(), 2);
        let env_get_call = calls[0];
        let force_call = calls[1];
        let InstructionData::Call { func_ref, .. } = function.dfg.insts[env_get_call] else {
            panic!("forced env-get function emits env-get call first");
        };
        assert_eq!(func_ref, env_get);
        let InstructionData::Call { func_ref, .. } = function.dfg.insts[force_call] else {
            panic!("forced env-get function emits force call second");
        };
        assert_eq!(func_ref, force);

        assert_eq!(
            opcodes(&function),
            vec![Opcode::Iconst, Opcode::Call, Opcode::Call, Opcode::Return]
        );
        assert_eq!(
            function.dfg.inst_args(env_get_call)[0],
            entry_block_values(&function)[1]
        );
        assert_eq!(
            function
                .dfg
                .value_type(function.dfg.inst_args(env_get_call)[1]),
            types::I32
        );
        assert_eq!(iconst_words(&function), vec![13]);
        assert_eq!(
            function.dfg.inst_args(force_call),
            &[
                entry_block_values(&function)[0],
                function.dfg.inst_results(env_get_call)[0],
                function.dfg.inst_results(env_get_call)[1],
            ]
        );
        assert_eq!(
            return_operands(&function),
            function.dfg.inst_results(force_call)
        );
        verify_clif_function(&function).expect("forced env-get function verifies independently");
    }

    #[test]
    fn forced_env_get_ir_thunk_body_lowers_direct_local_thunk_alloc_root() {
        let arena = IrArena::from_raw_parts(
            vec![
                local_var_node(17),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let artifact = lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(1))
            .expect("direct forced local thunk allocation lowers");

        assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
        assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
        assert_eq!(
            artifact.source(),
            JitClifArtifactSource::IrRoot(IrId::new(1))
        );
        assert_eq!(
            artifact.function_name(),
            &clif_name_for_ir_root(IrId::new(1))
        );
        assert_eq!(
            artifact.function().dfg.ext_funcs.len(),
            2,
            "forced env-get artifacts import env-get and force"
        );
    }

    #[test]
    fn apply_local_slots_ir_thunk_body_imports_env_get_and_apply_signatures() {
        let arena = apply_local_slots_arena(2, 5);

        let function = lower_apply_local_slots_ir_thunk_body(&arena, IrId::new(2))
            .expect("direct local-slot apply lowers");
        let env_get_import = imported_function_by_user_external_name(
            &function,
            clif_external_name_for_aos_env_get(),
        );
        let apply_import =
            imported_function_by_user_external_name(&function, clif_external_name_for_aos_apply());
        let expected_env_get_signature = clif_signature_for_runtime_call(
            runtime_helper_call_signature(AOS_ENV_GET_SYMBOL)
                .expect("env-get helper signature is core-owned"),
        )
        .expect("env-get signature lowers to CLIF");
        let expected_apply_signature = clif_signature_for_runtime_call(
            runtime_helper_call_signature(AOS_APPLY_SYMBOL)
                .expect("apply helper signature is core-owned"),
        )
        .expect("apply signature lowers to CLIF");

        assert_eq!(
            function.dfg.signatures[env_get_import.1.signature],
            expected_env_get_signature
        );
        assert_eq!(
            function.dfg.signatures[apply_import.1.signature],
            expected_apply_signature
        );
    }

    #[test]
    fn apply_local_slots_ir_thunk_body_reads_function_and_argument_then_calls_apply() {
        let arena = apply_local_slots_arena(3, 8);

        let function = lower_apply_local_slots_ir_thunk_body(&arena, IrId::new(2))
            .expect("direct local-slot apply lowers");
        let (env_get, _) = imported_function_by_user_external_name(
            &function,
            clif_external_name_for_aos_env_get(),
        );
        let (apply, _) =
            imported_function_by_user_external_name(&function, clif_external_name_for_aos_apply());
        let calls = call_insts(&function);
        assert_eq!(calls.len(), 3);
        let function_env_get_call = calls[0];
        let argument_env_get_call = calls[1];
        let apply_call = calls[2];
        let InstructionData::Call { func_ref, .. } = function.dfg.insts[function_env_get_call]
        else {
            panic!("apply lowerer emits function env-get call first");
        };
        assert_eq!(func_ref, env_get);
        let InstructionData::Call { func_ref, .. } = function.dfg.insts[argument_env_get_call]
        else {
            panic!("apply lowerer emits argument env-get call second");
        };
        assert_eq!(func_ref, env_get);
        let InstructionData::Call { func_ref, .. } = function.dfg.insts[apply_call] else {
            panic!("apply lowerer emits apply call third");
        };
        assert_eq!(func_ref, apply);

        assert_eq!(
            opcodes(&function),
            vec![
                Opcode::Iconst,
                Opcode::Call,
                Opcode::Iconst,
                Opcode::Call,
                Opcode::Call,
                Opcode::Return,
            ]
        );
        assert_eq!(iconst_words(&function), vec![3, 8]);
        assert_eq!(
            function.dfg.inst_args(function_env_get_call)[0],
            entry_block_values(&function)[1]
        );
        assert_eq!(
            function.dfg.inst_args(argument_env_get_call)[0],
            entry_block_values(&function)[1]
        );
        assert_eq!(
            function
                .dfg
                .value_type(function.dfg.inst_args(function_env_get_call)[1]),
            types::I32
        );
        assert_eq!(
            function
                .dfg
                .value_type(function.dfg.inst_args(argument_env_get_call)[1]),
            types::I32
        );
        assert_eq!(
            function.dfg.inst_args(apply_call),
            &[
                entry_block_values(&function)[0],
                function.dfg.inst_results(function_env_get_call)[0],
                function.dfg.inst_results(function_env_get_call)[1],
                function.dfg.inst_results(argument_env_get_call)[0],
                function.dfg.inst_results(argument_env_get_call)[1],
            ]
        );
        assert_eq!(
            return_operands(&function),
            function.dfg.inst_results(apply_call)
        );
        verify_clif_function(&function).expect("apply function verifies independently");
    }

    #[test]
    fn apply_local_slots_ir_thunk_body_lowers_direct_apply_thunk_alloc_root() {
        let arena = apply_local_slots_thunk_arena(13, 21);

        let artifact = lower_apply_local_slots_ir_thunk_body_artifact(&arena, IrId::new(3))
            .expect("direct apply thunk allocation lowers");

        assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
        assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
        assert_eq!(
            artifact.source(),
            JitClifArtifactSource::IrRoot(IrId::new(3))
        );
        assert_eq!(
            artifact.function_name(),
            &clif_name_for_ir_root(IrId::new(3))
        );
        assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_apply(),
        );
        assert_eq!(iconst_words(artifact.function()), vec![13, 21]);
    }

    #[test]
    fn apply_local_slots_ir_thunk_body_rejects_unsupported_roots_and_bodies() {
        let root_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            )],
            Vec::new(),
        );
        let body_arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Int,
                    Span::new(1, 2),
                    EffectClass::pure(),
                    IrData::Int(1),
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 2),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let root_error = lower_apply_local_slots_ir_thunk_body(&root_arena, IrId::new(0))
            .expect_err("non-apply root is not covered by apply lowering");
        let body_error = lower_apply_local_slots_ir_thunk_body(&body_arena, IrId::new(1))
            .expect_err("non-apply thunk body is not covered by apply lowering");

        assert!(
            matches!(root_error, JitLowerError::UnsupportedApplyRoot { kind } if kind == IrKind::Int)
        );
        assert!(
            matches!(body_error, JitLowerError::UnsupportedApplyBody { kind } if kind == IrKind::Int)
        );
    }

    #[test]
    fn apply_local_slots_ir_thunk_body_rejects_malformed_wrappers() {
        let missing_body_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(9)),
            )],
            Vec::new(),
        );
        let malformed_wrapper_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let missing_body_error =
            lower_apply_local_slots_ir_thunk_body(&missing_body_arena, IrId::new(0))
                .expect_err("missing apply thunk body is rejected");
        let malformed_wrapper_error =
            lower_apply_local_slots_ir_thunk_body(&malformed_wrapper_arena, IrId::new(0))
                .expect_err("apply thunk allocation without body node is malformed");

        assert!(
            matches!(missing_body_error, JitLowerError::MissingIrBody { body } if body == IrId::new(9))
        );
        assert!(matches!(
            malformed_wrapper_error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::ThunkAlloc,
                data: IrData::None,
                expected: "body node",
            }
        ));
    }

    #[test]
    fn apply_local_slots_ir_thunk_body_rejects_malformed_apply_payloads_and_children() {
        let malformed_payload_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Apply,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let missing_child_arena = IrArena::from_raw_parts(
            vec![
                local_var_node(1),
                IrNode::new(
                    IrKind::Apply,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(9),
                    },
                ),
            ],
            Vec::new(),
        );
        let unsupported_child_arena = IrArena::from_raw_parts(
            vec![
                local_var_node(1),
                IrNode::new(
                    IrKind::Int,
                    Span::new(2, 3),
                    EffectClass::pure(),
                    IrData::Int(2),
                ),
                IrNode::new(
                    IrKind::Apply,
                    Span::new(0, 3),
                    EffectClass::pure(),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(1),
                    },
                ),
            ],
            Vec::new(),
        );
        let malformed_child_arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::None,
                ),
                local_var_node(2),
                IrNode::new(
                    IrKind::Apply,
                    Span::new(0, 2),
                    EffectClass::pure(),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(1),
                    },
                ),
            ],
            Vec::new(),
        );

        let malformed_payload_error =
            lower_apply_local_slots_ir_thunk_body(&malformed_payload_arena, IrId::new(0))
                .expect_err("apply without pair payload is rejected");
        let missing_child_error =
            lower_apply_local_slots_ir_thunk_body(&missing_child_arena, IrId::new(1))
                .expect_err("apply with missing child is rejected");
        let unsupported_child_error =
            lower_apply_local_slots_ir_thunk_body(&unsupported_child_arena, IrId::new(2))
                .expect_err("apply with non-local child is rejected");
        let malformed_child_error =
            lower_apply_local_slots_ir_thunk_body(&malformed_child_arena, IrId::new(2))
                .expect_err("apply with malformed local child is rejected");

        assert!(matches!(
            malformed_payload_error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::Apply,
                data: IrData::None,
                expected: "application pair payload",
            }
        ));
        assert!(
            matches!(missing_child_error, JitLowerError::MissingApplyChild { child } if child == IrId::new(9))
        );
        assert!(matches!(
            unsupported_child_error,
            JitLowerError::UnsupportedApplyChild {
                child,
                kind: IrKind::Int,
            } if child == IrId::new(1)
        ));
        assert!(matches!(
            malformed_child_error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::LocalVar,
                data: IrData::None,
                expected: "local slot payload",
            }
        ));
    }

    #[test]
    fn tier1_ir_thunk_body_artifact_selects_literal_and_env_get_paths() {
        let literal_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Bool,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(true),
            )],
            Vec::new(),
        );
        let literal_artifact = lower_tier1_ir_thunk_body_artifact(&literal_arena, IrId::new(0))
            .expect("tier-1 selector lowers literal root");

        assert_eq!(
            iconst_words(literal_artifact.function()),
            vec![ValueTag::Bool as u64, Value::bool(true).payload_bits()]
        );
        assert!(literal_artifact.function().dfg.ext_funcs.is_empty());

        let local_arena = IrArena::from_raw_parts(vec![local_var_node(19)], Vec::new());
        let local_artifact = lower_tier1_ir_thunk_body_artifact(&local_arena, IrId::new(0))
            .expect("tier-1 selector lowers local root through env-get");

        assert_eq!(local_artifact.function().dfg.ext_funcs.len(), 1);
        imported_function_by_user_external_name(
            local_artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        assert_eq!(iconst_words(local_artifact.function()), vec![19]);
    }

    #[test]
    fn tier1_ir_thunk_body_lowers_wrapped_local_body() {
        let arena = IrArena::from_raw_parts(
            vec![
                local_var_node(23),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let function = lower_tier1_ir_thunk_body(&arena, IrId::new(1))
            .expect("tier-1 selector lowers wrapped local root");

        assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
        assert_eq!(function.dfg.ext_funcs.len(), 1);
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
        assert_eq!(iconst_words(&function), vec![23]);
    }

    #[test]
    fn tier1_ir_thunk_body_artifact_selects_apply_path() {
        let arena = apply_local_slots_arena(41, 43);

        let artifact = lower_tier1_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("tier-1 selector lowers local-slot apply");

        assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_apply(),
        );
        assert_eq!(iconst_words(artifact.function()), vec![41, 43]);
    }

    #[test]
    fn tier1_ir_thunk_body_artifact_selects_wrapped_apply_path() {
        let arena = apply_local_slots_thunk_arena(44, 45);

        let artifact = lower_tier1_ir_thunk_body_artifact(&arena, IrId::new(3))
            .expect("tier-1 selector lowers wrapped local-slot apply");

        assert_eq!(
            artifact.function_name(),
            &clif_name_for_ir_root(IrId::new(3))
        );
        assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_apply(),
        );
        assert_eq!(iconst_words(artifact.function()), vec![44, 45]);
    }

    #[test]
    fn force_aware_tier1_ir_thunk_body_artifact_preserves_literals_and_forces_local_slots() {
        let literal_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Int(29),
            )],
            Vec::new(),
        );
        let literal_artifact =
            lower_force_aware_tier1_ir_thunk_body_artifact(&literal_arena, IrId::new(0))
                .expect("force-aware selector preserves literal lowering");

        assert_eq!(
            iconst_words(literal_artifact.function()),
            vec![ValueTag::Int as u64, Value::int(29).payload_bits()]
        );
        assert!(literal_artifact.function().dfg.ext_funcs.is_empty());

        let local_arena = IrArena::from_raw_parts(vec![local_var_node(31)], Vec::new());
        let local_artifact =
            lower_force_aware_tier1_ir_thunk_body_artifact(&local_arena, IrId::new(0))
                .expect("force-aware selector lowers local root through env-get and force");

        assert_eq!(local_artifact.function().dfg.ext_funcs.len(), 2);
        imported_function_by_user_external_name(
            local_artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            local_artifact.function(),
            clif_external_name_for_aos_force(),
        );
        assert_eq!(iconst_words(local_artifact.function()), vec![31]);
    }

    #[test]
    fn force_aware_tier1_ir_thunk_body_artifact_selects_apply_without_extra_force() {
        let arena = apply_local_slots_arena(47, 53);

        let artifact = lower_force_aware_tier1_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("force-aware selector lowers local-slot apply through apply helper");

        assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_apply(),
        );
        assert_eq!(iconst_words(artifact.function()), vec![47, 53]);
    }

    #[test]
    fn force_aware_tier1_ir_thunk_body_artifact_selects_wrapped_apply_without_extra_force() {
        let arena = apply_local_slots_thunk_arena(54, 55);

        let artifact = lower_force_aware_tier1_ir_thunk_body_artifact(&arena, IrId::new(3))
            .expect("force-aware selector lowers wrapped local-slot apply through apply helper");

        assert_eq!(
            artifact.function_name(),
            &clif_name_for_ir_root(IrId::new(3))
        );
        assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_apply(),
        );
        assert_eq!(iconst_words(artifact.function()), vec![54, 55]);
    }

    #[test]
    fn full_ir_tier1_selectors_accept_static_select_roots() {
        let ir = static_select_ir(61);

        let Err(arena_only_error) =
            lower_force_aware_tier1_ir_thunk_body_artifact(&ir.arena, ir.root)
        else {
            panic!("arena-only force-aware selector should reject select roots");
        };
        assert!(matches!(
            arena_only_error,
            JitLowerError::UnsupportedIrRoot {
                kind: IrKind::Select
            } | JitLowerError::UnsupportedIrBody {
                kind: IrKind::Select
            }
        ));

        let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
            .expect("full-IR selector lowers static select root");
        assert_eq!(artifact.function().dfg.ext_funcs.len(), 3);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_force(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_select_ic(),
        );

        let force_aware_artifact =
            lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
                .expect("full-IR force-aware selector lowers static select root");
        assert_eq!(
            force_aware_artifact.function().dfg.ext_funcs.len(),
            artifact.function().dfg.ext_funcs.len()
        );
        imported_function_by_user_external_name(
            force_aware_artifact.function(),
            clif_external_name_for_aos_select_ic(),
        );
    }

    #[test]
    fn full_ir_tier1_selectors_accept_static_select_literal_defaults() {
        let ir = static_select_default_ir(66, IrId::new(2), vec![literal_int_node(99)]);

        let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
            .expect("full-IR selector lowers static select root with literal default");
        assert_eq!(artifact.function().dfg.ext_funcs.len(), 4);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_force(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_has_attr(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_select_ic(),
        );
        assert!(all_iconst_words(artifact.function()).contains(&(ValueTag::Int as u64)));
        assert!(all_iconst_words(artifact.function()).contains(&Value::int(99).payload_bits()));

        let wrapped_default_ir = static_select_default_ir(
            67,
            IrId::new(3),
            vec![
                literal_int_node(99),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(12, 14),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(2)),
                ),
            ],
        );
        let force_aware_artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(
            &wrapped_default_ir,
            wrapped_default_ir.root,
        )
        .expect("force-aware full-IR selector lowers select with wrapped literal default");
        assert_eq!(force_aware_artifact.function().dfg.ext_funcs.len(), 4);
        imported_function_by_user_external_name(
            force_aware_artifact.function(),
            clif_external_name_for_aos_has_attr(),
        );
        imported_function_by_user_external_name(
            force_aware_artifact.function(),
            clif_external_name_for_aos_select_ic(),
        );
        assert!(
            all_iconst_words(force_aware_artifact.function())
                .contains(&Value::int(99).payload_bits())
        );
    }

    #[test]
    fn full_ir_tier1_selectors_reject_non_literal_select_defaults() {
        let ir = static_select_default_ir(68, IrId::new(2), vec![local_var_node(69)]);

        let Err(error) = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root) else {
            panic!("non-literal select default is outside the bounded lowerer");
        };

        assert!(matches!(
            error,
            JitLowerError::UnsupportedSelectDefault { default } if default == IrId::new(2)
        ));
    }

    #[test]
    fn full_ir_tier1_selectors_accept_static_has_attr_roots() {
        let ir = static_has_attr_ir(63);

        let Err(arena_only_error) =
            lower_force_aware_tier1_ir_thunk_body_artifact(&ir.arena, ir.root)
        else {
            panic!("arena-only force-aware selector should reject hasAttr roots");
        };
        assert!(matches!(
            arena_only_error,
            JitLowerError::UnsupportedIrRoot {
                kind: IrKind::HasAttr
            } | JitLowerError::UnsupportedIrBody {
                kind: IrKind::HasAttr
            }
        ));

        let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
            .expect("full-IR selector lowers static hasAttr root");
        assert_eq!(artifact.function().dfg.ext_funcs.len(), 3);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_force(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_has_attr(),
        );

        let force_aware_artifact =
            lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
                .expect("full-IR force-aware selector lowers static hasAttr root");
        assert_eq!(
            force_aware_artifact.function().dfg.ext_funcs.len(),
            artifact.function().dfg.ext_funcs.len()
        );
        imported_function_by_user_external_name(
            force_aware_artifact.function(),
            clif_external_name_for_aos_has_attr(),
        );
    }

    #[test]
    fn full_ir_tier1_selectors_accept_wrapped_static_select_roots() {
        let ir = wrapped_static_select_ir(62);

        let artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
            .expect("full-IR force-aware selector lowers wrapped static select root");
        assert_eq!(
            artifact.function_name(),
            &clif_name_for_ir_root(IrId::new(2))
        );
        assert_eq!(artifact.function().dfg.ext_funcs.len(), 3);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_force(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_select_ic(),
        );
    }

    #[test]
    fn full_ir_tier1_selectors_accept_wrapped_static_has_attr_roots() {
        let ir = wrapped_static_has_attr_ir(64);

        let artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
            .expect("full-IR force-aware selector lowers wrapped static hasAttr root");
        assert_eq!(
            artifact.function_name(),
            &clif_name_for_ir_root(IrId::new(2))
        );
        assert_eq!(artifact.function().dfg.ext_funcs.len(), 3);
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_env_get(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_force(),
        );
        imported_function_by_user_external_name(
            artifact.function(),
            clif_external_name_for_aos_has_attr(),
        );
    }

    #[test]
    fn force_aware_tier1_ir_thunk_body_lowers_wrapped_local_body() {
        let arena = IrArena::from_raw_parts(
            vec![
                local_var_node(37),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let function = lower_force_aware_tier1_ir_thunk_body(&arena, IrId::new(1))
            .expect("force-aware selector lowers wrapped local root");

        assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
        assert_eq!(function.dfg.ext_funcs.len(), 2);
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
        assert_eq!(iconst_words(&function), vec![37]);
    }

    #[test]
    fn tier1_ir_thunk_body_artifact_reports_unsupported_selector_shapes() {
        let root_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let body_arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Str,
                    Span::new(1, 6),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let Err(root_error) = lower_tier1_ir_thunk_body_artifact(&root_arena, IrId::new(0)) else {
            panic!("unsupported direct root is rejected");
        };
        let Err(body_error) =
            lower_force_aware_tier1_ir_thunk_body_artifact(&body_arena, IrId::new(1))
        else {
            panic!("unsupported wrapped body is rejected");
        };

        assert!(
            matches!(root_error, JitLowerError::UnsupportedIrRoot { kind } if kind == IrKind::Str)
        );
        assert!(
            matches!(body_error, JitLowerError::UnsupportedIrBody { kind } if kind == IrKind::Str)
        );
    }

    #[test]
    fn tier1_ir_thunk_body_artifact_reports_selector_shape_malformed_roots() {
        let missing_root_arena = IrArena::new();
        let missing_body_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(9)),
            )],
            Vec::new(),
        );
        let malformed_wrapper_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let Err(missing_root_error) =
            lower_tier1_ir_thunk_body_artifact(&missing_root_arena, IrId::new(7))
        else {
            panic!("missing selector root is rejected");
        };
        let Err(missing_body_error) =
            lower_force_aware_tier1_ir_thunk_body_artifact(&missing_body_arena, IrId::new(0))
        else {
            panic!("missing selector body is rejected");
        };
        let Err(malformed_wrapper_error) =
            lower_tier1_ir_thunk_body_artifact(&malformed_wrapper_arena, IrId::new(0))
        else {
            panic!("malformed selector wrapper is rejected");
        };

        assert!(
            matches!(missing_root_error, JitLowerError::MissingIrNode { root } if root == IrId::new(7))
        );
        assert!(
            matches!(missing_body_error, JitLowerError::MissingIrBody { body } if body == IrId::new(9))
        );
        assert!(matches!(
            malformed_wrapper_error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::ThunkAlloc,
                data: IrData::None,
                expected: "body node",
            }
        ));
    }

    #[test]
    fn tier1_ir_thunk_body_artifact_reports_selector_payload_mismatches() {
        let mismatched_literal_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let mismatched_local_arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let mismatched_body_arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Bool,
                    Span::new(1, 5),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 5),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let Err(literal_error) =
            lower_tier1_ir_thunk_body_artifact(&mismatched_literal_arena, IrId::new(0))
        else {
            panic!("mismatched selector literal is rejected");
        };
        let Err(local_error) =
            lower_force_aware_tier1_ir_thunk_body_artifact(&mismatched_local_arena, IrId::new(0))
        else {
            panic!("mismatched selector local slot is rejected");
        };
        let Err(body_error) =
            lower_tier1_ir_thunk_body_artifact(&mismatched_body_arena, IrId::new(1))
        else {
            panic!("mismatched selector thunk body is rejected");
        };

        assert!(matches!(
            literal_error,
            JitLowerError::MismatchedConstantData {
                kind: IrKind::Int,
                data: IrData::None,
            }
        ));
        assert!(matches!(
            local_error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::LocalVar,
                data: IrData::None,
                expected: "local slot payload",
            }
        ));
        assert!(matches!(
            body_error,
            JitLowerError::MismatchedBodyConstantData {
                kind: IrKind::Bool,
                data: IrData::None,
            }
        ));
    }

    fn lowered_ir(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    fn local_var_node(slot: u32) -> IrNode {
        IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Local { slot },
        )
    }

    fn literal_int_node(value: i64) -> IrNode {
        IrNode::new(
            IrKind::Int,
            Span::new(10, 12),
            EffectClass::pure(),
            IrData::Int(value),
        )
    }

    fn apply_local_slots_arena(function_slot: u32, argument_slot: u32) -> IrArena {
        IrArena::from_raw_parts(
            vec![
                local_var_node(function_slot),
                local_var_node(argument_slot),
                IrNode::new(
                    IrKind::Apply,
                    Span::new(0, 2),
                    EffectClass::pure(),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(1),
                    },
                ),
            ],
            Vec::new(),
        )
    }

    fn apply_local_slots_thunk_arena(function_slot: u32, argument_slot: u32) -> IrArena {
        IrArena::from_raw_parts(
            vec![
                local_var_node(function_slot),
                local_var_node(argument_slot),
                IrNode::new(
                    IrKind::Apply,
                    Span::new(1, 3),
                    EffectClass::pure(),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(1),
                    },
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 3),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(2)),
                ),
            ],
            Vec::new(),
        )
    }

    fn direct_thunk_ir_with_facts(facts: ExprFacts) -> Ir {
        let mut ir = minimal_ir(IrId::new(1), direct_thunk_arena());
        *ir.facts
            .get_mut(IrId::new(1))
            .expect("direct thunk fixture has a fact record") = facts;
        ir
    }

    fn static_select_ir(slot: u32) -> Ir {
        let mut symbols = SymbolTable::new();
        let symbol = symbols
            .intern(b"target")
            .expect("fixture symbol table accepts target");
        let arena = IrArena::from_raw_parts(
            vec![
                local_var_node(slot),
                IrNode::new(
                    IrKind::Select,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::Select {
                        receiver: IrId::new(0),
                        path: IrAttrPathId::new(0),
                        site: IrInlineCacheSiteId::new(11),
                        default: None,
                    },
                ),
            ],
            Vec::new(),
        );
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root: IrId::new(1),
            arena,
            facts,
            symbols,
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
                .into_boxed_slice(),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn static_select_default_ir(slot: u32, default: IrId, mut default_nodes: Vec<IrNode>) -> Ir {
        let mut symbols = SymbolTable::new();
        let symbol = symbols
            .intern(b"target")
            .expect("fixture symbol table accepts target");
        let mut nodes = vec![
            local_var_node(slot),
            IrNode::new(
                IrKind::Select,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Select {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    site: IrInlineCacheSiteId::new(11),
                    default: Some(default),
                },
            ),
        ];
        nodes.append(&mut default_nodes);
        let arena = IrArena::from_raw_parts(nodes, Vec::new());
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root: IrId::new(1),
            arena,
            facts,
            symbols,
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
                .into_boxed_slice(),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn static_has_attr_ir(slot: u32) -> Ir {
        let mut symbols = SymbolTable::new();
        let symbol = symbols
            .intern(b"target")
            .expect("fixture symbol table accepts target");
        let arena = IrArena::from_raw_parts(
            vec![
                local_var_node(slot),
                IrNode::new(
                    IrKind::HasAttr,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::HasAttr {
                        receiver: IrId::new(0),
                        path: IrAttrPathId::new(0),
                        site: IrInlineCacheSiteId::new(11),
                    },
                ),
            ],
            Vec::new(),
        );
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root: IrId::new(1),
            arena,
            facts,
            symbols,
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
                .into_boxed_slice(),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn wrapped_static_select_ir(slot: u32) -> Ir {
        let mut symbols = SymbolTable::new();
        let symbol = symbols
            .intern(b"target")
            .expect("fixture symbol table accepts target");
        let arena = IrArena::from_raw_parts(
            vec![
                local_var_node(slot),
                IrNode::new(
                    IrKind::Select,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::Select {
                        receiver: IrId::new(0),
                        path: IrAttrPathId::new(0),
                        site: IrInlineCacheSiteId::new(11),
                        default: None,
                    },
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(1)),
                ),
            ],
            Vec::new(),
        );
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root: IrId::new(2),
            arena,
            facts,
            symbols,
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
                .into_boxed_slice(),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn wrapped_static_has_attr_ir(slot: u32) -> Ir {
        let mut symbols = SymbolTable::new();
        let symbol = symbols
            .intern(b"target")
            .expect("fixture symbol table accepts target");
        let arena = IrArena::from_raw_parts(
            vec![
                local_var_node(slot),
                IrNode::new(
                    IrKind::HasAttr,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::HasAttr {
                        receiver: IrId::new(0),
                        path: IrAttrPathId::new(0),
                        site: IrInlineCacheSiteId::new(11),
                    },
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 8),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(1)),
                ),
            ],
            Vec::new(),
        );
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root: IrId::new(2),
            arena,
            facts,
            symbols,
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
                .into_boxed_slice(),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn direct_thunk_arena() -> IrArena {
        IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Int,
                    Span::new(1, 2),
                    EffectClass::pure(),
                    IrData::Int(1),
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 2),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        )
    }

    fn minimal_ir(root: IrId, arena: IrArena) -> Ir {
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root,
            arena,
            facts,
            symbols: SymbolTable::new(),
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn single_imported_function(function: &Function) -> (FuncRef, &ExtFuncData) {
        let imports = function.dfg.ext_funcs.iter().collect::<Vec<_>>();

        assert_eq!(imports.len(), 1);
        imports[0]
    }

    fn imported_function_by_user_external_name(
        function: &Function,
        expected: UserExternalName,
    ) -> (FuncRef, &ExtFuncData) {
        function
            .dfg
            .ext_funcs
            .iter()
            .find(|(_func_ref, import)| imported_user_external_name(function, import) == expected)
            .expect("imported function with expected user external name exists")
    }

    fn imported_user_external_name(function: &Function, import: &ExtFuncData) -> UserExternalName {
        let ExternalName::User(user_name_ref) = import.name else {
            panic!("imported env-get helper uses a user external name");
        };

        function.params.user_named_funcs()[user_name_ref].clone()
    }

    fn entry_block_values(function: &Function) -> Vec<cranelift_codegen::ir::Value> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function.dfg.block_params(entry_block).to_vec()
    }

    fn entry_block_param_types(function: &Function) -> Vec<Type> {
        entry_block_values(function)
            .iter()
            .map(|value| function.dfg.value_type(*value))
            .collect()
    }

    fn param_types(signature: &cranelift_codegen::ir::Signature) -> Vec<Type> {
        signature
            .params
            .iter()
            .map(|parameter| parameter.value_type)
            .collect()
    }

    fn iconst_words(function: &Function) -> Vec<u64> {
        iconst_values(function)
            .into_iter()
            .map(|(_value, word)| word)
            .collect()
    }

    fn all_iconst_words(function: &Function) -> Vec<u64> {
        function
            .layout
            .blocks()
            .flat_map(|block| function.layout.block_insts(block))
            .filter_map(|inst| match function.dfg.insts[inst] {
                InstructionData::UnaryImm {
                    opcode: Opcode::Iconst,
                    imm,
                } => Some(imm.bits() as u64),
                _ => None,
            })
            .collect()
    }

    fn iconst_values(function: &Function) -> Vec<(cranelift_codegen::ir::Value, u64)> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function
            .layout
            .block_insts(entry_block)
            .filter_map(|inst| match function.dfg.insts[inst] {
                InstructionData::UnaryImm {
                    opcode: Opcode::Iconst,
                    imm,
                } => Some((function.dfg.inst_results(inst)[0], imm.bits() as u64)),
                _ => None,
            })
            .collect()
    }

    fn return_operands(function: &Function) -> Vec<cranelift_codegen::ir::Value> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        let return_inst = function
            .layout
            .block_insts(entry_block)
            .find(|inst| function.dfg.insts[*inst].opcode() == Opcode::Return)
            .expect("lowered function has a return instruction");
        function.dfg.inst_args(return_inst).to_vec()
    }

    fn single_call_inst(function: &Function) -> cranelift_codegen::ir::Inst {
        let calls = call_insts(function);

        assert_eq!(calls.len(), 1);
        calls[0]
    }

    fn call_insts(function: &Function) -> Vec<cranelift_codegen::ir::Inst> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function
            .layout
            .block_insts(entry_block)
            .filter(|inst| function.dfg.insts[*inst].opcode() == Opcode::Call)
            .collect()
    }

    fn opcodes(function: &Function) -> Vec<Opcode> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function
            .layout
            .block_insts(entry_block)
            .map(|inst| function.dfg.insts[inst].opcode())
            .collect()
    }
}
