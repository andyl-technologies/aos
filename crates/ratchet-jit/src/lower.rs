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
use crate::artifact::JitClifArtifact;
use cranelift_codegen::{
    ir::{Function, UserExternalName, UserFuncName},
    settings,
    verifier::verify_function,
};
use ratchet_core::{
    BindingLowering, Cardinality, ExprFacts, Ir, IrArena, IrData, IrId, IrKind, Strictness,
    ThunkSharing,
};
mod alloc_cons;
mod arith_tree;
#[cfg(feature = "candidate_c_value")]
mod arith_tree_compressed;
mod candidate_b;
mod candidate_c;
mod error;
pub mod interp;
mod lambda_chain;
mod lambda_rec;
#[cfg(all(test, feature = "candidate_c_value"))]
mod one_word_shape_tests;
mod stack_maps;
mod value_words;
pub use alloc_cons::{
    AOS_ALLOC_CONS_FUNCTION_INDEX, clif_external_name_for_aos_alloc_cons,
    lower_singleton_list_ir_thunk_body_artifact,
};
pub use candidate_b::{
    JitCandidateBConstantError, lower_candidate_b_constant_ir_thunk_body_artifact,
    lower_candidate_b_env_get_ir_thunk_body_artifact,
};
pub use candidate_c::{
    JitCandidateCConstantError, lower_candidate_c_constant_ir_thunk_body_artifact,
};
pub use error::JitLowerError;
pub use lambda_chain::{
    JitTier2ChainCalleeSite, JitTier2ChainLowering, JitTier2ChainScan, JitTier2EnvBoundary,
    JitTier2PinnedCallee, TIER2_MAX_CHAIN_ARITY, lower_tier2_curried_chain,
    lower_tier2_fold_genlist, lower_tier2_fold_i64acc, scan_tier2_curried_chain,
    scan_tier2_pinned_callee, scan_tier2_unary_predicate,
};
pub use lambda_rec::{
    AOS_TIER2_LOCAL_FUNCTION_NAMESPACE, JitTier2LambdaLowering, TIER2_NATIVE_DEPTH_BUDGET,
    lower_tier2_self_recursive_lambda, tier2_self_recursive_lambda_cache_eligible,
};
pub use stack_maps::{
    AOS_JIT_STACK_MAP_ENTER_FUNCTION_INDEX, AOS_JIT_STACK_MAP_EXIT_FUNCTION_INDEX,
    clif_external_name_for_aos_jit_stack_map_enter, clif_external_name_for_aos_jit_stack_map_exit,
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

mod emit;
mod extract;
mod shapes;
pub(crate) use emit::*;
pub(crate) use extract::*;
pub use shapes::*;

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

pub(crate) fn verify_clif_function(function: &Function) -> Result<(), JitLowerError> {
    let flags = settings::Flags::new(settings::builder());
    verify_function(function, &flags).map_err(JitLowerError::Verifier)
}

// These tests exercise two-word-carrier codegen (tier-2 bodies, inline arith,
// candidate bridges, or two-word CLIF shape asserts), which declines on the
// one-word carrier; baseline-only until the S4b phase-2 one-word emitters land.
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests;
