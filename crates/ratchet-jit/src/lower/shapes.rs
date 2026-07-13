//! Tier-1 delegating-shape public lowering entry points (moved from `lower.rs`).

use cranelift_codegen::ir::{Function, UserFuncName};
use ratchet_core::{
    Ir, IrArena, IrData,
    IrId, IrKind, runtime_thunk_call_signature,
};
use ratchet_value::value::Value;
use crate::{
    abi::clif_signature_for_runtime_call,
    artifact::{JitClifArtifact, JitClifArtifactSource},
};

use super::*;

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

pub(crate) fn lower_constant_thunk_body_with_name(
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
pub(crate) fn string_length_operand_for_root(
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
