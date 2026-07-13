//! Tier-1 CLIF emission helpers and runtime-helper imports (moved from `lower.rs`).

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{
        ExtFuncData, ExternalName, Function, InstBuilder, UserExternalName, UserFuncName, types,
    },
};
use ratchet_core::{
    IrData,
    IrId, IrKind, IrNode,
    runtime_helper_call_signature, runtime_thunk_call_signature,
};
use ratchet_value::value::Value;
use crate::{
    abi::clif_signature_for_runtime_call,
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource},
    tier::JitTier,
};

use super::*;

pub(crate) fn lower_env_get_slot_thunk_body_with_name(
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

pub(crate) fn lower_forced_env_get_slot_thunk_body_with_name(
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

pub(crate) fn lower_upval_get_slot_thunk_body_with_name(
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

pub(crate) fn lower_forced_upval_get_slot_thunk_body_with_name(
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

pub(crate) fn lower_primop_call_thunk_body_with_name(
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

pub(crate) fn lower_string_length_inline_thunk_body_with_name(
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

pub(crate) fn lower_apply_local_slots_thunk_body_with_name(
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

pub(crate) fn lower_update_local_slots_thunk_body_with_name(
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

pub(crate) fn lower_attr_lookup_local_slot_thunk_body_with_name(
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

pub(crate) fn import_env_get_function(
    function: &mut Function,
) -> Result<cranelift_codegen::ir::FuncRef, JitLowerError> {
    import_runtime_helper_function(
        function,
        AOS_ENV_GET_SYMBOL,
        clif_external_name_for_aos_env_get(),
    )
}

pub(crate) fn import_primop_call_function(
    function: &mut Function,
) -> Result<cranelift_codegen::ir::FuncRef, JitLowerError> {
    import_runtime_helper_function(
        function,
        AOS_PRIMOP_CALL_SYMBOL,
        clif_external_name_for_aos_primop_call(),
    )
}

pub(crate) fn import_upval_get_function(
    function: &mut Function,
) -> Result<cranelift_codegen::ir::FuncRef, JitLowerError> {
    import_runtime_helper_function(
        function,
        AOS_UPVAL_GET_SYMBOL,
        clif_external_name_for_aos_upval_get(),
    )
}

pub(crate) fn import_string_length_function(
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
pub(crate) fn maybe_import_upval_get_function(
    function: &mut Function,
    operands: impl IntoIterator<Item = Tier1SlotOperand>,
) -> Result<Option<cranelift_codegen::ir::FuncRef>, JitLowerError> {
    if operands.into_iter().any(Tier1SlotOperand::is_upval) {
        Ok(Some(import_upval_get_function(function)?))
    } else {
        Ok(None)
    }
}

pub(crate) fn import_runtime_helper_function(
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

pub(crate) fn thunk_body_artifact(source: JitClifArtifactSource, function: Function) -> JitClifArtifact {
    JitClifArtifact::new(
        JitTier::Tier1Baseline,
        JitClifArtifactKind::ThunkBody,
        source,
        function,
    )
}

pub(crate) fn append_entry_block_params(function: &mut Function) -> cranelift_codegen::ir::Block {
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

pub(crate) fn emit_value_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    constant_words: [i64; value_words::VALUE_WORDS],
) {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let words = value_words::iconst_words(&mut cursor, constant_words);
    cursor.ins().return_(&words);
}
pub(crate) fn emit_env_get_return(
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

pub(crate) fn emit_upval_get_return(
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

pub(crate) fn emit_primop_call_return(
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
pub(crate) enum Tier1SlotOperand {
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
pub(crate) fn slot_operand_for_operand_node(node: IrNode) -> Option<Tier1SlotOperand> {
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
pub(crate) fn emit_slot_operand_load(
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

pub(crate) fn emit_apply_local_slots_return(
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
