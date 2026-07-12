//! User stack-map slots for live two-word runtime values.
//!
//! Cranelift user stack maps identify one word inside an explicit stack slot.
//! Each explicit slot starts with the intrusive runtime-binding header, followed
//! by complete runtime values. A map entry anchors each tag word; its payload is
//! the following word. A collector that rewrites a value must update both words,
//! and code that keeps it live after the safepoint reloads both.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{
        Inst, InstBuilder, StackSlot, StackSlotData, StackSlotKind, UserStackMapEntry, Value,
        types,
    },
};

use super::{
    AOS_ENV_GET_SYMBOL, AOS_FORCE_SYMBOL, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, JitLowerError,
    import_runtime_helper_function,
};

/// User-external function index reserved for compiled stack-map entry.
pub const AOS_JIT_STACK_MAP_ENTER_FUNCTION_INDEX: u32 = 10;
/// User-external function index reserved for compiled stack-map exit.
pub const AOS_JIT_STACK_MAP_EXIT_FUNCTION_INDEX: u32 = 11;

const AOS_JIT_STACK_MAP_ENTER_SYMBOL: &str = "aos_jit_stack_map_enter";
const AOS_JIT_STACK_MAP_EXIT_SYMBOL: &str = "aos_jit_stack_map_exit";

/// Returns the deterministic CLIF external name for stack-map entry.
pub fn clif_external_name_for_aos_jit_stack_map_enter() -> cranelift_codegen::ir::UserExternalName {
    cranelift_codegen::ir::UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_JIT_STACK_MAP_ENTER_FUNCTION_INDEX,
    )
}

/// Returns the deterministic CLIF external name for stack-map exit.
pub fn clif_external_name_for_aos_jit_stack_map_exit() -> cranelift_codegen::ir::UserExternalName {
    cranelift_codegen::ir::UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_JIT_STACK_MAP_EXIT_FUNCTION_INDEX,
    )
}

/// Imported runtime helpers that bracket one live compiled frame.
#[derive(Clone, Copy)]
pub(super) struct Runtime {
    pub(super) enter: cranelift_codegen::ir::FuncRef,
    pub(super) exit: cranelift_codegen::ir::FuncRef,
}

/// Per-function force-call safepoint emitter.
///
/// Each force call spills its input plus every caller-supplied value that
/// remains live across the call, then reloads the latter after the runtime has
/// had an opportunity to rewrite the frame. A distinct address anchor lets the
/// runtime identify the finalized map even when Cranelift reorders blocks.
pub(super) struct ForceSafepoints {
    runtime: Runtime,
    next_safepoint: u32,
}

impl ForceSafepoints {
    /// Imports the binding helpers and starts a new function-local map table.
    pub(super) fn import(
        function: &mut cranelift_codegen::ir::Function,
    ) -> Result<Self, JitLowerError> {
        Ok(Self {
            runtime: import_runtime(function)?,
            next_safepoint: 0,
        })
    }

    /// Emits one mapped `aos_force` call and refreshes values live across it.
    pub(super) fn force(
        &mut self,
        cursor: &mut FuncCursor<'_>,
        force: cranelift_codegen::ir::FuncRef,
        rt: Value,
        input: [Value; 2],
        live: &mut [[Value; 2]],
    ) -> Result<[Value; 2], JitLowerError> {
        let mut values = Vec::with_capacity(live.len().saturating_add(1));
        values.push(input);
        values.extend_from_slice(live);
        let binding = spill_values(cursor, &values);
        let safepoint = self.next_safepoint;
        self.next_safepoint = self.next_safepoint.checked_add(1).ok_or(
            JitLowerError::MalformedForceSafepoint {
                reason: "function contains more than u32::MAX force calls",
            },
        )?;
        enter(cursor, self.runtime, rt, binding, safepoint);
        let call = cursor
            .ins()
            .call(force, &[rt, input[0], input[1]]);
        attach(cursor, call, binding);
        let results = cursor.func.dfg.inst_results(call).to_vec();
        exit(cursor, self.runtime, rt, binding);
        if results.len() != 2 {
            return Err(JitLowerError::InvalidRuntimeCallResultArity {
                symbol_name: AOS_FORCE_SYMBOL,
                expected: 2,
                actual: results.len(),
            });
        }
        for (index, value) in live.iter_mut().enumerate() {
            *value = reload(cursor, binding, index + 1);
        }
        Ok([results[0], results[1]])
    }
}

pub(super) fn import_runtime(
    function: &mut cranelift_codegen::ir::Function,
) -> Result<Runtime, JitLowerError> {
    Ok(Runtime {
        enter: import_runtime_helper_function(
            function,
            AOS_JIT_STACK_MAP_ENTER_SYMBOL,
            clif_external_name_for_aos_jit_stack_map_enter(),
        )?,
        exit: import_runtime_helper_function(
            function,
            AOS_JIT_STACK_MAP_EXIT_SYMBOL,
            clif_external_name_for_aos_jit_stack_map_exit(),
        )?,
    })
}

pub(super) fn emit_forced_env_get_return(
    function: &mut cranelift_codegen::ir::Function,
    entry_block: cranelift_codegen::ir::Block,
    env_get: cranelift_codegen::ir::FuncRef,
    force: cranelift_codegen::ir::FuncRef,
    runtime: Runtime,
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
    let mut safepoints = ForceSafepoints {
        runtime,
        next_safepoint: 0,
    };
    let forced = safepoints.force(
        &mut cursor,
        force,
        rt,
        [env_get_results[0], env_get_results[1]],
        &mut [],
    )?;
    cursor.ins().return_(&forced);
    Ok(())
}

const BINDING_HEADER_BYTES: u32 = 32;
const BINDING_IDENTITY_OFFSET: u32 = 24;
const VALUE_STACK_SLOT_BYTES: u32 = 16;
const VALUE_STACK_SLOT_ALIGN_SHIFT: u8 = 3;
const VALUE_PAYLOAD_OFFSET: i32 = 8;

/// One intrusive compiled-frame binding region.
#[derive(Clone, Copy)]
pub(super) struct Binding {
    slot: StackSlot,
    values: u32,
}

/// Spills two-word runtime values after an intrusive binding header.
pub(super) fn spill_values(cursor: &mut FuncCursor<'_>, values: &[[Value; 2]]) -> Binding {
    let value_count = values.len() as u32;
    let size = BINDING_HEADER_BYTES.saturating_add(
        value_count.saturating_mul(VALUE_STACK_SLOT_BYTES),
    );
    let slot = cursor.func.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot,
        size,
        VALUE_STACK_SLOT_ALIGN_SHIFT,
    ));
    for (index, value) in values.iter().enumerate() {
        let offset = value_offset(index);
        cursor.ins().stack_store(value[0], slot, offset);
        cursor
            .ins()
            .stack_store(value[1], slot, offset + VALUE_PAYLOAD_OFFSET);
    }
    Binding {
        slot,
        values: value_count,
    }
}

/// Attaches every spilled runtime-value anchor to one call safepoint.
pub(super) fn attach(cursor: &mut FuncCursor<'_>, call: Inst, binding: Binding) {
    cursor.func.dfg.append_user_stack_map_entry(
        call,
        UserStackMapEntry {
            ty: types::I32,
            slot: binding.slot,
            offset: BINDING_IDENTITY_OFFSET,
        },
    );
    for index in 0..binding.values {
        cursor.func.dfg.append_user_stack_map_entry(
            call,
            UserStackMapEntry {
                ty: types::I64,
                slot: binding.slot,
                offset: BINDING_HEADER_BYTES + index * VALUE_STACK_SLOT_BYTES,
            },
        );
    }
}

/// Reloads a runtime value that may have been rewritten at a safepoint.
pub(super) fn reload(cursor: &mut FuncCursor<'_>, binding: Binding, index: usize) -> [Value; 2] {
    let offset = value_offset(index);
    [
        cursor.ins().stack_load(types::I64, binding.slot, offset),
        cursor
            .ins()
            .stack_load(types::I64, binding.slot, offset + VALUE_PAYLOAD_OFFSET),
    ]
}

/// Emits the binding-region address passed to runtime enter/exit helpers.
pub(super) fn address(cursor: &mut FuncCursor<'_>, binding: Binding) -> Value {
    cursor.ins().stack_addr(types::I64, binding.slot, 0)
}

/// Emits the address-identity anchor used to select the finalized map.
pub(super) fn identity_address(cursor: &mut FuncCursor<'_>, binding: Binding) -> Value {
    cursor
        .ins()
        .stack_addr(types::I64, binding.slot, BINDING_IDENTITY_OFFSET as i32)
}

/// Returns the number of runtime values stored in a binding.
pub(super) const fn value_count(binding: Binding) -> u32 {
    binding.values
}

/// Links a binding region into the pinned runtime context.
pub(super) fn enter(
    cursor: &mut FuncCursor<'_>,
    runtime: Runtime,
    rt: Value,
    binding: Binding,
    safepoint: u32,
) {
    let binding_address = address(cursor, binding);
    let identity_address = identity_address(cursor, binding);
    let safepoint = cursor.ins().iconst(types::I32, i64::from(safepoint));
    let values = cursor
        .ins()
        .iconst(types::I32, i64::from(value_count(binding)));
    cursor
        .ins()
        .call(
            runtime.enter,
            &[rt, binding_address, identity_address, safepoint, values],
        );
}

/// Unlinks the current binding region after its safepoint returns.
pub(super) fn exit(
    cursor: &mut FuncCursor<'_>,
    runtime: Runtime,
    rt: Value,
    binding: Binding,
) {
    let binding_address = address(cursor, binding);
    cursor.ins().call(runtime.exit, &[rt, binding_address]);
}

fn value_offset(index: usize) -> i32 {
    BINDING_HEADER_BYTES as i32 + (index as i32) * VALUE_STACK_SLOT_BYTES as i32
}

// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use cranelift_codegen::cursor::Cursor;
    use cranelift_codegen::ir::{AbiParam, Function, Signature, UserFuncName};

    use super::*;

    #[test]
    fn spilled_value_anchors_both_words_at_call_safepoint() {
        let mut signature = Signature::new(cranelift_codegen::isa::CallConv::SystemV);
        signature.params.push(AbiParam::new(types::I64));
        signature.params.push(AbiParam::new(types::I64));
        let mut function = Function::with_name_signature(UserFuncName::default(), signature);
        let callee_signature = function.import_signature(Signature::new(
            cranelift_codegen::isa::CallConv::SystemV,
        ));
        let callee = function.import_function(cranelift_codegen::ir::ExtFuncData {
            name: cranelift_codegen::ir::ExternalName::testcase("safepoint"),
            signature: callee_signature,
            colocated: false,
        });
        let block = function.dfg.make_block();
        function.dfg.append_block_param(block, types::I64);
        function.dfg.append_block_param(block, types::I64);
        let mut cursor = FuncCursor::new(&mut function);
        cursor.insert_block(block);
        let params = cursor.func.dfg.block_params(block).to_vec();
        let binding = spill_values(&mut cursor, &[[params[0], params[1]]]);
        let call = cursor.ins().call(callee, &[]);
        attach(&mut cursor, call, binding);
        let reloaded = reload(&mut cursor, binding, 0);
        cursor.ins().return_(&reloaded);

        let entries = function
            .dfg
            .user_stack_map_entries(call)
            .expect("call carries a stack map");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ty, types::I32);
        assert_eq!(entries[0].offset, 24);
        assert_eq!(entries[1].slot, binding.slot);
        assert_eq!(entries[1].offset, 32);
        assert_eq!(function.sized_stack_slots[binding.slot].size, 48);
    }
}
