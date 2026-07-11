//! User stack-map slots for live two-word runtime values.
//!
//! Cranelift user stack maps identify one word inside an explicit stack slot.
//! Ratchet uses the entry at offset zero as the anchor for a complete runtime
//! `Value`: the tag word is at offset zero and the payload word is at offset
//! eight. A collector that rewrites the slot must update both words, and code
//! that keeps the value live after the safepoint must reload both words.

use cranelift_codegen::{
    cursor::FuncCursor,
    ir::{Inst, InstBuilder, StackSlot, StackSlotData, StackSlotKind, UserStackMapEntry, Value, types},
};

const VALUE_STACK_SLOT_BYTES: u32 = 16;
const VALUE_STACK_SLOT_ALIGN_SHIFT: u8 = 3;
const VALUE_PAYLOAD_OFFSET: i32 = 8;

/// Spills one two-word runtime value into an explicit stack-map slot.
pub(super) fn spill_value(cursor: &mut FuncCursor<'_>, value: [Value; 2]) -> StackSlot {
    let slot = cursor.func.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot,
        VALUE_STACK_SLOT_BYTES,
        VALUE_STACK_SLOT_ALIGN_SHIFT,
    ));
    cursor.ins().stack_store(value[0], slot, 0);
    cursor.ins().stack_store(value[1], slot, VALUE_PAYLOAD_OFFSET);
    slot
}

/// Attaches a spilled runtime-value anchor to one call safepoint.
pub(super) fn attach(cursor: &mut FuncCursor<'_>, call: Inst, slot: StackSlot) {
    cursor.func.dfg.append_user_stack_map_entry(
        call,
        UserStackMapEntry {
            ty: types::I64,
            slot,
            offset: 0,
        },
    );
}

/// Reloads a runtime value that may have been rewritten at a safepoint.
pub(super) fn reload(cursor: &mut FuncCursor<'_>, slot: StackSlot) -> [Value; 2] {
    [
        cursor.ins().stack_load(types::I64, slot, 0),
        cursor
            .ins()
            .stack_load(types::I64, slot, VALUE_PAYLOAD_OFFSET),
    ]
}

#[cfg(test)]
mod tests {
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
        let slot = spill_value(&mut cursor, [params[0], params[1]]);
        let call = cursor.ins().call(callee, &[]);
        attach(&mut cursor, call, slot);
        let reloaded = reload(&mut cursor, slot);
        cursor.ins().return_(&reloaded);

        let entries = function
            .dfg
            .user_stack_map_entries(call)
            .expect("call carries a stack map");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].slot, slot);
        assert_eq!(entries[0].offset, 0);
        assert_eq!(function.sized_stack_slots[slot].size, 16);
    }
}
