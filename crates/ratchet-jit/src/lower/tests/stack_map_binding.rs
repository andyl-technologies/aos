//! Lowering tests for live compiled-frame stack-map bindings.

use super::*;

#[test]
fn forced_env_get_brackets_force_with_a_bound_stack_map() {
    let arena = IrArena::from_raw_parts(vec![local_var_node(13)], Vec::new());
    let function = lower_forced_env_get_ir_thunk_body(&arena, IrId::new(0))
        .expect("forced local var root lowers");
    let imports = [
        (clif_external_name_for_aos_env_get(), "env-get"),
        (clif_external_name_for_aos_jit_stack_map_enter(), "enter"),
        (clif_external_name_for_aos_force(), "force"),
        (clif_external_name_for_aos_jit_stack_map_exit(), "exit"),
    ];
    let calls = call_insts(&function);
    assert_eq!(calls.len(), imports.len());
    for (call, (external_name, label)) in calls.iter().copied().zip(imports) {
        let (expected, _) = imported_function_by_user_external_name(&function, external_name);
        let InstructionData::Call { func_ref, .. } = function.dfg.insts[call] else {
            panic!("forced env-get function emits the {label} call");
        };
        assert_eq!(func_ref, expected);
    }

    assert_eq!(
        opcodes(&function),
        vec![
            Opcode::Iconst,
            Opcode::Call,
            Opcode::StackStore,
            Opcode::StackStore,
            Opcode::StackAddr,
            Opcode::Iconst,
            Opcode::Iconst,
            Opcode::Call,
            Opcode::Call,
            Opcode::StackAddr,
            Opcode::Call,
            Opcode::Return,
        ]
    );
    let env_get_call = calls[0];
    let force_call = calls[2];
    let stack_map = function
        .dfg
        .user_stack_map_entries(force_call)
        .expect("force call carries the spilled input value");
    assert_eq!(stack_map.len(), 1);
    assert_eq!(stack_map[0].offset, 24);
    assert_eq!(function.sized_stack_slots[stack_map[0].slot].size, 40);
    assert_eq!(
        function.dfg.inst_args(env_get_call)[0],
        entry_block_values(&function)[1]
    );
    assert_eq!(
        function.dfg.value_type(function.dfg.inst_args(env_get_call)[1]),
        types::I32
    );
    assert_eq!(iconst_words(&function), vec![13, 0, 1]);
    assert_eq!(
        function.dfg.inst_args(force_call),
        &[
            entry_block_values(&function)[0],
            function.dfg.inst_results(env_get_call)[0],
            function.dfg.inst_results(env_get_call)[1],
        ]
    );
    assert_eq!(return_operands(&function), function.dfg.inst_results(force_call));
    verify_clif_function(&function).expect("forced env-get function verifies independently");
}
