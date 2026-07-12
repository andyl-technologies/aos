//! Singleton-list lowering through the semantic cons allocation helper.
//!
//! This is the first allocation-capable native body. It accepts only a list
//! whose sole element is an embeddable scalar literal, spills that complete
//! value into an explicit user stack map, and calls `aos_alloc_cons` with a
//! null tail. Larger and non-literal lists remain on the evaluator path.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, UserExternalName, types},
};
use ratchet_core::{IrArena, IrData, IrId, IrKind, runtime_thunk_call_signature};
use ratchet_value::value::ValueTag;

use super::{
    AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, JitLowerError, append_entry_block_params,
    clif_name_for_ir_root, constant_value_for_root, import_runtime_helper_function, stack_maps,
    thunk_body_artifact, verify_clif_function,
};
use crate::{
    abi::clif_signature_for_runtime_call,
    artifact::{JitClifArtifact, JitClifArtifactSource},
};

const AOS_ALLOC_CONS_SYMBOL: &str = "aos_alloc_cons";

/// User-external function index reserved for `aos_alloc_cons`.
pub const AOS_ALLOC_CONS_FUNCTION_INDEX: u32 = 12;

/// Returns the deterministic CLIF external name for `aos_alloc_cons`.
pub fn clif_external_name_for_aos_alloc_cons() -> UserExternalName {
    UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_ALLOC_CONS_FUNCTION_INDEX,
    )
}

/// Lowers one scalar singleton list into an allocation-capable thunk artifact.
///
/// The generated body brackets the cons call with the compiled-frame stack-map
/// helpers and returns the allocated pointer as the payload of a list value.
///
/// # Errors
///
/// Returns [`JitLowerError`] when `root` is absent or malformed, is not a
/// singleton list, contains a non-embeddable element, has an invalid runtime
/// ABI, or produces CLIF rejected by the verifier.
pub fn lower_singleton_list_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let element = singleton_list_element(arena, root)?;
    let head = constant_value_for_root(arena, element)?;
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(clif_name_for_ir_root(root), signature);
    let entry_block = append_entry_block_params(&mut function);
    let alloc_cons = import_runtime_helper_function(
        &mut function,
        AOS_ALLOC_CONS_SYMBOL,
        clif_external_name_for_aos_alloc_cons(),
    )?;
    let stack_runtime = stack_maps::import_runtime(&mut function)?;
    emit_singleton_list_return(&mut function, entry_block, alloc_cons, stack_runtime, head)?;
    verify_clif_function(&function)?;
    Ok(thunk_body_artifact(
        JitClifArtifactSource::IrRoot(root),
        function,
    ))
}

fn singleton_list_element(arena: &IrArena, root: IrId) -> Result<IrId, JitLowerError> {
    let root_node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;
    let (node, body) = match (root_node.kind, root_node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => (
            arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?,
            true,
        ),
        (IrKind::ThunkAlloc, data) => {
            return Err(JitLowerError::MismatchedIrNodeData {
                kind: IrKind::ThunkAlloc,
                data,
                expected: "body node",
            });
        }
        _ => (root_node, false),
    };
    if node.kind != IrKind::List {
        return Err(if body {
            JitLowerError::UnsupportedIrBody { kind: node.kind }
        } else {
            JitLowerError::UnsupportedIrRoot { kind: node.kind }
        });
    }
    let IrData::Children(children) = node.data else {
        return Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::List,
            data: node.data,
            expected: "list children",
        });
    };
    let elements = arena
        .child_slice(children)
        .ok_or(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::List,
            data: node.data,
            expected: "valid list children",
        })?;
    match elements {
        [element] => Ok(*element),
        _ if body => Err(JitLowerError::UnsupportedIrBody { kind: IrKind::List }),
        _ => Err(JitLowerError::UnsupportedIrRoot { kind: IrKind::List }),
    }
}

fn emit_singleton_list_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    alloc_cons: cranelift_codegen::ir::FuncRef,
    stack_runtime: stack_maps::Runtime,
    head: ratchet_value::value::Value,
) -> Result<(), JitLowerError> {
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let rt = cursor
        .func
        .dfg
        .block_params(entry_block)
        .first()
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 0 })?;
    let head_words = [
        cursor.ins().iconst(types::I64, head.tag() as u64 as i64),
        cursor
            .ins()
            .iconst(types::I64, head.relocation_sensitive_identity_bits() as i64),
    ];
    let binding = stack_maps::spill_values(&mut cursor, &[head_words]);
    stack_maps::enter(&mut cursor, stack_runtime, rt, binding, 0);
    let tail = cursor.ins().iconst(types::I64, 0);
    let call = cursor
        .ins()
        .call(alloc_cons, &[rt, head_words[0], head_words[1], tail]);
    stack_maps::attach(&mut cursor, call, binding);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    stack_maps::exit(&mut cursor, stack_runtime, rt, binding);
    if results.len() != 1 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ALLOC_CONS_SYMBOL,
            expected: 1,
            actual: results.len(),
        });
    }
    let tag = cursor
        .ins()
        .iconst(types::I64, ValueTag::List as u64 as i64);
    cursor.ins().return_(&[tag, results[0]]);
    Ok(())
}

// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use cranelift_codegen::ir::Opcode;
    use ratchet_core::{EffectClass, IrChildSlice, IrNode, syntax::Span};

    use super::*;

    #[test]
    fn singleton_scalar_list_lowers_to_one_allocating_safepoint() {
        let arena = singleton_list_arena();
        let artifact = lower_singleton_list_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("singleton list lowers");
        let function = artifact.function();
        let calls = function
            .layout
            .blocks()
            .flat_map(|block| function.layout.block_insts(block))
            .filter(|inst| function.dfg.insts[*inst].opcode() == Opcode::Call)
            .collect::<Vec<_>>();

        assert_eq!(calls.len(), 3, "enter, allocation, and exit are emitted");
        assert_eq!(
            function
                .dfg
                .user_stack_map_entries(calls[1])
                .expect("allocation call carries a stack map")
                .len(),
            2,
        );
    }

    #[test]
    fn multi_element_list_stays_on_the_evaluator_path() {
        let mut arena = singleton_list_arena();
        arena = IrArena::from_raw_parts(arena.nodes().to_vec(), vec![IrId::new(1), IrId::new(1)]);
        let mut nodes = arena.nodes().to_vec();
        nodes[2] = node(IrKind::List, IrData::Children(IrChildSlice::new(0, 2)));
        let arena = IrArena::from_raw_parts(nodes, arena.child_pool().to_vec());

        assert!(matches!(
            lower_singleton_list_ir_thunk_body_artifact(&arena, IrId::new(2)),
            Err(JitLowerError::UnsupportedIrRoot { kind: IrKind::List })
        ));
    }

    fn singleton_list_arena() -> IrArena {
        IrArena::from_raw_parts(
            vec![
                node(IrKind::Int, IrData::Int(41)),
                node(IrKind::ThunkAlloc, IrData::Node(IrId::new(0))),
                node(IrKind::List, IrData::Children(IrChildSlice::new(0, 1))),
            ],
            vec![IrId::new(1)],
        )
    }

    fn node(kind: IrKind, data: IrData) -> IrNode {
        IrNode::new(kind, Span::new(0, 1), EffectClass::pure(), data)
    }
}
