//! Unit tests for the tier-1 CLIF lowerer (moved from `lower.rs` verbatim).

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

mod stack_map_binding;

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

mod part_1;
mod part_2;
mod part_3;
