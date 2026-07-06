use std::num::NonZeroUsize;

use cranelift_codegen::ir::{
    ExtFuncData, ExternalName, Function, InstructionData, Opcode, UserExternalName, Value,
};
use ratchet_core::{
    EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData, IrFacts, IrId,
    IrInlineCacheSiteId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
    runtime_helper_call_signature,
    syntax::{Span, SymbolTable},
};
use ratchet_jit::{
    AOS_HAS_ATTR_FUNCTION_INDEX, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
    AOS_SELECT_IC_FUNCTION_INDEX, JitClifSignatureError, JitLowerError, JitRuntimeSymbolAddress,
    JitRuntimeSymbolAddressCandidate, clif_external_name_for_aos_env_get,
    clif_external_name_for_aos_force, clif_external_name_for_aos_has_attr,
    clif_external_name_for_aos_select_ic, clif_signature_for_runtime_call,
    jit_cranelift_registered_artifact_definition_preflight_with_candidates,
    jit_module_readiness_preflight_for_artifact,
    lower_select_local_slot_ir_root_thunk_body_artifact, lower_select_local_slot_ir_thunk_body,
};

#[test]
fn attr_helper_external_names_use_reserved_namespace_and_indices() {
    let has_attr = clif_external_name_for_aos_has_attr();
    let select_ic = clif_external_name_for_aos_select_ic();

    assert_eq!(has_attr.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
    assert_eq!(has_attr.index, AOS_HAS_ATTR_FUNCTION_INDEX);
    assert_eq!(select_ic.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
    assert_eq!(select_ic.index, AOS_SELECT_IC_FUNCTION_INDEX);
}

#[test]
fn select_local_slot_ir_thunk_body_imports_env_force_and_select_helpers() {
    let ir = attr_lookup_ir(AttrLookupFixtureKind::Select, 5, None);

    let function = lower_select_local_slot_ir_thunk_body(&ir, ir.root).expect("select lowers");
    let env_get_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let force_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    let select_ic_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_select_ic());

    assert_eq!(function.dfg.ext_funcs.len(), 3);
    assert_eq!(
        function.dfg.signatures[env_get_import.1.signature],
        helper_signature("aos_env_get")
    );
    assert_eq!(
        function.dfg.signatures[force_import.1.signature],
        helper_signature("aos_force")
    );
    assert_eq!(
        function.dfg.signatures[select_ic_import.1.signature],
        helper_signature("aos_select_ic")
    );
    assert_eq!(iconst_words(&function), vec![5, 0, 11]);
}

#[test]
fn select_local_slot_ir_thunk_body_forces_receiver_then_calls_select_ic() {
    let ir = attr_lookup_ir(AttrLookupFixtureKind::Select, 7, None);

    let function = lower_select_local_slot_ir_thunk_body(&ir, ir.root).expect("select lowers");
    let (env_get, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let (force, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    let (select_ic, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_select_ic());
    let calls = call_insts(&function);
    let entry_values = entry_block_values(&function);
    let iconsts = iconst_values(&function);

    assert_eq!(calls.len(), 3);
    assert_eq!(
        iconsts.iter().map(|(_, word)| *word).collect::<Vec<_>>(),
        vec![7, 0, 11]
    );
    assert_call_target(&function, calls[0], env_get);
    assert_call_target(&function, calls[1], force);
    assert_call_target(&function, calls[2], select_ic);
    assert_eq!(
        opcodes(&function),
        vec![
            Opcode::Iconst,
            Opcode::Call,
            Opcode::Call,
            Opcode::Iconst,
            Opcode::Iconst,
            Opcode::Call,
            Opcode::Return,
        ]
    );

    let env_get_args = call_args(&function, calls[0]);
    assert_eq!(env_get_args, vec![entry_values[1], iconsts[0].0]);
    let env_get_results = function.dfg.inst_results(calls[0]).to_vec();

    let force_args = call_args(&function, calls[1]);
    assert_eq!(
        force_args,
        vec![entry_values[0], env_get_results[0], env_get_results[1]]
    );
    let force_results = function.dfg.inst_results(calls[1]).to_vec();

    let select_args = call_args(&function, calls[2]);
    assert_eq!(
        select_args,
        vec![
            entry_values[0],
            force_results[0],
            force_results[1],
            iconsts[1].0,
            iconsts[2].0,
        ]
    );
}

#[test]
fn select_root_artifact_records_runtime_imports() {
    let ir = attr_lookup_ir(AttrLookupFixtureKind::Select, 8, None);

    let artifact = lower_select_local_slot_ir_root_thunk_body_artifact(&ir)
        .expect("select root artifact lowers");
    let readiness =
        jit_module_readiness_preflight_for_artifact(&artifact).expect("select readiness builds");

    assert_eq!(
        artifact_import_names(readiness.artifact_runtime_imports()),
        ["aos_env_get", "aos_force", "aos_select_ic"]
    );
    assert!(readiness.artifact_runtime_import_gaps().is_empty());
}

#[test]
fn select_lowerer_accepts_direct_thunk_alloc_wrapper() {
    let ir = wrapped_attr_lookup_ir(10);

    let artifact =
        lower_select_local_slot_ir_root_thunk_body_artifact(&ir).expect("wrapped select lowers");

    assert_eq!(
        artifact_import_names(
            jit_module_readiness_preflight_for_artifact(&artifact)
                .expect("select readiness builds")
                .artifact_runtime_imports(),
        ),
        ["aos_env_get", "aos_force", "aos_select_ic"]
    );
    assert_eq!(iconst_words(artifact.function()), vec![10, 0, 11]);
}

#[test]
fn registered_artifact_definition_rewrites_select_runtime_imports() {
    let ir = attr_lookup_ir(AttrLookupFixtureKind::Select, 13, None);
    let artifact = lower_select_local_slot_ir_root_thunk_body_artifact(&ir)
        .expect("select root artifact lowers");
    let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        artifact,
        &[
            synthetic_candidate("aos_env_get", RuntimeHelperRole::EnvironmentAccess, 0x1000),
            synthetic_candidate("aos_force", RuntimeHelperRole::ForcingControl, 0x2000),
            synthetic_candidate("aos_select_ic", RuntimeHelperRole::AttrsetAccess, 0x3000),
        ],
    )
    .expect("registered artifact definition accepts select helper candidates");

    assert_eq!(
        artifact_import_names(preflight.artifact_runtime_imports()),
        ["aos_env_get", "aos_force", "aos_select_ic"]
    );
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert!(preflight.imported_symbol_for("aos_select_ic").is_some());
    assert!(preflight.registered_symbol_for("aos_env_get").is_some());
    assert!(preflight.registered_symbol_for("aos_force").is_some());
    assert!(preflight.registered_symbol_for("aos_select_ic").is_some());
}

#[test]
fn select_lowering_rejects_unsupported_shapes() {
    let dynamic_path_ir = attr_lookup_ir(
        AttrLookupFixtureKind::Select,
        1,
        Some(vec![IrAttrPathSegment::Dynamic(IrId::new(0))]),
    );
    let select_default_ir = attr_lookup_ir(AttrLookupFixtureKind::SelectWithDefault, 1, None);
    let non_local_receiver_ir =
        attr_lookup_ir(AttrLookupFixtureKind::SelectNonLocalReceiver, 1, None);

    let dynamic_path_error =
        lower_select_local_slot_ir_thunk_body(&dynamic_path_ir, dynamic_path_ir.root)
            .expect_err("dynamic attr path is rejected");
    let select_default_error =
        lower_select_local_slot_ir_thunk_body(&select_default_ir, select_default_ir.root)
            .expect_err("select default is rejected");
    let non_local_receiver_error =
        lower_select_local_slot_ir_thunk_body(&non_local_receiver_ir, non_local_receiver_ir.root)
            .expect_err("non-local attr receiver is rejected");

    assert!(matches!(
        dynamic_path_error,
        JitLowerError::UnsupportedAttrPathSegment {
            path,
            index: 0,
            segment: IrAttrPathSegment::Dynamic(dynamic),
        } if path == IrAttrPathId::new(0) && dynamic == IrId::new(0)
    ));
    assert!(
        matches!(select_default_error, JitLowerError::UnsupportedSelectDefault { default } if default == IrId::new(1))
    );
    assert!(matches!(
        non_local_receiver_error,
        JitLowerError::UnsupportedAttrReceiver {
            receiver,
            kind: IrKind::Int,
        } if receiver == IrId::new(0)
    ));
}

#[derive(Clone, Copy)]
enum AttrLookupFixtureKind {
    Select,
    SelectNonLocalReceiver,
    SelectWithDefault,
}

fn attr_lookup_ir(
    kind: AttrLookupFixtureKind,
    slot: u32,
    attr_path: Option<Vec<IrAttrPathSegment>>,
) -> Ir {
    let span = Span::new(0, 1);
    let mut symbols = SymbolTable::new();
    let symbol = symbols
        .intern(b"target")
        .expect("fixture symbol table accepts target");
    let receiver = match kind {
        AttrLookupFixtureKind::SelectNonLocalReceiver => IrNode::new(
            IrKind::Int,
            span,
            EffectClass::pure(),
            IrData::Int(i64::from(slot)),
        ),
        AttrLookupFixtureKind::Select | AttrLookupFixtureKind::SelectWithDefault => IrNode::new(
            IrKind::LocalVar,
            span,
            EffectClass::pure(),
            IrData::Local { slot },
        ),
    };
    let mut nodes = vec![receiver];
    let root_data = match kind {
        AttrLookupFixtureKind::Select | AttrLookupFixtureKind::SelectNonLocalReceiver => {
            IrData::Select {
                site: IrInlineCacheSiteId::new(11),
                receiver: IrId::new(0),
                path: IrAttrPathId::new(0),
                default: None,
            }
        }
        AttrLookupFixtureKind::SelectWithDefault => {
            nodes.push(IrNode::new(
                IrKind::Int,
                span,
                EffectClass::pure(),
                IrData::Int(99),
            ));
            IrData::Select {
                site: IrInlineCacheSiteId::new(11),
                receiver: IrId::new(0),
                path: IrAttrPathId::new(0),
                default: Some(IrId::new(1)),
            }
        }
    };
    let root = IrId::new(nodes.len() as u32);
    nodes.push(IrNode::new(
        IrKind::Select,
        span,
        EffectClass::pure(),
        root_data,
    ));
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root,
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![
            attr_path
                .unwrap_or_else(|| vec![IrAttrPathSegment::Static(symbol)])
                .into_boxed_slice(),
        ]
        .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn wrapped_attr_lookup_ir(slot: u32) -> Ir {
    let mut ir = attr_lookup_ir(AttrLookupFixtureKind::Select, slot, None);
    let root = ir.root;
    ir.arena = IrArena::from_raw_parts(
        vec![
            ir.arena
                .node(IrId::new(0))
                .copied()
                .expect("receiver node exists"),
            ir.arena.node(root).copied().expect("lookup node exists"),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(1)),
            ),
        ],
        Vec::new(),
    );
    ir.root = IrId::new(2);
    ir.facts = IrFacts::conservative(ir.arena.nodes().len());
    ir
}

fn imported_function_by_user_external_name(
    function: &Function,
    expected: UserExternalName,
) -> (cranelift_codegen::ir::FuncRef, &ExtFuncData) {
    function
        .dfg
        .ext_funcs
        .iter()
        .find(|(_func_ref, import)| imported_user_external_name(function, import) == expected)
        .expect("imported function with expected user external name exists")
}

fn imported_user_external_name(function: &Function, import: &ExtFuncData) -> UserExternalName {
    let ExternalName::User(user_name_ref) = import.name else {
        panic!("imported helper uses a user external name");
    };

    function.params.user_named_funcs()[user_name_ref].clone()
}

fn helper_signature(symbol_name: &'static str) -> cranelift_codegen::ir::Signature {
    let runtime_signature =
        runtime_helper_call_signature(symbol_name).expect("helper signature is core-owned");
    clif_signature_for_runtime_call(runtime_signature).unwrap_or_else(
        |error: JitClifSignatureError| panic!("helper signature lowers to CLIF: {error}"),
    )
}

fn entry_block_values(function: &Function) -> Vec<Value> {
    let entry_block = function
        .layout
        .entry_block()
        .expect("lowered function has an entry block");
    function.dfg.block_params(entry_block).to_vec()
}

fn iconst_words(function: &Function) -> Vec<u64> {
    iconst_values(function)
        .into_iter()
        .map(|(_value, word)| word)
        .collect()
}

fn iconst_values(function: &Function) -> Vec<(Value, u64)> {
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

fn call_args(function: &Function, call: cranelift_codegen::ir::Inst) -> Vec<Value> {
    function.dfg.inst_args(call).to_vec()
}

fn assert_call_target(
    function: &Function,
    call: cranelift_codegen::ir::Inst,
    expected: cranelift_codegen::ir::FuncRef,
) {
    let InstructionData::Call { func_ref, .. } = function.dfg.insts[call] else {
        panic!("instruction is a direct call");
    };

    assert_eq!(func_ref, expected);
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

fn artifact_import_names<'a>(
    imports: impl IntoIterator<Item = &'a ratchet_jit::JitModuleArtifactRuntimeImport>,
) -> Vec<&'a str> {
    imports
        .into_iter()
        .map(|import| import.symbol_name())
        .collect()
}

fn synthetic_candidate(
    symbol_name: &str,
    role: RuntimeHelperRole,
    raw: usize,
) -> JitRuntimeSymbolAddressCandidate {
    JitRuntimeSymbolAddressCandidate::new(
        symbol_name.to_owned(),
        RuntimeSymbolKind::Helper(role),
        JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).expect("test address is non-zero")),
    )
}
