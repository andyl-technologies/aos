// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#![cfg(not(feature = "candidate_c_value"))]

use std::num::NonZeroUsize;

use cranelift_codegen::ir::{
    ExtFuncData, ExternalName, Function, InstructionData, Opcode, UserExternalName, Value,
};
use ratchet_core::{
    EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData, IrFacts, IrId,
    IrInlineCacheSiteId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
    runtime_helper_call_signature,
    syntax::{BinOpKind, Span, Symbol, SymbolTable},
};
use ratchet_jit::{
    AOS_HAS_ATTR_FUNCTION_INDEX, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
    AOS_SELECT_IC_FUNCTION_INDEX, AOS_UPDATE_FUNCTION_INDEX, JitClifSignatureError, JitLowerError,
    JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate, clif_external_name_for_aos_env_get,
    clif_external_name_for_aos_force, clif_external_name_for_aos_has_attr,
    clif_external_name_for_aos_jit_stack_map_enter,
    clif_external_name_for_aos_jit_stack_map_exit,
    clif_external_name_for_aos_select_ic, clif_external_name_for_aos_update,
    clif_signature_for_runtime_call,
    jit_cranelift_registered_artifact_definition_preflight_with_candidates,
    jit_module_readiness_preflight_for_artifact,
    lower_has_attr_local_slot_ir_root_thunk_body_artifact, lower_has_attr_local_slot_ir_thunk_body,
    lower_select_local_slot_ir_root_thunk_body_artifact, lower_select_local_slot_ir_thunk_body,
    lower_update_local_slots_ir_root_thunk_body_artifact, lower_update_local_slots_ir_thunk_body,
};

#[test]
fn attr_helper_external_names_use_reserved_namespace_and_indices() {
    let has_attr = clif_external_name_for_aos_has_attr();
    let select_ic = clif_external_name_for_aos_select_ic();
    let update = clif_external_name_for_aos_update();

    assert_eq!(has_attr.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
    assert_eq!(has_attr.index, AOS_HAS_ATTR_FUNCTION_INDEX);
    assert_eq!(select_ic.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
    assert_eq!(select_ic.index, AOS_SELECT_IC_FUNCTION_INDEX);
    assert_eq!(update.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
    assert_eq!(update.index, AOS_UPDATE_FUNCTION_INDEX);
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

    assert_eq!(function.dfg.ext_funcs.len(), 5);
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
    assert_eq!(iconst_words(&function), vec![5, 0, 1, 0, 11]);
}

#[test]
fn has_attr_local_slot_ir_thunk_body_imports_env_force_and_has_attr_helpers() {
    let ir = attr_lookup_ir(AttrLookupFixtureKind::HasAttr, 5, None);

    let function = lower_has_attr_local_slot_ir_thunk_body(&ir, ir.root).expect("hasAttr lowers");
    let env_get_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let force_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    let has_attr_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_has_attr());

    assert_eq!(function.dfg.ext_funcs.len(), 5);
    assert_eq!(
        function.dfg.signatures[env_get_import.1.signature],
        helper_signature("aos_env_get")
    );
    assert_eq!(
        function.dfg.signatures[force_import.1.signature],
        helper_signature("aos_force")
    );
    assert_eq!(
        function.dfg.signatures[has_attr_import.1.signature],
        helper_signature("aos_has_attr")
    );
    assert_eq!(iconst_words(&function), vec![5, 0, 1, 0, 11]);
}

#[test]
fn update_local_slots_ir_thunk_body_imports_env_force_and_update_helpers() {
    let arena = update_local_slots_arena(5, 6);

    let function =
        lower_update_local_slots_ir_thunk_body(&arena, IrId::new(2)).expect("update lowers");
    let env_get_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let force_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    let update_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_update());

    assert_eq!(function.dfg.ext_funcs.len(), 5);
    assert_eq!(
        function.dfg.signatures[env_get_import.1.signature],
        helper_signature("aos_env_get")
    );
    assert_eq!(
        function.dfg.signatures[force_import.1.signature],
        helper_signature("aos_force")
    );
    assert_eq!(
        function.dfg.signatures[update_import.1.signature],
        helper_signature("aos_update")
    );
    assert_eq!(iconst_words(&function), vec![5, 0, 1, 6, 1, 2]);
}

#[test]
fn select_local_slot_ir_thunk_body_forces_receiver_then_calls_select_ic() {
    let ir = attr_lookup_ir(AttrLookupFixtureKind::Select, 7, None);

    let function = lower_select_local_slot_ir_thunk_body(&ir, ir.root).expect("select lowers");
    let (env_get, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let (force, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    let (enter, _) = imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_enter(),
    );
    let (exit, _) = imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_exit(),
    );
    let (select_ic, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_select_ic());
    let calls = call_insts(&function);
    let entry_values = entry_block_values(&function);
    let iconsts = iconst_values(&function);

    assert_eq!(calls.len(), 5);
    assert_eq!(
        iconsts.iter().map(|(_, word)| *word).collect::<Vec<_>>(),
        vec![7, 0, 1, 0, 11]
    );
    assert_call_target(&function, calls[0], env_get);
    assert_call_target(&function, calls[1], enter);
    assert_call_target(&function, calls[2], force);
    assert_call_target(&function, calls[3], exit);
    assert_call_target(&function, calls[4], select_ic);

    let env_get_args = call_args(&function, calls[0]);
    assert_eq!(env_get_args, vec![entry_values[1], iconsts[0].0]);
    let env_get_results = function.dfg.inst_results(calls[0]).to_vec();

    let force_args = call_args(&function, calls[2]);
    assert_eq!(
        force_args,
        vec![entry_values[0], env_get_results[0], env_get_results[1]]
    );
    let force_results = function.dfg.inst_results(calls[2]).to_vec();

    let select_args = call_args(&function, calls[4]);
    assert_eq!(
        select_args,
        vec![
            entry_values[0],
            force_results[0],
            force_results[1],
            iconsts[3].0,
            iconsts[4].0,
        ]
    );
}

#[test]
fn has_attr_local_slot_ir_thunk_body_forces_receiver_then_calls_has_attr() {
    let ir = attr_lookup_ir(AttrLookupFixtureKind::HasAttr, 7, None);

    let function = lower_has_attr_local_slot_ir_thunk_body(&ir, ir.root).expect("hasAttr lowers");
    let (env_get, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let (force, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    let (enter, _) = imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_enter(),
    );
    let (exit, _) = imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_exit(),
    );
    let (has_attr, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_has_attr());
    let calls = call_insts(&function);
    let entry_values = entry_block_values(&function);
    let iconsts = iconst_values(&function);

    assert_eq!(calls.len(), 5);
    assert_eq!(
        iconsts.iter().map(|(_, word)| *word).collect::<Vec<_>>(),
        vec![7, 0, 1, 0, 11]
    );
    assert_call_target(&function, calls[0], env_get);
    assert_call_target(&function, calls[1], enter);
    assert_call_target(&function, calls[2], force);
    assert_call_target(&function, calls[3], exit);
    assert_call_target(&function, calls[4], has_attr);

    let env_get_args = call_args(&function, calls[0]);
    assert_eq!(env_get_args, vec![entry_values[1], iconsts[0].0]);
    let env_get_results = function.dfg.inst_results(calls[0]).to_vec();

    let force_args = call_args(&function, calls[2]);
    assert_eq!(
        force_args,
        vec![entry_values[0], env_get_results[0], env_get_results[1]]
    );
    let force_results = function.dfg.inst_results(calls[2]).to_vec();

    let has_attr_args = call_args(&function, calls[4]);
    assert_eq!(
        has_attr_args,
        vec![
            entry_values[0],
            force_results[0],
            force_results[1],
            iconsts[3].0,
            iconsts[4].0,
        ]
    );
}

#[test]
fn update_local_slots_ir_thunk_body_forces_operands_then_calls_update() {
    let arena = update_local_slots_arena(7, 8);

    let function =
        lower_update_local_slots_ir_thunk_body(&arena, IrId::new(2)).expect("update lowers");
    let (env_get, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let (force, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    let (enter, _) = imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_enter(),
    );
    let (exit, _) = imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_exit(),
    );
    let (update, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_update());
    let calls = call_insts(&function);
    let entry_values = entry_block_values(&function);
    let iconsts = iconst_values(&function);

    assert_eq!(calls.len(), 9);
    assert_eq!(
        iconsts.iter().map(|(_, word)| *word).collect::<Vec<_>>(),
        vec![7, 0, 1, 8, 1, 2]
    );
    assert_call_target(&function, calls[0], env_get);
    assert_call_target(&function, calls[1], enter);
    assert_call_target(&function, calls[2], force);
    assert_call_target(&function, calls[3], exit);
    assert_call_target(&function, calls[4], env_get);
    assert_call_target(&function, calls[5], enter);
    assert_call_target(&function, calls[6], force);
    assert_call_target(&function, calls[7], exit);
    assert_call_target(&function, calls[8], update);

    let left_env_get_args = call_args(&function, calls[0]);
    assert_eq!(left_env_get_args, vec![entry_values[1], iconsts[0].0]);
    let left_env_get_results = function.dfg.inst_results(calls[0]).to_vec();

    let left_force_args = call_args(&function, calls[2]);
    assert_eq!(
        left_force_args,
        vec![
            entry_values[0],
            left_env_get_results[0],
            left_env_get_results[1],
        ]
    );
    let right_env_get_args = call_args(&function, calls[4]);
    assert_eq!(right_env_get_args, vec![entry_values[1], iconsts[3].0]);
    let right_env_get_results = function.dfg.inst_results(calls[4]).to_vec();

    let right_force_args = call_args(&function, calls[6]);
    assert_eq!(
        right_force_args,
        vec![
            entry_values[0],
            right_env_get_results[0],
            right_env_get_results[1],
        ]
    );
    let right_force_results = function.dfg.inst_results(calls[6]).to_vec();
    let reloaded_left = stack_load_results(&function);
    assert_eq!(reloaded_left.len(), 2);

    let update_args = call_args(&function, calls[8]);
    assert_eq!(
        update_args,
        vec![
            entry_values[0],
            reloaded_left[0],
            reloaded_left[1],
            right_force_results[0],
            right_force_results[1],
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
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_select_ic",
        ]
    );
    assert!(readiness.artifact_runtime_import_gaps().is_empty());
}

#[test]
fn has_attr_root_artifact_records_runtime_imports() {
    let ir = attr_lookup_ir(AttrLookupFixtureKind::HasAttr, 8, None);

    let artifact = lower_has_attr_local_slot_ir_root_thunk_body_artifact(&ir)
        .expect("hasAttr root artifact lowers");
    let readiness =
        jit_module_readiness_preflight_for_artifact(&artifact).expect("hasAttr readiness builds");

    assert_eq!(
        artifact_import_names(readiness.artifact_runtime_imports()),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_has_attr",
        ]
    );
    assert!(readiness.artifact_runtime_import_gaps().is_empty());
}

#[test]
fn update_root_artifact_records_runtime_imports() {
    let ir = update_local_slots_ir(8, 9);

    let artifact =
        lower_update_local_slots_ir_root_thunk_body_artifact(&ir).expect("update root lowers");
    let readiness =
        jit_module_readiness_preflight_for_artifact(&artifact).expect("update readiness builds");

    assert_eq!(
        artifact_import_names(readiness.artifact_runtime_imports()),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_update",
        ]
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
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_select_ic",
        ]
    );
    assert_eq!(iconst_words(artifact.function()), vec![10, 0, 1, 0, 11]);
}

#[test]
fn has_attr_lowerer_accepts_direct_thunk_alloc_wrapper() {
    let ir = wrapped_has_attr_ir(10);

    let artifact =
        lower_has_attr_local_slot_ir_root_thunk_body_artifact(&ir).expect("wrapped hasAttr lowers");

    assert_eq!(
        artifact_import_names(
            jit_module_readiness_preflight_for_artifact(&artifact)
                .expect("hasAttr readiness builds")
                .artifact_runtime_imports(),
        ),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_has_attr",
        ]
    );
    assert_eq!(iconst_words(artifact.function()), vec![10, 0, 1, 0, 11]);
}

#[test]
fn update_lowerer_accepts_direct_thunk_alloc_wrapper() {
    let ir = wrapped_update_ir(10, 12);

    let artifact =
        lower_update_local_slots_ir_root_thunk_body_artifact(&ir).expect("wrapped update lowers");

    assert_eq!(
        artifact_import_names(
            jit_module_readiness_preflight_for_artifact(&artifact)
                .expect("update readiness builds")
                .artifact_runtime_imports(),
        ),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_update",
        ]
    );
    assert_eq!(iconst_words(artifact.function()), vec![10, 0, 1, 12, 1, 2]);
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
            synthetic_candidate(
                "aos_jit_stack_map_enter",
                RuntimeHelperRole::SafepointControl,
                0x2100,
            ),
            synthetic_candidate(
                "aos_jit_stack_map_exit",
                RuntimeHelperRole::SafepointControl,
                0x2200,
            ),
            synthetic_candidate("aos_select_ic", RuntimeHelperRole::AttrsetAccess, 0x3000),
        ],
    )
    .expect("registered artifact definition accepts select helper candidates");

    assert_eq!(
        artifact_import_names(preflight.artifact_runtime_imports()),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_select_ic",
        ]
    );
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert!(preflight.imported_symbol_for("aos_select_ic").is_some());
    assert!(preflight.registered_symbol_for("aos_env_get").is_some());
    assert!(preflight.registered_symbol_for("aos_force").is_some());
    assert!(preflight.registered_symbol_for("aos_select_ic").is_some());
}

#[test]
fn registered_artifact_definition_rewrites_has_attr_runtime_imports() {
    let ir = attr_lookup_ir(AttrLookupFixtureKind::HasAttr, 13, None);
    let artifact = lower_has_attr_local_slot_ir_root_thunk_body_artifact(&ir)
        .expect("hasAttr root artifact lowers");
    let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        artifact,
        &[
            synthetic_candidate("aos_env_get", RuntimeHelperRole::EnvironmentAccess, 0x1000),
            synthetic_candidate("aos_force", RuntimeHelperRole::ForcingControl, 0x2000),
            synthetic_candidate(
                "aos_jit_stack_map_enter",
                RuntimeHelperRole::SafepointControl,
                0x2100,
            ),
            synthetic_candidate(
                "aos_jit_stack_map_exit",
                RuntimeHelperRole::SafepointControl,
                0x2200,
            ),
            synthetic_candidate("aos_has_attr", RuntimeHelperRole::AttrsetAccess, 0x3000),
        ],
    )
    .expect("registered artifact definition accepts hasAttr helper candidates");

    assert_eq!(
        artifact_import_names(preflight.artifact_runtime_imports()),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_has_attr",
        ]
    );
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert!(preflight.imported_symbol_for("aos_has_attr").is_some());
    assert!(preflight.registered_symbol_for("aos_env_get").is_some());
    assert!(preflight.registered_symbol_for("aos_force").is_some());
    assert!(preflight.registered_symbol_for("aos_has_attr").is_some());
}

#[test]
fn registered_artifact_definition_rewrites_update_runtime_imports() {
    let ir = update_local_slots_ir(13, 17);
    let artifact =
        lower_update_local_slots_ir_root_thunk_body_artifact(&ir).expect("update root lowers");
    let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        artifact,
        &[
            synthetic_candidate("aos_env_get", RuntimeHelperRole::EnvironmentAccess, 0x1000),
            synthetic_candidate("aos_force", RuntimeHelperRole::ForcingControl, 0x2000),
            synthetic_candidate(
                "aos_jit_stack_map_enter",
                RuntimeHelperRole::SafepointControl,
                0x2100,
            ),
            synthetic_candidate(
                "aos_jit_stack_map_exit",
                RuntimeHelperRole::SafepointControl,
                0x2200,
            ),
            synthetic_candidate("aos_update", RuntimeHelperRole::AttrsetAccess, 0x3000),
        ],
    )
    .expect("registered artifact definition accepts update helper candidates");

    assert_eq!(
        artifact_import_names(preflight.artifact_runtime_imports()),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_update",
        ]
    );
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert!(preflight.imported_symbol_for("aos_update").is_some());
    assert!(preflight.registered_symbol_for("aos_env_get").is_some());
    assert!(preflight.registered_symbol_for("aos_force").is_some());
    assert!(preflight.registered_symbol_for("aos_update").is_some());
}

#[path = "attr_lookup_lowering/rejection.rs"]
mod rejection;

#[derive(Clone, Copy)]
enum AttrLookupFixtureKind {
    HasAttr,
    HasAttrNonLocalReceiver,
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
        AttrLookupFixtureKind::HasAttrNonLocalReceiver
        | AttrLookupFixtureKind::SelectNonLocalReceiver => IrNode::new(
            IrKind::Int,
            span,
            EffectClass::pure(),
            IrData::Int(i64::from(slot)),
        ),
        AttrLookupFixtureKind::HasAttr
        | AttrLookupFixtureKind::Select
        | AttrLookupFixtureKind::SelectWithDefault => IrNode::new(
            IrKind::LocalVar,
            span,
            EffectClass::pure(),
            IrData::Local { slot },
        ),
    };
    let mut nodes = vec![receiver];
    let root_data = match kind {
        AttrLookupFixtureKind::HasAttr | AttrLookupFixtureKind::HasAttrNonLocalReceiver => {
            IrData::HasAttr {
                site: IrInlineCacheSiteId::new(11),
                receiver: IrId::new(0),
                path: IrAttrPathId::new(0),
            }
        }
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
    let root_kind = match kind {
        AttrLookupFixtureKind::HasAttr | AttrLookupFixtureKind::HasAttrNonLocalReceiver => {
            IrKind::HasAttr
        }
        AttrLookupFixtureKind::Select
        | AttrLookupFixtureKind::SelectNonLocalReceiver
        | AttrLookupFixtureKind::SelectWithDefault => IrKind::Select,
    };
    nodes.push(IrNode::new(root_kind, span, EffectClass::pure(), root_data));
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

fn wrapped_has_attr_ir(slot: u32) -> Ir {
    let mut ir = attr_lookup_ir(AttrLookupFixtureKind::HasAttr, slot, None);
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

fn local_var_node(slot: u32) -> IrNode {
    IrNode::new(
        IrKind::LocalVar,
        Span::new(0, 1),
        EffectClass::pure(),
        IrData::Local { slot },
    )
}

fn binary_local_slots_arena(op: BinOpKind, left_slot: u32, right_slot: u32) -> IrArena {
    IrArena::from_raw_parts(
        vec![
            local_var_node(left_slot),
            local_var_node(right_slot),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    )
}

fn update_local_slots_arena(left_slot: u32, right_slot: u32) -> IrArena {
    binary_local_slots_arena(BinOpKind::Update, left_slot, right_slot)
}

fn update_local_slots_ir(left_slot: u32, right_slot: u32) -> Ir {
    let arena = update_local_slots_arena(left_slot, right_slot);
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(2),
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

fn wrapped_update_ir(left_slot: u32, right_slot: u32) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(left_slot),
            local_var_node(right_slot),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op: BinOpKind::Update,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
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
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(3),
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

fn stack_load_results(function: &Function) -> Vec<Value> {
    let entry_block = function
        .layout
        .entry_block()
        .expect("lowered function has an entry block");
    function
        .layout
        .block_insts(entry_block)
        .filter(|inst| function.dfg.insts[*inst].opcode() == Opcode::StackLoad)
        .map(|inst| function.dfg.inst_results(inst)[0])
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
