//! Tree-walk test support: evaluation and lowering entry points.

use super::super::*;
use super::*;

pub(crate) fn lower(source: &str) -> Ir {
    aos_nix_dialect::nix_lower(
        resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers")
}

pub(crate) fn lower_bytes(source: &[u8]) -> Ir {
    aos_nix_dialect::nix_lower(
        resolve_ast(parse_bytes(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers")
}

pub(crate) fn eval(source: &str) -> Value {
    eval_whnf(&lower(source)).expect("source evaluates")
}

pub(crate) fn eval_with_options(source: &str, options: TreeWalkOptions) -> Value {
    eval_whnf_with_options(&lower(source), options).expect("source evaluates")
}

pub(crate) fn eval_owned_with_source(source_name: &[u8], source: &str) -> EvalOutcome {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        source_name.to_vec(),
        source.as_bytes().to_vec(),
    );
    let value = evaluator.eval_root().expect("source evaluates");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    EvalOutcome {
        value,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: evaluator.thunk_resolve_remembered_set,
        thunk_resolve_card_table: evaluator.thunk_resolve_card_table,
        memory_budget_action: None,
        tier_b_transition_admission_report: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        cold_hash_consed_value_materialization: None,
        gc_stress_boundary_scans: EvalGcStressBoundaryScans::default(),
        gc_stress_boundary_minor_gc_reference_writebacks:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
        gc_stress_boundary_minor_gc_forwarding_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
        gc_stress_boundary_minor_gc_destination_storage:
            EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
        gc_stress_boundary_minor_gc_object_generations:
            EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
        gc_stress_boundary_minor_gc_writeback_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
    }
}

pub(crate) fn eval_owned_with_options_and_heap_resident_memory_mode(
    source: &str,
    options: TreeWalkOptions,
    resident_memory_mode: EvalHeapResidentMemoryMode,
) -> EvalOutcome {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator
        .heap
        .set_resident_memory_mode(resident_memory_mode);
    let value = evaluator.eval_root().expect("source evaluates");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    let memory_budget_action = evaluator.heap.last_memory_budget_action();
    EvalOutcome {
        value,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: evaluator.thunk_resolve_remembered_set,
        thunk_resolve_card_table: evaluator.thunk_resolve_card_table,
        memory_budget_action,
        tier_b_transition_admission_report: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        cold_hash_consed_value_materialization: None,
        gc_stress_boundary_scans: EvalGcStressBoundaryScans::default(),
        gc_stress_boundary_minor_gc_reference_writebacks:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
        gc_stress_boundary_minor_gc_forwarding_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
        gc_stress_boundary_minor_gc_destination_storage:
            EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
        gc_stress_boundary_minor_gc_object_generations:
            EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
        gc_stress_boundary_minor_gc_writeback_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
    }
}

pub(crate) fn eval_string_bytes_with_source(source_name: &[u8], source: &str) -> Vec<u8> {
    let outcome = eval_owned_with_source(source_name, source);
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is a heap-owned string");
    string.bytes().to_vec()
}

pub(crate) fn eval_string_bytes(source: &str) -> Vec<u8> {
    let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is a heap-owned string");
    string.bytes().to_vec()
}

pub(crate) fn eval_string_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    let outcome = eval_whnf_owned_with_options(&lower(source), options).expect("source evaluates");
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is a heap-owned string");
    string.bytes().to_vec()
}

pub(crate) fn eval_path_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    let outcome = eval_whnf_owned_with_options(&lower(source), options).expect("source evaluates");
    let path = outcome
        .heap()
        .get_path(outcome.value())
        .expect("result is a heap-owned path");
    path.bytes().to_vec()
}

pub(crate) fn eval_json_bytes(source: &str) -> Vec<u8> {
    eval_string_bytes(&format!("builtins.toJSON ({source})"))
}

pub(crate) fn eval_json_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    eval_string_bytes_with_options(&format!("builtins.toJSON ({source})"), options)
}

pub(crate) fn eval_cpp_json_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
    let ir = lower(source);
    let root = ir.root;
    let root_span = ir.arena.node(root).expect("root node exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator.eval_root().expect("source evaluates");
    let mut bytes = Vec::new();
    let mut context = StringContext::empty();
    evaluator
        .write_json_value(
            root,
            root_span,
            root,
            root_span,
            value,
            &mut bytes,
            &mut context,
        )
        .expect("value serializes as JSON");
    bytes
}

pub(crate) fn pinned_builtin_name_bytes() -> Vec<Vec<u8>> {
    PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES
        .iter()
        .map(|name| name.as_bytes().to_vec())
        .collect()
}

pub(crate) fn pinned_builtin_names_json() -> Vec<u8> {
    serde_json::to_vec(PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES)
        .expect("pinned builtin fixture serializes")
}

pub(crate) fn eval_xml_bytes(source: &str) -> Vec<u8> {
    eval_string_bytes(&format!("builtins.toXML ({source})"))
}
