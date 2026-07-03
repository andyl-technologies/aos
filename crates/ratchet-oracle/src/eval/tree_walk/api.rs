//! Public evaluation entry points and attribute-path index helpers.

use super::*;

/// Evaluates an IR root to weak head normal form with the tree-walk oracle.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if the root node is missing, malformed for its IR
/// kind, fails a scalar type check, or belongs to a part of the interpreter that
/// this Phase-1 slice has not implemented yet. Returns
/// [`TreeWalkErrorKind::HeapValueRequiresOwner`] if the root evaluates to a
/// heap-backed value; use [`eval_whnf_owned`] for those values so their
/// evaluator heap stays alive.
pub fn eval_whnf(ir: &Ir) -> Result<Value, TreeWalkError> {
    eval_whnf_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root to weak head normal form with explicit evaluator options.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if the root node is missing, malformed for its IR
/// kind, fails a scalar type check, or belongs to a part of the interpreter that
/// this Phase-1 slice has not implemented yet. Returns
/// [`TreeWalkErrorKind::HeapValueRequiresOwner`] if the root evaluates to a
/// heap-backed value; use [`eval_whnf_owned_with_options`] for those values so
/// their evaluator heap stays alive.
pub fn eval_whnf_with_options(ir: &Ir, options: TreeWalkOptions) -> Result<Value, TreeWalkError> {
    let mut evaluator = TreeWalk::with_options(ir, options);
    let value = evaluator.eval_root()?;
    evaluator.derivation_snapshot()?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    if value.tag().is_heap() {
        let span = ir
            .arena
            .node(ir.root)
            .map(|node| node.span)
            .unwrap_or_default();
        return Err(TreeWalkError::new(
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: value.tag(),
            },
            span,
        ));
    }
    evaluator.advance_persist_eval_cache_run_boundary();
    Ok(value)
}

/// Evaluates an IR root while returning the heap that owns heap-backed values.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned(ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
    eval_whnf_owned_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root with explicit options while returning the owning heap.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned_with_options(
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<EvalOutcome, TreeWalkError> {
    eval_whnf_owned_with_options_and_realizer(ir, options, None)
}

/// Evaluates an IR root with explicit options and an optional IFD realizer.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned_with_options_and_realizer(
    ir: &Ir,
    options: TreeWalkOptions,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    let evaluator = TreeWalk::with_options(ir, options);
    eval_whnf_owned_with_evaluator(evaluator, ifd_realizer)
}

/// Evaluates an IR root with explicit options, IFD, and caller-owned cache state.
///
/// The supplied cache runtime remains advisory: enabled runtimes may observe
/// source-backed or lowered-IR-backed forced inline thunk results and reuse
/// clean pure inline-scalar force results for a conservative IR subset. They
/// also observe `derivationStrict` `.drv` ATerm comparison hashes after normal
/// path computation. They do not perform general demand-graph memo lookup. When
/// options configure a persistent-cache root, forced-expression observations may
/// record demand and threshold-selected durable value/trace payloads.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned_with_options_realizer_and_eval_cache(
    ir: &Ir,
    options: TreeWalkOptions,
    ifd_realizer: Option<IfdRealizer>,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
) -> Result<EvalOutcome, TreeWalkError> {
    let evaluator = TreeWalk::with_options_and_eval_cache(ir, options, eval_cache);
    eval_whnf_owned_with_evaluator(evaluator, ifd_realizer)
}

fn eval_whnf_owned_with_evaluator(
    mut evaluator: TreeWalk,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    if let Some(realizer) = ifd_realizer {
        evaluator.set_ifd_realizer(realizer);
    }
    let value = evaluator.eval_root()?;
    let derivations = evaluator.derivation_snapshot()?;
    let gc_stress_boundary_scans = gc_stress_boundary_scans_for_outcome(&evaluator, value)?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    evaluator.advance_persist_eval_cache_run_boundary();
    let memory_budget_action = evaluator.heap.last_memory_budget_action();
    let (
        cheap_memory_budget_plan,
        cheap_memory_advice_report,
        cold_hash_consed_value_materialization,
    ) = post_eval_heap_memory_reports(&mut evaluator);
    Ok(EvalOutcome {
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
        cheap_memory_budget_plan,
        cheap_memory_advice_report,
        cold_hash_consed_value_materialization,
        gc_stress_boundary_scans,
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
    })
}

/// Evaluates an IR root and selects an attr path with `nix-instantiate -A` auto-calls.
///
/// Formal-set lambdas encountered before each path segment are called with an
/// empty attrset so defaults are honored. Plain lambdas are left untouched and
/// therefore produce the same type error as ordinary attr selection.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, formal-set auto-call, or
/// attribute selection fails.
pub fn eval_instantiation_attr_path_owned_with_options_and_realizer(
    ir: &Ir,
    attr_path: &[Vec<u8>],
    options: TreeWalkOptions,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    let evaluator = TreeWalk::with_options(ir, options);
    eval_instantiation_attr_path_with_evaluator(ir, attr_path, evaluator, ifd_realizer)
}

/// Evaluates a source-backed IR root and selects an attr path like `nix-instantiate -A`.
///
/// This is the source-provenance variant of
/// [`eval_instantiation_attr_path_owned_with_options_and_realizer`]. It should
/// be used for file-backed root modules so diagnostics and
/// `builtins.unsafeGetAttrPos` can report the original file path and source
/// bytes.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, formal-set auto-call, or
/// attribute selection fails.
pub fn eval_instantiation_attr_path_owned_with_options_source_and_realizer(
    ir: &Ir,
    attr_path: &[Vec<u8>],
    options: TreeWalkOptions,
    source_name: impl Into<Vec<u8>>,
    source: impl Into<Vec<u8>>,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    let evaluator = TreeWalk::with_options_and_source(ir, options, source_name, source);
    eval_instantiation_attr_path_with_evaluator(ir, attr_path, evaluator, ifd_realizer)
}

/// Evaluates a source-backed IR root with `-A` semantics and caller-owned cache state.
///
/// This is the cache-sharing variant of
/// [`eval_instantiation_attr_path_owned_with_options_source_and_realizer`].
/// The cache runtime remains advisory: enabled runtimes may reuse clean pure
/// inline-scalar force results for a conservative IR subset, but they do not
/// perform general demand-graph memo lookup. When options configure a
/// persistent-cache root, forced-expression observations may record demand and
/// threshold-selected durable value/trace payloads.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, formal-set auto-call, or
/// attribute selection fails.
pub fn eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
    ir: &Ir,
    attr_path: &[Vec<u8>],
    options: TreeWalkOptions,
    source_name: impl Into<Vec<u8>>,
    source: impl Into<Vec<u8>>,
    ifd_realizer: Option<IfdRealizer>,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
) -> Result<EvalOutcome, TreeWalkError> {
    let evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        ir,
        options,
        source_name,
        source,
        eval_cache,
    );
    eval_instantiation_attr_path_with_evaluator(ir, attr_path, evaluator, ifd_realizer)
}

fn eval_instantiation_attr_path_with_evaluator(
    ir: &Ir,
    attr_path: &[Vec<u8>],
    mut evaluator: TreeWalk,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    if let Some(realizer) = ifd_realizer {
        evaluator.set_ifd_realizer(realizer);
    }
    let root = evaluator.eval_root()?;
    let span = evaluator.node(ir.root)?.span;
    let value = evaluator.eval_instantiation_attr_path(ir.root, span, root, attr_path)?;
    let derivations = evaluator.derivation_snapshot()?;
    let gc_stress_boundary_scans = gc_stress_boundary_scans_for_outcome(&evaluator, value)?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    evaluator.advance_persist_eval_cache_run_boundary();
    let memory_budget_action = evaluator.heap.last_memory_budget_action();
    let (
        cheap_memory_budget_plan,
        cheap_memory_advice_report,
        cold_hash_consed_value_materialization,
    ) = post_eval_heap_memory_reports(&mut evaluator);
    Ok(EvalOutcome {
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
        cheap_memory_budget_plan,
        cheap_memory_advice_report,
        cold_hash_consed_value_materialization,
        gc_stress_boundary_scans,
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
    })
}

fn post_eval_heap_memory_reports(
    evaluator: &mut TreeWalk,
) -> (
    Option<EvalHeapCheapMemoryBudgetPlan>,
    Option<EvalHeapCheapMemoryAdviceReport>,
    Option<ColdHashConsedValueMaterializationReport>,
) {
    let Some(min_idle_epochs) = evaluator.options.heap_cheap_memory_advice_min_idle_epochs() else {
        return (None, None, None);
    };

    let cheap_memory_budget_plan = evaluator.options.heap_memory_budget().map(|budget| {
        evaluator
            .heap
            .plan_memory_budget_with_cheap_memory_advice(budget, min_idle_epochs)
    });
    let should_materialize_cold_values = cheap_memory_budget_plan
        .and_then(EvalHeapCheapMemoryBudgetPlan::cheap_advice_report)
        .is_some()
        && evaluator.options.persist_cache_root().is_some();
    let cold_hash_consed_value_materialization = should_materialize_cold_values
        .then(|| evaluator.materialize_cold_hash_consed_values_indexed(min_idle_epochs));
    let cheap_memory_advice_report = Some(
        cheap_memory_budget_plan
            .and_then(EvalHeapCheapMemoryBudgetPlan::cheap_advice_report)
            .unwrap_or_else(|| evaluator.heap.advise_cheap_memory_ranges(min_idle_epochs)),
    );

    (
        cheap_memory_budget_plan,
        cheap_memory_advice_report,
        cold_hash_consed_value_materialization,
    )
}

fn gc_stress_boundary_scans_for_outcome(
    evaluator: &TreeWalk,
    value: Value,
) -> Result<EvalGcStressBoundaryScans, TreeWalkError> {
    let id = evaluator.current_ir().root;
    evaluator.gc_stress_boundary_scans(value).map_err(|source| {
        let span = evaluator
            .current_ir()
            .arena
            .node(id)
            .map(|node| node.span)
            .unwrap_or_default();
        TreeWalkError::new(TreeWalkErrorKind::GcStressBoundaryScan { id, source }, span)
    })
}

pub(crate) fn attr_path_segment_is_list_index(segment: &[u8]) -> bool {
    parse_attr_path_list_index(segment).is_some()
}

pub(crate) fn parse_attr_path_list_index(segment: &[u8]) -> Option<usize> {
    let index = segment.iter().copied().try_fold(0u32, |index, byte| {
        let digit = u32::from(byte.checked_sub(b'0')?);
        if digit > 9 {
            return None;
        }
        index.checked_mul(10)?.checked_add(digit)
    })?;
    if segment.is_empty() {
        None
    } else {
        Some(index as usize)
    }
}

pub(crate) fn parse_attr_path_list_index_diagnostic(segment: &[u8]) -> i64 {
    segment
        .iter()
        .copied()
        .try_fold(0i64, |index, byte| {
            let digit = i64::from(byte - b'0');
            index.checked_mul(10)?.checked_add(digit)
        })
        .unwrap_or(i64::MAX)
}

/// Evaluates an IR root and renders it like raw `nix-instantiate --eval --strict`.
///
/// The renderer forces list elements and attribute values while printing Nix's
/// raw value syntax: quoted strings, lexicographic attribute keys,
/// `<LAMBDA>`/`<PRIMOP>` placeholders, and `«repeated»` for recursive values.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, nested forcing, or value
/// rendering fails.
pub fn eval_raw_bytes(ir: &Ir) -> Result<Vec<u8>, TreeWalkError> {
    eval_raw_bytes_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root with explicit options and renders raw strict output.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, nested forcing, or value
/// rendering fails.
pub fn eval_raw_bytes_with_options(
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<Vec<u8>, TreeWalkError> {
    eval_raw_bytes_with_evaluator(ir, TreeWalk::with_options(ir, options))
}

/// Evaluates an IR root with source provenance and renders raw strict output.
///
/// Use this for file-backed root modules so source-position builtins such as
/// `__curPos` and `builtins.unsafeGetAttrPos` can report the original path,
/// line, and column.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, nested forcing, or value
/// rendering fails.
pub fn eval_raw_bytes_with_options_source(
    ir: &Ir,
    options: TreeWalkOptions,
    source_name: impl Into<Vec<u8>>,
    source: impl Into<Vec<u8>>,
) -> Result<Vec<u8>, TreeWalkError> {
    eval_raw_bytes_with_evaluator(
        ir,
        TreeWalk::with_options_and_source(ir, options, source_name, source),
    )
}

fn eval_raw_bytes_with_evaluator(
    ir: &Ir,
    mut evaluator: TreeWalk,
) -> Result<Vec<u8>, TreeWalkError> {
    let value = evaluator.eval_root()?;
    let span = evaluator.node(ir.root)?.span;
    let mut out = Vec::new();
    let mut visited = Vec::new();
    evaluator.write_raw_value(ir.root, span, ir.root, span, value, &mut out, &mut visited)?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    evaluator.advance_persist_eval_cache_run_boundary();
    Ok(out)
}

/// Evaluates an IR root and renders a numeric value like raw `nix-instantiate --eval`.
///
/// Prefer [`eval_raw_bytes`] when the caller needs Nix's complete raw strict
/// value syntax.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails, or if the root value is
/// not an integer or float.
pub fn eval_number_raw_bytes(ir: &Ir) -> Result<Vec<u8>, TreeWalkError> {
    eval_number_raw_bytes_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root with explicit options and renders a numeric raw value.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails, or if the root value is
/// not an integer or float.
pub fn eval_number_raw_bytes_with_options(
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<Vec<u8>, TreeWalkError> {
    let mut evaluator = TreeWalk::with_options(ir, options);
    let value = evaluator.eval_root()?;
    let span = evaluator.node(ir.root)?.span;
    let bytes = TreeWalk::raw_number_bytes(ir.root, span, value)?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    evaluator.advance_persist_eval_cache_run_boundary();
    Ok(bytes)
}
