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
    evaluator.record_attr_select_cache_site_telemetry();
    evaluator.derivation_snapshot()?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    emit_direct_island_probe_report(&evaluator);
    emit_direct_island_site_report(&evaluator);
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
/// Returns [`TreeWalkError`] if root evaluation fails. Returns
/// [`TreeWalkErrorKind::TierBTransitionAdmission`] if automatic Tier-B
/// admission is enabled and the post-evaluation admission bridge rejects the
/// completed outcome heap.
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
/// Returns [`TreeWalkError`] if root evaluation fails. Returns
/// [`TreeWalkErrorKind::TierBTransitionAdmission`] if automatic Tier-B
/// admission is enabled and the post-evaluation admission bridge rejects the
/// completed outcome heap.
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
/// Returns [`TreeWalkError`] if root evaluation fails. Returns
/// [`TreeWalkErrorKind::TierBTransitionAdmission`] if automatic Tier-B
/// admission is enabled and the post-evaluation admission bridge rejects the
/// completed outcome heap.
pub fn eval_whnf_owned_with_options_realizer_and_eval_cache(
    ir: &Ir,
    options: TreeWalkOptions,
    ifd_realizer: Option<IfdRealizer>,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
) -> Result<EvalOutcome, TreeWalkError> {
    let evaluator = TreeWalk::with_options_and_eval_cache(ir, options, eval_cache);
    eval_whnf_owned_with_evaluator(evaluator, ifd_realizer)
}

/// Evaluates an IR root to WHNF with caller-owned cache state and a tier-1 engine.
///
/// This is the tier-1 JIT variant of
/// [`eval_whnf_owned_with_options_realizer_and_eval_cache`]. When `engine` is
/// `Some` it is installed on the evaluator before forcing begins, so hot thunk
/// bodies are promoted and later instances dispatch native code (subject to the
/// options' [`jit_tier1_publish_enabled`](TreeWalkOptions::jit_tier1_publish_enabled)
/// flag). A `None` engine is exactly the non-JIT path.
///
/// # Errors
///
/// Returns [`TreeWalkError`] under the same conditions as
/// [`eval_whnf_owned_with_options_realizer_and_eval_cache`].
pub fn eval_whnf_owned_with_options_realizer_eval_cache_and_engine(
    ir: &Ir,
    options: TreeWalkOptions,
    ifd_realizer: Option<IfdRealizer>,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
    engine: Option<std::rc::Rc<dyn Tier1Engine>>,
) -> Result<EvalOutcome, TreeWalkError> {
    let mut evaluator = TreeWalk::with_options_and_eval_cache(ir, options, eval_cache);
    if let Some(engine) = engine {
        evaluator.set_tier1_engine(engine);
    }
    // Step-4 W4 restore seam (default OFF): with AOS_NIX_SNAPSHOT=1 and a
    // cache root, try adopting a persisted prelude snapshot before any
    // evaluation. Every refusal falls back to the cold path.
    #[cfg(feature = "candidate_c_value")]
    {
        use super::eval_core::SnapshotAdoptAttempt;
        match evaluator.maybe_adopt_prelude_snapshot() {
            SnapshotAdoptAttempt::Adopted => {
                if evaluator.options.eval_stats_dump() {
                    eprintln!("aos-nix snapshot: prelude snapshot adopted");
                }
            }
            SnapshotAdoptAttempt::Refused(reason) => {
                if evaluator.options.eval_stats_dump() {
                    eprintln!("aos-nix snapshot: adoption refused, cold path: {reason}");
                }
            }
            SnapshotAdoptAttempt::Disabled => {}
        }
    }
    eval_whnf_owned_with_evaluator(evaluator, ifd_realizer)
}

fn eval_whnf_owned_with_evaluator(
    mut evaluator: TreeWalk,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    if let Some(realizer) = ifd_realizer {
        evaluator.set_ifd_realizer(realizer);
    }
    let pool = parallel_demand::ParallelDemandPool::spawn(&mut evaluator);
    let value = evaluator.eval_root();
    if let Some(pool) = pool {
        pool.finish(&mut evaluator);
    }
    evaluator.emit_formal_set_ready_census_report();
    let mut value = value?;
    #[cfg(feature = "ready_exclusive_probe")]
    evaluator.emit_ready_exclusive_window_report();
    emit_terminal_reservation_residency(&evaluator);
    emit_weak_liveness_census(&evaluator, value);
    emit_permanent_retention_census(&evaluator, value);
    emit_stg_apply_census(&evaluator);
    #[cfg(feature = "active_packed_thunk_probe")]
    emit_active_packed_thunk_accounting(&evaluator);
    emit_promise_region_census(&evaluator);
    #[cfg(feature = "lifetime_cohort_probe")]
    evaluator.emit_lifetime_cohort_terminal(value);
    // Tier-B quiescent point: the root force has fully unwound, so worker
    // garbage is reclaimable with the produced value as an extra root. A
    // no-op unless AOS_NIX_GC=sweep is enabled and the growth threshold has
    // been reached.
    #[cfg(feature = "candidate_c_value")]
    if evaluator
        .maybe_publish_terminal_permanent(&mut value)?
        .is_none()
    {
        evaluator.maybe_sweep_heap_at_quiescence(&[value])?;
    }
    #[cfg(not(feature = "candidate_c_value"))]
    evaluator.maybe_sweep_heap_at_quiescence(&[value])?;
    evaluator.record_attr_select_cache_site_telemetry();
    let derivations = evaluator.derivation_snapshot()?;
    // Step-4 W3 capture seam (default OFF): the prelude-warmer flow writes
    // the post-eval snapshot when AOS_NIX_SNAPSHOT=1 + AOS_NIX_SNAPSHOT_WARM=1.
    // Post-eval only — the capture-time collapse leaves the heap capture-only
    // — and advisory: a write failure is reported, never an eval error.
    #[cfg(feature = "candidate_c_value")]
    if super::eval_core::snapshot_tier_enabled() && super::eval_core::snapshot_warm_requested() {
        match evaluator.write_prelude_snapshot() {
            Ok(path) => {
                if evaluator.options.eval_stats_dump() {
                    eprintln!("aos-nix snapshot: wrote {}", path.display());
                }
            }
            Err(error) => eprintln!("aos-nix snapshot: warmer write failed: {error}"),
        }
    }
    let gc_stress_boundary_scans = gc_stress_boundary_scans_for_outcome(&evaluator, value)?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    emit_heap_refusal_census(&evaluator);
    emit_heap_storage_census(&evaluator);
    #[cfg(feature = "peak_ordinal_probe")]
    evaluator.emit_peak_ordinal_report();
    emit_direct_island_probe_report(&evaluator);
    emit_direct_island_site_report(&evaluator);
    let id = evaluator.current_ir().root;
    let span = evaluator
        .current_ir()
        .arena
        .node(id)
        .map(|node| node.span)
        .unwrap_or_default();
    finish_owned_eval_outcome(
        evaluator,
        value,
        stats,
        derivations,
        gc_stress_boundary_scans,
        id,
        span,
    )
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
/// attribute selection fails. Returns
/// [`TreeWalkErrorKind::TierBTransitionAdmission`] if automatic Tier-B
/// admission is enabled and the post-evaluation admission bridge rejects the
/// completed outcome heap.
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
/// attribute selection fails. Returns
/// [`TreeWalkErrorKind::TierBTransitionAdmission`] if automatic Tier-B
/// admission is enabled and the post-evaluation admission bridge rejects the
/// completed outcome heap.
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
/// attribute selection fails. Returns
/// [`TreeWalkErrorKind::TierBTransitionAdmission`] if automatic Tier-B
/// admission is enabled and the post-evaluation admission bridge rejects the
/// completed outcome heap.
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

/// Evaluates a source-backed IR root with `-A` semantics, owned cache, and an engine.
///
/// This is the tier-1 JIT variant of
/// [`eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache`].
/// When `engine` is `Some` it is installed on the evaluator before forcing, so
/// hot thunk bodies promote and dispatch native code (subject to the options'
/// [`jit_tier1_publish_enabled`](TreeWalkOptions::jit_tier1_publish_enabled)
/// flag). A `None` engine is exactly the non-JIT path.
///
/// # Errors
///
/// Returns [`TreeWalkError`] under the same conditions as
/// [`eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache`].
#[allow(clippy::too_many_arguments)]
pub fn eval_instantiation_attr_path_owned_with_options_source_realizer_eval_cache_and_engine(
    ir: &Ir,
    attr_path: &[Vec<u8>],
    options: TreeWalkOptions,
    source_name: impl Into<Vec<u8>>,
    source: impl Into<Vec<u8>>,
    ifd_realizer: Option<IfdRealizer>,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
    engine: Option<std::rc::Rc<dyn Tier1Engine>>,
) -> Result<EvalOutcome, TreeWalkError> {
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        ir,
        options,
        source_name,
        source,
        eval_cache,
    );
    if let Some(engine) = engine {
        evaluator.set_tier1_engine(engine);
    }
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
    let demand_epoch_start = (
        evaluator.stats.thunks_forced(),
        evaluator.stats.function_calls(),
    );
    #[cfg(feature = "collection_poll_probe")]
    let windowed_speed_epoch =
        std::env::var("AOS_NIX_WHOLE_DEMAND_DISPATCHER_PROBE").is_ok_and(|value| value == "1");
    #[cfg(not(feature = "collection_poll_probe"))]
    let windowed_speed_epoch = false;
    let demand_epoch = if windowed_speed_epoch {
        None
    } else {
        demand_epoch_probe::DemandEpoch::begin()
    };
    let demand_epoch_enabled = demand_epoch.is_some();
    #[cfg(feature = "demand_region_shadow_probe")]
    evaluator.begin_demand_region_shadow_epoch();
    #[cfg(feature = "root_continuation_probe")]
    evaluator.begin_root_continuation_probe();
    let pool = parallel_demand::ParallelDemandPool::spawn(&mut evaluator);
    #[cfg(feature = "collection_poll_probe")]
    let dispatcher_probe =
        evaluator.begin_whole_demand_dispatcher_probe(ir.root, attr_path.len())?;
    #[cfg(feature = "collection_poll_probe")]
    let mut value = if dispatcher_probe {
        evaluator.eval_instantiation_attr_path_dispatcher(ir.root, attr_path)
    } else {
        (|| match evaluator.try_eval_demand_machine_instantiation(ir.root, attr_path) {
            Some(result) => result,
            None => {
                let root = evaluator.eval_root()?;
                let span = evaluator.node(ir.root)?.span;
                #[cfg(feature = "lifetime_cohort_probe")]
                {
                    let mut roots = [root];
                    evaluator.with_lifetime_cohort_shadow_roots(
                        ir.root,
                        span,
                        &mut roots,
                        |eval, slots| {
                            let root = eval
                                .current_transient_value_stack_root(slots.start)
                                .ok_or_else(|| {
                                    TreeWalkError::new(
                                        TreeWalkErrorKind::SafepointRootStackLengthOverflow {
                                            id: ir.root,
                                        },
                                        span,
                                    )
                                })?;
                            eval.eval_instantiation_attr_path(ir.root, span, root, attr_path)
                        },
                    )
                }
                #[cfg(not(feature = "lifetime_cohort_probe"))]
                {
                    evaluator.eval_instantiation_attr_path(ir.root, span, root, attr_path)
                }
            }
        })()
    };
    #[cfg(not(feature = "collection_poll_probe"))]
    let mut value = (|| match evaluator.try_eval_demand_machine_instantiation(ir.root, attr_path) {
        Some(result) => result,
        None => {
            let root = evaluator.eval_root()?;
            let span = evaluator.node(ir.root)?.span;
            #[cfg(feature = "lifetime_cohort_probe")]
            {
                let mut roots = [root];
                evaluator.with_lifetime_cohort_shadow_roots(
                    ir.root,
                    span,
                    &mut roots,
                    |eval, slots| {
                        let root = eval
                            .current_transient_value_stack_root(slots.start)
                            .ok_or_else(|| {
                                TreeWalkError::new(
                                    TreeWalkErrorKind::SafepointRootStackLengthOverflow {
                                        id: ir.root,
                                    },
                                    span,
                                )
                            })?;
                        eval.eval_instantiation_attr_path(ir.root, span, root, attr_path)
                    },
                )
            }
            #[cfg(not(feature = "lifetime_cohort_probe"))]
            {
                evaluator.eval_instantiation_attr_path(ir.root, span, root, attr_path)
            }
        }
    })();
    if let Some(pool) = pool {
        pool.finish(&mut evaluator);
    }
    evaluator.emit_formal_set_ready_census_report();
    #[cfg(feature = "root_continuation_probe")]
    evaluator.finish_root_continuation_probe(value.is_ok());
    let mut value = value?;
    #[cfg(feature = "demand_region_shadow_probe")]
    evaluator.emit_demand_region_shadow_report();
    #[cfg(feature = "dedup_string_list_canary")]
    evaluator.emit_dedup_string_list_canary_report();
    #[cfg(feature = "final_config_trie_canary")]
    evaluator.emit_final_config_trie_canary_report();
    #[cfg(feature = "option_map_fold_probe")]
    evaluator.emit_option_map_fold_probe_report();
    #[cfg(feature = "root_continuation_probe")]
    evaluator.emit_root_continuation_probe_report();
    #[cfg(feature = "collection_poll_probe")]
    evaluator.emit_whole_demand_dispatcher_probe_report();
    #[cfg(feature = "collection_poll_probe")]
    evaluator.emit_restart_to_root_probe_report();
    #[cfg(feature = "collection_poll_probe")]
    evaluator.emit_nested_nonmoving_safepoint_probe_report();
    #[cfg(feature = "nested_nonmoving_retirement_probe")]
    evaluator.emit_rotating_rollover_probe_report();
    #[cfg(feature = "nested_nonmoving_retirement_probe")]
    evaluator.emit_nested_nonmoving_retirement_report();
    #[cfg(feature = "young_increment_projection_probe")]
    evaluator.emit_young_increment_projection_report();
    evaluator.emit_resident_phase("demand-complete");
    #[cfg(feature = "ready_exclusive_probe")]
    evaluator.emit_ready_exclusive_window_report();
    emit_terminal_reservation_residency(&evaluator);
    emit_weak_liveness_census(&evaluator, value);
    emit_permanent_retention_census(&evaluator, value);
    emit_stg_apply_census(&evaluator);
    #[cfg(feature = "active_packed_thunk_probe")]
    emit_active_packed_thunk_accounting(&evaluator);
    emit_promise_region_census(&evaluator);
    #[cfg(feature = "lifetime_cohort_probe")]
    evaluator.emit_lifetime_cohort_terminal(value);
    // Tier-B quiescent point: the instantiation force has fully unwound (see
    // `eval_whnf_owned_with_evaluator`).
    #[cfg(feature = "candidate_c_value")]
    if evaluator
        .maybe_publish_terminal_permanent(&mut value)?
        .is_none()
    {
        evaluator.maybe_sweep_heap_at_quiescence(&[value])?;
    }
    #[cfg(not(feature = "candidate_c_value"))]
    evaluator.maybe_sweep_heap_at_quiescence(&[value])?;
    #[cfg(feature = "hole_reuse_shadow_probe")]
    if std::env::var("AOS_NIX_HOLE_REUSE_SHADOW").is_ok_and(|setting| setting == "1") {
        eprintln!(
            "aos_nix_hole_reuse_shadow {}",
            ratchet_value::heap::flat::hole_reuse_shadow::hole_reuse_shadow_report()
        );
    }
    evaluator.emit_resident_phase("post-quiescent-sweep");
    let span = evaluator.node(ir.root)?.span;
    evaluator.record_attr_select_cache_site_telemetry();
    evaluator.emit_resident_phase("pre-derivation-snapshot");
    let derivations = evaluator.derivation_snapshot()?;
    evaluator.emit_resident_phase("post-derivation-snapshot");
    let demand_epoch_end = (
        evaluator.stats.thunks_forced(),
        evaluator.stats.function_calls(),
    );
    if let Some(epoch) = demand_epoch {
        epoch.end();
    }
    if demand_epoch_enabled {
        eprintln!(
            "aos_nix_demand_epoch_counts {{\"thunks_forced\":[{},{}],\
             \"function_calls\":[{},{}]}}",
            demand_epoch_start.0, demand_epoch_end.0, demand_epoch_start.1, demand_epoch_end.1
        );
    }
    let gc_stress_boundary_scans = gc_stress_boundary_scans_for_outcome(&evaluator, value)?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    emit_heap_refusal_census(&evaluator);
    emit_heap_storage_census(&evaluator);
    #[cfg(feature = "peak_ordinal_probe")]
    evaluator.emit_peak_ordinal_report();
    emit_direct_island_probe_report(&evaluator);
    emit_direct_island_site_report(&evaluator);
    finish_owned_eval_outcome(
        evaluator,
        value,
        stats,
        derivations,
        gc_stress_boundary_scans,
        ir.root,
        span,
    )
}

/// Emits the default-off live heap and captured-frame census.
fn emit_heap_refusal_census(evaluator: &TreeWalk) {
    if std::env::var_os("AOS_NIX_HEAP_CENSUS").is_none() {
        return;
    }
    eprint!("{}", evaluator.heap.refusal_census());
}

/// Emits reachability without treating hash-cons indexes as strong roots.
fn emit_weak_liveness_census(evaluator: &TreeWalk, value: Value) {
    if std::env::var_os("AOS_NIX_WEAK_LIVENESS_CENSUS").is_none() {
        return;
    }
    if !evaluator.has_complete_terminal_root_set() {
        eprintln!(
            "aos_nix_weak_liveness_census_error \
             \"terminal evaluator continuations are not fully quiescent\""
        );
        return;
    }
    let result = evaluator
        .mutator_root_set()
        .and_then(|mut roots| {
            roots
                .try_push_value_stack(0, value)
                .map_err(TreeWalkSafepointRootError::RootSet)?;
            Ok(roots)
        })
        .map_err(|error| error.to_string())
        .and_then(|roots| {
            evaluator
                .heap
                .weak_liveness_census(&roots)
                .map_err(|error| error.to_string())
        });
    match result {
        Ok(census) => eprintln!("{census}"),
        Err(error) => eprintln!("aos_nix_weak_liveness_census_error {error:?}"),
    }
}

/// Emits terminal suspended-thunk retention by permanent lists and attrsets.
fn emit_permanent_retention_census(evaluator: &TreeWalk, value: Value) {
    if std::env::var_os("AOS_NIX_PERMANENT_RETENTION_CENSUS").is_none() {
        return;
    }
    if !evaluator.has_complete_terminal_root_set() {
        eprintln!(
            "aos_nix_permanent_retention_census_error \
             \"terminal evaluator continuations are not fully quiescent\""
        );
        return;
    }
    let result = evaluator
        .mutator_root_set()
        .and_then(|mut roots| {
            roots
                .try_push_value_stack(0, value)
                .map_err(TreeWalkSafepointRootError::RootSet)?;
            Ok(roots)
        })
        .map_err(|error| error.to_string())
        .and_then(|roots| {
            evaluator
                .heap
                .permanent_composite_retention_census(&roots)
                .map_err(|error| error.to_string())
        });
    match result {
        Ok(census) => eprintln!("{census}"),
        Err(error) => eprintln!("aos_nix_permanent_retention_census_error {error:?}"),
    }
}

/// Emits a default-off high-water reservation-residency sample.
///
/// Both owned entry paths call this after the root and parallel pool have
/// returned but before the optional quiescent sweep. Process RSS is sampled
/// first because `mincore` needs a temporary byte for every used arena page.
fn emit_terminal_reservation_residency(evaluator: &TreeWalk) {
    if !std::env::var("AOS_NIX_RESERVATION_RESIDENCY").is_ok_and(|value| value == "1") {
        return;
    }
    let rss_bytes = ProcessResidentMemorySample::current()
        .ok()
        .flatten()
        .map(ProcessResidentMemorySample::resident_bytes);
    let root_complete = evaluator.has_complete_terminal_root_set();
    match evaluator.heap.flat_reservation_residency() {
        Some(Ok(residency)) => {
            let resident_bytes = residency
                .total_resident_pages
                .saturating_mul(residency.page_size);
            let rss = match rss_bytes {
                Some(bytes) => bytes.to_string(),
                None => "null".to_owned(),
            };
            eprintln!(
                "aos_nix_terminal_reservation_residency \
                 {{\"rss_bytes\":{rss},\"root_complete\":{root_complete},\
                 \"page_size\":{},\"used_pages\":{},\
                 \"resident_pages\":{},\"resident_bytes\":{},\"low_used_bytes\":{},\
                 \"low_pages\":{},\"low_resident_pages\":{},\"high_used_bytes\":{},\
                 \"high_pages\":{},\"high_resident_pages\":{}}}",
                residency.page_size,
                residency.total_pages,
                residency.total_resident_pages,
                resident_bytes,
                residency.low.used_bytes,
                residency.low.pages,
                residency.low.resident_pages,
                residency.high.used_bytes,
                residency.high.pages,
                residency.high.resident_pages,
            );
        }
        Some(Err(error)) => {
            eprintln!("aos_nix_terminal_reservation_residency_error {error:?}")
        }
        None => eprintln!("aos_nix_terminal_reservation_residency unavailable"),
    }
}

/// Emits default-off packed-STG admission and execution counters.
fn emit_stg_apply_census(evaluator: &TreeWalk) {
    if !std::env::var("AOS_NIX_STG_APPLY_CENSUS").is_ok_and(|value| value == "1") {
        return;
    }
    let counters = evaluator.stg_apply_runtime.counters;
    let lower = counters.lower_declines;
    let kind = counters.lower_decline_kinds;
    eprintln!(
        "aos_nix_stg_apply_census \
         {{\"attempts\":{},\"declines\":{},\"cache_hits\":{},\
         \"blocks_lowered\":{},\"claims\":{},\"completions\":{},\
         \"force_continuations\":{},\"oracle_leaves\":{},\
         \"errors\":{},\"panics\":{},\
         \"lower_unsupported_kind\":{},\"lower_unsupported_shape\":{},\
         \"lower_select_default\":{},\"lower_dynamic_select\":{},\
         \"lower_non_unary_lambda\":{},\"lower_missing_frame\":{},\
         \"lower_invalid_slot\":{},\"lower_invalid_capture\":{},\
         \"lower_ambiguous_frame\":{},\"lower_non_numeric_binary\":{},\
         \"lower_operand_too_wide\":{},\"blocks_with_lambda\":{},\
         \"blocks_with_thunk\":{},\"blocks_with_apply\":{},\
         \"blocks_with_select\":{},\"blocks_with_other_primop\":{},\
         \"negative_cache_hits\":{},\"thunk_continuations\":{},\
         \"apply_continuations\":{},\"disqualifier_bitmap_histogram\":{:?}}}",
        counters.attempts,
        counters.declines,
        counters.cache_hits,
        counters.blocks_lowered,
        counters.claims,
        counters.completions,
        counters.force_continuations,
        counters.oracle_leaves,
        counters.errors,
        counters.panics,
        lower[0],
        lower[1],
        lower[2],
        lower[3],
        lower[4],
        lower[5],
        lower[6],
        lower[7],
        lower[8],
        lower[9],
        lower[10],
        counters.blocks_with_lambda,
        counters.blocks_with_thunk,
        counters.blocks_with_apply,
        counters.blocks_with_select,
        counters.blocks_with_other_primop,
        counters.negative_cache_hits,
        counters.thunk_continuations,
        counters.apply_continuations,
        counters.disqualifier_bitmap_histogram,
    );
    eprintln!(
        "aos_nix_stg_decline_kinds \
         {{\"int\":{},\"float\":{},\"bool\":{},\"null\":{},\"str\":{},\
         \"path\":{},\"search_path\":{},\"uri\":{},\"local_var\":{},\
         \"upval_var\":{},\"global_var\":{},\"builtin_attr\":{},\"list\":{},\
         \"attr_set\":{},\"lambda\":{},\"formal_set\":{},\"formal\":{},\
         \"apply\":{},\"select\":{},\"has_attr\":{},\"let\":{},\"with\":{},\
         \"assert\":{},\"if\":{},\"bin_op\":{},\"unary_op\":{},\"interp\":{},\
         \"thunk_alloc\":{},\"primop\":{}}}",
        kind[IrKind::Int as usize],
        kind[IrKind::Float as usize],
        kind[IrKind::Bool as usize],
        kind[IrKind::Null as usize],
        kind[IrKind::Str as usize],
        kind[IrKind::Path as usize],
        kind[IrKind::SearchPath as usize],
        kind[IrKind::Uri as usize],
        kind[IrKind::LocalVar as usize],
        kind[IrKind::UpvalVar as usize],
        kind[IrKind::GlobalVar as usize],
        kind[IrKind::BuiltinAttr as usize],
        kind[IrKind::List as usize],
        kind[IrKind::AttrSet as usize],
        kind[IrKind::Lambda as usize],
        kind[IrKind::FormalSet as usize],
        kind[IrKind::Formal as usize],
        kind[IrKind::Apply as usize],
        kind[IrKind::Select as usize],
        kind[IrKind::HasAttr as usize],
        kind[IrKind::Let as usize],
        kind[IrKind::With as usize],
        kind[IrKind::Assert as usize],
        kind[IrKind::If as usize],
        kind[IrKind::BinOp as usize],
        kind[IrKind::UnaryOp as usize],
        kind[IrKind::Interp as usize],
        kind[IrKind::ThunkAlloc as usize],
        kind[IrKind::PrimOp as usize],
    );
}

#[cfg(feature = "active_packed_thunk_probe")]
fn emit_active_packed_thunk_accounting(evaluator: &TreeWalk) {
    let accounting = evaluator.heap.active_packed_thunk_accounting();
    if accounting.apply_allocated == 0 && accounting.gen_list_elem_at_add_one_allocated == 0 {
        return;
    }
    eprintln!(
        "aos_nix_active_packed_thunks \
         {{\"apply_allocated\":{},\"genlist_allocated\":{},\
         \"initialized_bytes\":{},\"capacity_bytes\":{},\
         \"virtual_reserved_bytes\":{},\"fallbacks\":0}}",
        accounting.apply_allocated,
        accounting.gen_list_elem_at_add_one_allocated,
        accounting.initialized_bytes,
        accounting.capacity_bytes,
        accounting.virtual_reserved_bytes,
    );
}

/// Emits default-off runtime and optional module-root Promise/PIR censuses.
fn emit_promise_region_census(evaluator: &TreeWalk) {
    evaluator.emit_runtime_promise_region_census();
    if !std::env::var("AOS_NIX_PROMISE_REGION_ROOT_CENSUS").is_ok_and(|value| value == "1") {
        return;
    }
    let mut planned_modules = 0_u64;
    let mut failed_modules = 0_u64;
    let mut entry_only_statepoints = 0_u64;
    let mut arena_nodes = 0_u64;
    let mut unique_region_nodes = 0_u64;
    let mut specializations = 0_u64;
    let mut max_specializations = 0_usize;
    let mut virtual_promises = 0_u64;
    let mut virtual_frames = 0_u64;
    let mut virtual_closures = 0_u64;
    let mut virtual_lists = 0_u64;
    let mut virtual_attrs = 0_u64;
    let mut statepoints = [0_u64; 11];

    for (module_index, module) in evaluator.modules.iter().enumerate() {
        arena_nodes = arena_nodes.saturating_add(module.ir.arena.nodes().len() as u64);
        let plan = match plan_promise_region(
            &module.ir,
            module.ir.root,
            None,
            PromiseRegionOptions {
                symbol_validation: PromiseRegionSymbolValidation::ExternallyRemapped,
                ..PromiseRegionOptions::default()
            },
        ) {
            Ok(plan) => plan,
            Err(error) => {
                failed_modules = failed_modules.saturating_add(1);
                let error = error.to_string();
                eprintln!(
                    "aos_nix_promise_region_error \
                     {{\"module\":{module_index},\"error\":{error:?}}}"
                );
                continue;
            }
        };
        planned_modules = planned_modules.saturating_add(1);
        entry_only_statepoints =
            entry_only_statepoints.saturating_add(u64::from(plan.entry_is_only_statepoint));
        unique_region_nodes = unique_region_nodes.saturating_add(plan.unique_ir_nodes as u64);
        specializations = specializations.saturating_add(plan.specialization_count as u64);
        max_specializations = max_specializations.max(plan.max_specializations_per_node);
        virtual_promises =
            virtual_promises.saturating_add(plan.virtual_allocations.promises as u64);
        virtual_frames = virtual_frames.saturating_add(plan.virtual_allocations.frames as u64);
        virtual_closures =
            virtual_closures.saturating_add(plan.virtual_allocations.closures as u64);
        virtual_lists = virtual_lists.saturating_add(plan.virtual_allocations.lists as u64);
        virtual_attrs = virtual_attrs.saturating_add(plan.virtual_allocations.attrs as u64);
        for statepoint in plan.statepoints {
            let index = match statepoint.kind {
                PromiseStatepointKind::Effect => 0,
                PromiseStatepointKind::Global => 1,
                PromiseStatepointKind::DynamicScope => 2,
                PromiseStatepointKind::Dialect => 3,
                PromiseStatepointKind::RecursiveAttrSet => 4,
                PromiseStatepointKind::DynamicAttrSet => 5,
                PromiseStatepointKind::FormalSetLambda => 6,
                PromiseStatepointKind::DynamicSelect => 7,
                PromiseStatepointKind::DefaultSelect => 8,
                PromiseStatepointKind::UnknownCall => 9,
                PromiseStatepointKind::Unsupported => 10,
            };
            statepoints[index] = statepoints[index].saturating_add(1);
        }
    }

    let statepoint_total = statepoints.iter().copied().sum::<u64>();
    let virtual_total = virtual_promises
        .saturating_add(virtual_frames)
        .saturating_add(virtual_closures)
        .saturating_add(virtual_lists)
        .saturating_add(virtual_attrs);
    eprintln!(
        "aos_nix_promise_region_census \
         {{\"modules\":{},\"planned_modules\":{planned_modules},\
         \"failed_modules\":{failed_modules},\
         \"entry_only_statepoints\":{entry_only_statepoints},\
         \"arena_nodes\":{arena_nodes},\"unique_region_nodes\":{unique_region_nodes},\
         \"specializations\":{specializations},\
         \"max_specializations_per_node\":{max_specializations},\
         \"virtual_allocations\":{{\"total\":{virtual_total},\
         \"promises\":{virtual_promises},\"frames\":{virtual_frames},\
         \"closures\":{virtual_closures},\"lists\":{virtual_lists},\
         \"attrs\":{virtual_attrs}}},\
         \"statepoints\":{{\"total\":{statepoint_total},\"effect\":{},\
         \"global\":{},\"dynamic_scope\":{},\"dialect\":{},\
         \"recursive_attrset\":{},\"dynamic_attrset\":{},\
         \"formal_set_lambda\":{},\"dynamic_select\":{},\
         \"default_select\":{},\"unknown_call\":{},\"unsupported\":{}}}}}",
        evaluator.modules.len(),
        statepoints[0],
        statepoints[1],
        statepoints[2],
        statepoints[3],
        statepoints[4],
        statepoints[5],
        statepoints[6],
        statepoints[7],
        statepoints[8],
        statepoints[9],
        statepoints[10],
    );
}

impl TreeWalk {
    /// Emits a default-off current-RSS and arena phase sample.
    pub(super) fn emit_resident_phase(&self, phase: &str) {
        if !std::env::var("AOS_NIX_RSS_PHASES").is_ok_and(|value| value == "1") {
            return;
        }
        let rss = ProcessResidentMemorySample::current()
            .ok()
            .flatten()
            .map(ProcessResidentMemorySample::resident_bytes);
        let worker = self.heap.arena_stats();
        let permanent = self.heap.permanent_arena_stats();
        match rss {
            Some(rss_bytes) => eprintln!(
                "aos_nix_rss_phase phase={phase} modules={} rss_bytes={rss_bytes} \
                 worker_mapped_bytes={} worker_used_bytes={} permanent_mapped_bytes={} \
                 permanent_used_bytes={}",
                self.modules.len(),
                worker.mapped_bytes,
                worker.used_bytes,
                permanent.mapped_bytes,
                permanent.used_bytes,
            ),
            None => eprintln!(
                "aos_nix_rss_phase phase={phase} modules={} rss_bytes=unavailable \
                 worker_mapped_bytes={} worker_used_bytes={} permanent_mapped_bytes={} \
                 permanent_used_bytes={}",
                self.modules.len(),
                worker.mapped_bytes,
                worker.used_bytes,
                permanent.mapped_bytes,
                permanent.used_bytes,
            ),
        }
    }

    /// Emits a weak-root liveness sample at selected import milestones.
    pub(super) fn emit_weak_liveness_import_milestone(&mut self) {
        let modules = self.modules.len();
        #[cfg(feature = "evacuation_plan_probe")]
        self.emit_evacuation_plan_projection(modules);
        #[cfg(feature = "compact_destination_probe")]
        self.emit_compact_destination_projection(modules);
        #[cfg(feature = "nonmoving_reclaim_probe")]
        self.emit_nonmoving_reclaim_projection(modules);
        #[cfg(feature = "ready_exclusive_probe")]
        self.capture_ready_exclusive_window(modules);
        if !matches!(
            modules,
            64 | 128 | 256 | 512 | 1024 | 1152 | 1200 | 1216 | 1220
        ) {
            return;
        }
        self.emit_resident_phase("import-milestone");
        if std::env::var_os("AOS_NIX_WEAK_LIVENESS_CENSUS").is_none() {
            return;
        }
        let result = self
            .mutator_root_set()
            .map_err(|error| error.to_string())
            .and_then(|roots| {
                self.heap
                    .weak_liveness_census(&roots)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(census) => {
                eprintln!("aos_nix_weak_liveness_milestone modules={modules} {census}")
            }
            Err(error) => {
                eprintln!("aos_nix_weak_liveness_milestone_error modules={modules} {error:?}")
            }
        }
    }

    /// Emits the read-only same-layout evacuation plan at selected milestones.
    #[cfg(feature = "evacuation_plan_probe")]
    fn emit_evacuation_plan_projection(&self, modules: usize) {
        const CAPTURE_MODULES: [usize; 8] = [512, 768, 896, 1024, 1088, 1152, 1188, 1220];
        if !CAPTURE_MODULES.contains(&modules)
            || !std::env::var("AOS_NIX_EVACUATION_PLAN_PROBE").is_ok_and(|value| value == "1")
        {
            return;
        }
        let result = self
            .mutator_root_set()
            .map_err(|error| error.to_string())
            .and_then(|roots| {
                self.heap
                    .evacuation_plan(&roots)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(plan) => eprintln!("aos_nix_evacuation_plan modules={modules} {plan}"),
            Err(error) => eprintln!(
                "aos_nix_evacuation_plan_error \
                 {{\"modules\":{modules},\"error\":{error:?}}}"
            ),
        }
    }

    /// Emits the read-only compact-destination projection at the peak-band entry.
    #[cfg(feature = "compact_destination_probe")]
    fn emit_compact_destination_projection(&self, modules: usize) {
        const CAPTURE_MODULES: [usize; 9] = [512, 768, 896, 1024, 1088, 1152, 1188, 1200, 1220];
        if !CAPTURE_MODULES.contains(&modules)
            || !std::env::var("AOS_NIX_COMPACT_DESTINATION_PROBE").is_ok_and(|value| value == "1")
        {
            return;
        }
        let result = self
            .mutator_root_set()
            .map_err(|error| error.to_string())
            .and_then(|roots| {
                self.heap
                    .compact_destination_projection(&roots)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(projection) => {
                eprintln!("aos_nix_compact_destination modules={modules} {projection}")
            }
            Err(error) => eprintln!(
                "aos_nix_compact_destination_error \
                 {{\"modules\":{modules},\"error\":{error:?}}}"
            ),
        }
    }

    /// Emits the read-only nonmoving reclamation projection.
    #[cfg(feature = "nonmoving_reclaim_probe")]
    fn emit_nonmoving_reclaim_projection(&self, modules: usize) {
        const CAPTURE_MODULES: [usize; 9] = [512, 768, 896, 1024, 1088, 1152, 1188, 1200, 1220];
        let selected_module = std::env::var("AOS_NIX_NONMOVING_RECLAIM_MODULE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok());
        let selected = selected_module.map_or_else(
            || CAPTURE_MODULES.contains(&modules),
            |value| value == modules,
        );
        if !selected
            || !std::env::var("AOS_NIX_NONMOVING_RECLAIM_PROBE").is_ok_and(|value| value == "1")
        {
            return;
        }
        let rss = ProcessResidentMemorySample::current()
            .ok()
            .flatten()
            .map_or(0, ProcessResidentMemorySample::resident_bytes);
        let peak_rss = peak_resident_memory_bytes(PeakResidentMemoryScope::SelfProcess)
            .ok()
            .flatten()
            .unwrap_or(rss as u64);
        let result = self
            .mutator_root_set()
            .map_err(|error| error.to_string())
            .and_then(|roots| {
                self.heap
                    .nonmoving_reclaim_projection(
                        &roots,
                        rss as u64,
                        peak_rss,
                        modules,
                        selected_module.is_some(),
                        &[],
                    )
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(projection) => {
                eprintln!("aos_nix_nonmoving_reclaim modules={modules} {projection}")
            }
            Err(error) => eprintln!(
                "aos_nix_nonmoving_reclaim_error \
                 {{\"modules\":{modules},\"error\":{error:?}}}"
            ),
        }
    }

    /// Captures Ready-import-exclusive ownership before the final demand window.
    #[cfg(feature = "ready_exclusive_probe")]
    fn capture_ready_exclusive_window(&mut self, modules: usize) {
        const CAPTURE_MODULES: usize = 1188;
        if modules != CAPTURE_MODULES
            || self.ready_exclusive_window.is_some()
            || !std::env::var("AOS_NIX_READY_EXCLUSIVE_PROBE").is_ok_and(|value| value == "1")
        {
            return;
        }
        let census = self
            .mutator_root_set()
            .map_err(|error| error.to_string())
            .and_then(|roots| {
                self.heap
                    .ready_exclusive_census(&roots)
                    .map_err(|error| error.to_string())
            });
        match census {
            Ok(census) => {
                eprintln!(
                    "aos_nix_ready_exclusive_capture \
                     {{\"modules\":{modules},\"ready_roots\":{},\"other_roots\":{},\
                     \"all_objects\":{},\"ready_objects\":{},\"other_objects\":{},\
                     \"shared_objects\":{},\"union_reconciled\":{},\
                     \"unclassified_objects\":{},\"candidates\":{},\
                     \"inline_bytes\":{},\"list_spine_bytes\":{},\"bytes\":{}}}",
                    census.ready_roots(),
                    census.other_roots(),
                    census.all_reachable_objects(),
                    census.ready_reachable_objects(),
                    census.other_reachable_objects(),
                    census.shared_reachable_objects(),
                    census.union_reconciled(),
                    census.unclassified_exclusive_objects(),
                    census.candidates().len(),
                    census.inline_bytes(),
                    census.list_spine_bytes(),
                    census.attributable_bytes(),
                );
                self.ready_exclusive_window = Some(census);
            }
            Err(error) => {
                eprintln!(
                    "aos_nix_ready_exclusive_capture_error \
                     {{\"modules\":{modules},\"error\":{error:?}}}"
                );
            }
        }
    }

    /// Classifies captured Ready-exclusive bytes by access in the final window.
    #[cfg(feature = "ready_exclusive_probe")]
    fn emit_ready_exclusive_window_report(&self) {
        if !std::env::var("AOS_NIX_READY_EXCLUSIVE_PROBE").is_ok_and(|value| value == "1") {
            return;
        }
        let Some(census) = self.ready_exclusive_window.as_ref() else {
            eprintln!("aos_nix_ready_exclusive_window_error \"capture milestone not reached\"");
            return;
        };
        let mut touched_count = 0_u64;
        let mut touched_bytes = 0_u64;
        let mut cold_count = 0_u64;
        let mut cold_bytes = 0_u64;
        let mut unattributed_count = 0_u64;
        let mut unattributed_bytes = 0_u64;
        for candidate in census.candidates() {
            let bytes = candidate.attributable_bytes();
            match (
                candidate.initial_touch_epoch(),
                self.heap.ready_exclusive_candidate_touch_epoch(*candidate),
            ) {
                (Some(initial), Some(current)) if current > initial => {
                    touched_count = touched_count.saturating_add(1);
                    touched_bytes = touched_bytes.saturating_add(bytes);
                }
                (Some(initial), Some(current)) if current == initial => {
                    cold_count = cold_count.saturating_add(1);
                    cold_bytes = cold_bytes.saturating_add(bytes);
                }
                _ => {
                    unattributed_count = unattributed_count.saturating_add(1);
                    unattributed_bytes = unattributed_bytes.saturating_add(bytes);
                }
            }
        }
        eprintln!(
            "aos_nix_ready_exclusive_window \
             {{\"capture_candidates\":{},\"capture_bytes\":{},\
             \"touched\":[{touched_count},{touched_bytes}],\
             \"cold\":[{cold_count},{cold_bytes}],\
             \"unattributed\":[{unattributed_count},{unattributed_bytes}],\
             \"bytes_reconciled\":{}}}",
            census.candidates().len(),
            census.attributable_bytes(),
            touched_bytes
                .saturating_add(cold_bytes)
                .saturating_add(unattributed_bytes)
                == census.attributable_bytes(),
        );
    }
}

/// Emits the default-off flat-store and hash-cons capacity census.
fn emit_heap_storage_census(evaluator: &TreeWalk) {
    if std::env::var_os("AOS_NIX_STORAGE_CENSUS").is_none() {
        return;
    }
    evaluator.heap.emit_storage_census();
    let ir_bytes = evaluator
        .modules
        .iter()
        .map(|module| module.ir.resident_bytes())
        .sum::<usize>();
    let source_bytes = evaluator
        .modules
        .iter()
        .filter_map(|module| module.source.as_ref())
        .map(|source| {
            source
                .name
                .capacity()
                .saturating_add(source.bytes.capacity())
        })
        .sum::<usize>();
    let path_base_bytes = evaluator
        .modules
        .iter()
        .filter_map(|module| module.path_literal_base.as_ref())
        .map(Vec::capacity)
        .sum::<usize>();
    eprintln!(
        "aos_nix_module_storage_census {{\"modules\":[{},{}],\
         \"module_table_bytes\":{},\"ir_bytes\":{ir_bytes},\
         \"source_bytes\":{source_bytes},\"path_base_bytes\":{path_base_bytes}}}",
        evaluator.modules.len(),
        evaluator.modules.capacity(),
        evaluator
            .modules
            .capacity()
            .saturating_mul(std::mem::size_of::<TreeWalkModule>()),
    );
}

/// Emits candidate lowered nodes for the `lib/modules.nix` direct-island wall.
fn emit_direct_island_site_report(evaluator: &TreeWalk) {
    if std::env::var_os("AOS_NIX_DIRECT_ISLAND_SITES").is_none() {
        return;
    }
    const START: &[u8] = b"if freeformType == null && !isStrict";
    const END: &[u8] = b"in {\n      config = configWithFreeform;";
    for (module_index, module) in evaluator.modules.iter().enumerate() {
        let Some(source) = module.source.as_ref() else {
            continue;
        };
        if !source.name.ends_with(b"/lib/modules.nix") {
            continue;
        }
        let Some(start) = source
            .bytes
            .windows(START.len())
            .position(|window| window == START)
        else {
            continue;
        };
        let Some(end_start) = source
            .bytes
            .windows(END.len())
            .position(|window| window == END)
        else {
            continue;
        };
        let end = end_start.saturating_add(2);
        for (node_index, node) in module.ir.arena.nodes().iter().enumerate() {
            let node_start = node.span.start as usize;
            let node_end = node.span.end as usize;
            if node_start <= start && node_end >= start || node_start >= start && node_start < end {
                eprintln!(
                    "aos_nix_direct_island_site {{\"module\":{module_index},\
                     \"node\":{node_index},\"kind\":\"{:?}\",\"span\":[{},{}],\
                     \"target\":[{start},{end}]}}",
                    node.kind, node.span.start, node.span.end
                );
            }
        }
    }
}

/// Emits the default-off inclusive wall and dynamic-force coverage probe.
fn emit_direct_island_probe_report(evaluator: &TreeWalk) {
    let Some(report) = evaluator.direct_island_probe_report() else {
        return;
    };
    eprintln!(
        "aos_nix_direct_island_probe {{\"entries\":{},\"total_ns\":{},\
         \"island_ns\":{},\"total_forces\":{},\"island_forces\":{}}}",
        report.entries,
        report.total_ns,
        report.island_ns,
        report.total_forces,
        report.island_forces
    );
}

fn finish_owned_eval_outcome(
    mut evaluator: TreeWalk,
    value: Value,
    stats: EvalStats,
    derivations: Vec<EvalDerivation>,
    gc_stress_boundary_scans: EvalGcStressBoundaryScans,
    tier_b_transition_admission_id: IrId,
    tier_b_transition_admission_span: Span,
) -> Result<EvalOutcome, TreeWalkError> {
    evaluator.advance_persist_eval_cache_run_boundary();
    let memory_budget_action = evaluator.heap.last_memory_budget_action();
    let (
        cheap_memory_budget_plan,
        cheap_memory_advice_report,
        cold_hash_consed_value_materialization,
    ) = post_eval_heap_memory_reports(&mut evaluator);
    let apply_tier_b_transition_admission =
        evaluator.options.heap_tier_b_transition_admission_enabled();
    let mut outcome = EvalOutcome {
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
    };

    if apply_tier_b_transition_admission {
        outcome
            .apply_tier_b_transition_admission_plan()
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::TierBTransitionAdmission {
                        id: tier_b_transition_admission_id,
                        source,
                    },
                    tier_b_transition_admission_span,
                )
            })?;
    }

    Ok(outcome)
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

pub(in crate::eval) fn eval_raw_bytes_with_evaluator(
    ir: &Ir,
    evaluator: TreeWalk,
) -> Result<Vec<u8>, TreeWalkError> {
    let (out, _) = eval_raw_bytes_with_evaluator_owned(ir, evaluator)?;
    Ok(out)
}

pub(in crate::eval) fn eval_raw_bytes_with_evaluator_owned(
    ir: &Ir,
    mut evaluator: TreeWalk,
) -> Result<(Vec<u8>, TreeWalk), TreeWalkError> {
    evaluator.heap.set_attrs_hash_cons_enabled(false);
    let pool = parallel_demand::ParallelDemandPool::spawn(&mut evaluator);
    let out = evaluator
        .eval_root()
        .and_then(|value| render_raw_value_with_evaluator(&mut evaluator, ir, value));
    if let Some(pool) = pool {
        pool.finish(&mut evaluator);
    }
    evaluator.emit_formal_set_ready_census_report();
    let out = out?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    evaluator.advance_persist_eval_cache_run_boundary();
    Ok((out, evaluator))
}

pub(in crate::eval) fn eval_raw_bytes_with_post_render_tier_b_admission(
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<
    (
        Vec<u8>,
        Vec<u8>,
        Option<EvalHeapTierBAdmissionReport>,
        EvalStats,
    ),
    TreeWalkError,
> {
    let mut evaluator = TreeWalk::with_options(ir, options);
    evaluator.heap.set_attrs_hash_cons_enabled(false);
    let value = evaluator.eval_root()?;
    let pre_admission = render_raw_value_with_evaluator(&mut evaluator, ir, value)?;
    let span = evaluator.node(ir.root)?.span;
    let admission_report =
        apply_raw_tier_b_transition_admission_if_requested(&mut evaluator, ir.root, span)?;
    let post_admission = render_raw_value_with_evaluator(&mut evaluator, ir, value)?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    evaluator.advance_persist_eval_cache_run_boundary();
    Ok((pre_admission, post_admission, admission_report, stats))
}

/// Evaluates an IR root and returns recorded derivation path/ATerm surfaces.
///
/// This forces root-visible derivation attrsets enough for snapshot collection,
/// but the returned bytes are the evaluator's derivation side-table surfaces,
/// not a filesystem read of materialized `.drv` files.
pub(in crate::eval) fn eval_derivation_aterm_surfaces_with_options(
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<Vec<(String, Vec<u8>)>, TreeWalkError> {
    let mut evaluator = TreeWalk::with_options(ir, options);
    let value = evaluator.eval_root()?;
    evaluator.force_root_derivation_surfaces(value)?;
    let surfaces = evaluator.derivation_surface_snapshot()?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    evaluator.advance_persist_eval_cache_run_boundary();
    Ok(surfaces)
}

fn render_raw_value_with_evaluator(
    evaluator: &mut TreeWalk,
    ir: &Ir,
    value: Value,
) -> Result<Vec<u8>, TreeWalkError> {
    let span = evaluator.node(ir.root)?.span;
    let mut out = Vec::new();
    let mut visited = Vec::new();
    evaluator.write_raw_value(ir.root, span, ir.root, span, value, &mut out, &mut visited)?;
    Ok(out)
}

fn apply_raw_tier_b_transition_admission_if_requested(
    evaluator: &mut TreeWalk,
    id: IrId,
    span: Span,
) -> Result<Option<EvalHeapTierBAdmissionReport>, TreeWalkError> {
    if !evaluator.options.heap_tier_b_transition_admission_enabled() {
        return Ok(None);
    }
    let Some(action) = evaluator.heap.last_memory_budget_action() else {
        return Ok(None);
    };
    let Some(request) = EvalTierBTransitionRequest::from_memory_budget_action(action) else {
        return Ok(None);
    };

    let admission = request.admission_plan(&evaluator.heap).map_err(|source| {
        raw_tier_b_transition_admission_error(
            id,
            span,
            EvalTierBTransitionAdmissionApplyError::Plan(source),
        )
    })?;
    let report = evaluator
        .heap
        .apply_tier_b_admission_plan(admission.heap_plan())
        .map_err(|source| {
            raw_tier_b_transition_admission_error(
                id,
                span,
                EvalTierBTransitionAdmissionApplyError::Heap(source),
            )
        })?;
    evaluator.stats.record_heap_tier_b_admission(report);
    Ok(Some(report))
}

fn raw_tier_b_transition_admission_error(
    id: IrId,
    span: Span,
    source: EvalTierBTransitionAdmissionApplyError,
) -> TreeWalkError {
    TreeWalkError::new(
        TreeWalkErrorKind::TierBTransitionAdmission { id, source },
        span,
    )
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
    let bytes = evaluator.raw_number_bytes(ir.root, span, value)?;
    let stats = evaluator.stats_snapshot();
    TreeWalk::emit_stats_trace(&stats);
    evaluator.advance_persist_eval_cache_run_boundary();
    Ok(bytes)
}
