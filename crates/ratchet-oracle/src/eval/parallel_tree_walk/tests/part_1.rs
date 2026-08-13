//! Parallel tree-walk driver tests, continued.

use super::*;

#[test]
fn chase_lev_parallel_drv_output_eval_summarizes_successful_worker_heaps() {
    let roots = [
        derivation_root("parallel-drv-worker-heap-alpha"),
        derivation_root("parallel-drv-worker-heap-beta"),
    ];

    let report = eval_drv_outputs_parallel_chase_lev_top_level_roots(
        roots,
        workers(1),
        ParallelFailurePolicy::CollectAll,
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev .drv evaluation completes");
    let summaries = summarize_parallel_tree_walk_drv_worker_heaps(&report);
    let expected_heap_records = report
        .outcomes()
        .iter()
        .map(|outcome| {
            outcome
                .outcome()
                .as_ref()
                .expect("root succeeded")
                .worker_heap_report()
                .heap_records()
        })
        .sum::<usize>();
    let expected_worker_safepoints = report
        .outcomes()
        .iter()
        .map(|outcome| {
            outcome
                .outcome()
                .as_ref()
                .expect("root succeeded")
                .worker_heap_report()
                .worker_allocation_safepoints()
        })
        .sum::<u64>();

    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].worker_id(), 0);
    assert_eq!(summaries[0].successful_tasks(), 2);
    assert_eq!(summaries[0].heap_records(), expected_heap_records);
    assert_eq!(
        summaries[0].worker_allocation_safepoints(),
        expected_worker_safepoints
    );
    assert!(summaries[0].heap_records() > 0);
    assert!(summaries[0].worker_allocation_safepoints() > 0);
    assert!(summaries[0].all_successful_tasks_used_thread_local_tier_a());
}

#[test]
fn chase_lev_parallel_drv_output_differential_does_not_force_non_string_root_contexts() {
    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [derivation_attrset_root("parallel-drv-attrset-root-context")],
        [workers(1), workers(3)],
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev .drv differential matches serial attrset roots");

    assert_eq!(report.task_count(), 1);
    assert_eq!(report.worker_counts(), &[1, 3]);
    assert_eq!(report.collation().fragment_count(), 1);
    assert_eq!(report.collation().drv_output_count(), 1);
    assert!(report.collation().string_context().is_empty());
}

#[test]
fn chase_lev_parallel_drv_output_differential_forces_unforced_derivation_attrset_root() {
    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [unforced_derivation_attrset_root(
            "parallel-drv-unforced-attrset-root",
        )],
        [workers(1), workers(3)],
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev .drv differential forces unforced attrset root derivations");

    assert_eq!(report.task_count(), 1);
    assert_eq!(report.worker_counts(), &[1, 3]);
    assert_eq!(report.collation().fragment_count(), 1);
    assert_eq!(report.collation().drv_output_count(), 1);
    assert!(report.collation().string_context().is_empty());
    assert!(
        report.collation().drv_outputs()[0]
            .path()
            .ends_with(b".drv")
    );
}

#[test]
fn chase_lev_parallel_drv_output_differential_forces_derivation_attrset_list_roots() {
    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [derivation_attrset_list_root("parallel-drv-attrset-list")],
        [workers(1), workers(3)],
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev .drv differential forces root list derivation attrsets");

    assert_eq!(report.task_count(), 1);
    assert_eq!(report.worker_counts(), &[1, 3]);
    assert_eq!(report.collation().fragment_count(), 1);
    assert_eq!(report.collation().drv_output_count(), 2);
    assert!(report.collation().string_context().is_empty());
    assert!(
        report
            .collation()
            .drv_outputs()
            .iter()
            .all(|output| output.path().ends_with(b".drv"))
    );
}

#[test]
fn chase_lev_parallel_drv_output_differential_does_not_descend_into_nested_root_lists() {
    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [expression_root(
            r#"[[ (derivation { name = "parallel-drv-nested-list"; system = ":"; builder = ":"; }) ]]"#,
        )],
        [workers(1), workers(3)],
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev .drv differential does not recurse into nested root lists");

    assert_eq!(report.task_count(), 1);
    assert_eq!(report.worker_counts(), &[1, 3]);
    assert_eq!(report.collation().fragment_count(), 1);
    assert_eq!(report.collation().drv_output_count(), 0);
    assert!(report.collation().string_context().is_empty());
}

#[test]
fn chase_lev_parallel_drv_output_differential_normalizes_lazy_foldl_surface_attrs() {
    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [expression_root(
            r#"let d = derivation { name = "parallel-drv-lazy-foldl-surface"; system = ":"; builder = ":"; }; in {
                type = builtins.foldl' (acc: _: acc) "derivation" [ 1 ];
                drvPath = builtins.foldl' (acc: _: acc) d.drvPath [ 1 ];
            }"#,
        )],
        [workers(1), workers(3)],
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev .drv differential normalizes lazy foldl surface attrs");

    assert_eq!(report.task_count(), 1);
    assert_eq!(report.worker_counts(), &[1, 3]);
    assert_eq!(report.collation().fragment_count(), 1);
    assert_eq!(report.collation().drv_output_count(), 1);
    assert!(report.collation().string_context().is_empty());
    assert!(
        report.collation().drv_outputs()[0]
            .path()
            .ends_with(b".drv")
    );
}

#[test]
fn chase_lev_parallel_drv_output_differential_ignores_missing_or_non_string_fake_drv_paths() {
    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [
            expression_root(
                r#"{ type = "derivation"; nested = builtins.throw "fake derivation attrset forced"; }"#,
            ),
            expression_root(
                r#"{ type = "derivation"; drvPath = 42; nested = builtins.throw "fake derivation attrset forced"; }"#,
            ),
        ],
        [workers(1), workers(3)],
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev .drv differential ignores missing/non-string fake drvPath roots");

    assert_eq!(report.task_count(), 2);
    assert_eq!(report.worker_counts(), &[1, 3]);
    assert_eq!(report.collation().fragment_count(), 2);
    assert_eq!(report.collation().drv_output_count(), 0);
    assert!(report.collation().string_context().is_empty());
}

#[test]
fn chase_lev_parallel_drv_output_differential_accepts_empty_roots_with_worker_counts() {
    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        std::iter::empty::<ParallelTreeWalkRoot>(),
        [workers(1), workers(2)],
        TreeWalkOptions::default(),
    )
    .expect("empty .drv root sets compare successfully");

    assert_eq!(report.task_count(), 0);
    assert_eq!(report.worker_counts(), &[1, 2]);
    assert_eq!(report.collation().fragment_count(), 0);
    assert_eq!(report.collation().drv_output_count(), 0);
    assert!(report.collation().string_context().is_empty());
}

#[test]
fn parallel_raw_differential_accepts_empty_roots_with_worker_counts() {
    let report = compare_parallel_tree_walk_raw_across_worker_counts(
        std::iter::empty::<ParallelTreeWalkRoot>(),
        [workers(1), workers(2)],
        TreeWalkOptions::default(),
    )
    .expect("empty root sets compare successfully");

    assert_eq!(report.task_count(), 0);
    assert_eq!(report.worker_counts(), &[1, 2]);
    assert!(report.serial_outcomes().is_empty());
}

#[test]
fn chase_lev_parallel_raw_differential_accepts_empty_roots_with_worker_counts() {
    let report = compare_parallel_tree_walk_raw_chase_lev_across_worker_counts(
        std::iter::empty::<ParallelTreeWalkRoot>(),
        [workers(1), workers(2)],
        TreeWalkOptions::default(),
    )
    .expect("empty root sets compare successfully");

    assert_eq!(report.task_count(), 0);
    assert_eq!(report.worker_counts(), &[1, 2]);
    assert!(report.serial_outcomes().is_empty());
}

#[test]
fn parallel_raw_differential_rejects_empty_worker_counts() {
    let error = compare_parallel_tree_walk_raw_across_worker_counts(
        [ParallelTreeWalkRoot::expression(lower("1"))],
        [],
        TreeWalkOptions::default(),
    )
    .expect_err("empty worker-count list is rejected");

    assert_eq!(error, ParallelTreeWalkDifferentialError::NoWorkerCounts);
}

#[test]
fn chase_lev_parallel_raw_differential_rejects_empty_worker_counts() {
    let error = compare_parallel_tree_walk_raw_chase_lev_across_worker_counts(
        [ParallelTreeWalkRoot::expression(lower("1"))],
        [],
        TreeWalkOptions::default(),
    )
    .expect_err("empty worker-count list is rejected");

    assert_eq!(error, ParallelTreeWalkDifferentialError::NoWorkerCounts);
}

#[test]
fn chase_lev_parallel_drv_output_differential_rejects_empty_worker_counts() {
    let error = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [derivation_root("parallel-drv-empty-worker-counts")],
        [],
        TreeWalkOptions::default(),
    )
    .expect_err("empty worker-count list is rejected");

    assert_eq!(error, ParallelTreeWalkDrvDifferentialError::NoWorkerCounts);
}

#[test]
fn parallel_raw_differential_preflights_worker_counts_before_serial_eval() {
    let worker_count = usize::try_from(crate::eval::PARALLEL_THUNK_MAX_WORKER_ID)
        .ok()
        .and_then(|max_worker_id| max_worker_id.checked_add(1));
    let Some(worker_count) = worker_count else {
        return;
    };
    let worker_count = NonZeroUsize::new(worker_count).expect("test worker count is nonzero");

    let error = compare_parallel_tree_walk_raw_across_worker_counts(
        [ParallelTreeWalkRoot::expression(lower(
            "builtins.throw \"not reached\"",
        ))],
        [worker_count],
        TreeWalkOptions::default(),
    )
    .expect_err("oversized worker count is rejected before serial evaluation");

    assert!(matches!(
        error,
        ParallelTreeWalkDifferentialError::WorkerCountOutOfRange {
            worker_count: rejected_count,
            worker_id,
        } if rejected_count == worker_count.get() && worker_id == worker_count.get() - 1
    ));
}

#[test]
fn chase_lev_parallel_raw_differential_preflights_worker_counts_before_serial_eval() {
    let worker_count = usize::try_from(crate::eval::PARALLEL_THUNK_MAX_WORKER_ID)
        .ok()
        .and_then(|max_worker_id| max_worker_id.checked_add(1));
    let Some(worker_count) = worker_count else {
        return;
    };
    let worker_count = NonZeroUsize::new(worker_count).expect("test worker count is nonzero");

    let error = compare_parallel_tree_walk_raw_chase_lev_across_worker_counts(
        [ParallelTreeWalkRoot::expression(lower(
            "builtins.throw \"not reached\"",
        ))],
        [worker_count],
        TreeWalkOptions::default(),
    )
    .expect_err("oversized worker count is rejected before serial evaluation");

    assert!(matches!(
        error,
        ParallelTreeWalkDifferentialError::WorkerCountOutOfRange {
            worker_count: rejected_count,
            worker_id,
        } if rejected_count == worker_count.get() && worker_id == worker_count.get() - 1
    ));
}

#[test]
fn chase_lev_parallel_raw_differential_rejects_worker_count_without_serial_eval() {
    let worker_count = usize::try_from(crate::eval::PARALLEL_THUNK_MAX_WORKER_ID)
        .ok()
        .and_then(|max_worker_id| max_worker_id.checked_add(1));
    let Some(worker_count) = worker_count else {
        return;
    };
    let worker_count = NonZeroUsize::new(worker_count).expect("test worker count is nonzero");
    let serial_called = AtomicBool::new(false);

    let error = compare_parallel_tree_walk_raw_across_worker_counts_with(
        [ParallelTreeWalkRoot::expression(lower("1"))],
        [worker_count],
        TreeWalkOptions::default(),
        |_, _| {
            serial_called.store(true, Ordering::Relaxed);
            Ok(Vec::new())
        },
        eval_raw_bytes_parallel_chase_lev_top_level_roots,
    )
    .expect_err("oversized worker count is rejected before serial evaluation");

    assert!(matches!(
        error,
        ParallelTreeWalkDifferentialError::WorkerCountOutOfRange {
            worker_count: rejected_count,
            worker_id,
        } if rejected_count == worker_count.get() && worker_id == worker_count.get() - 1
    ));
    assert!(
        !serial_called.load(Ordering::Relaxed),
        "worker-count preflight must run before serial tree-walk evaluation"
    );
}

#[test]
fn chase_lev_parallel_drv_output_differential_preflights_worker_counts_before_serial_eval() {
    let worker_count = usize::try_from(crate::eval::PARALLEL_THUNK_MAX_WORKER_ID)
        .ok()
        .and_then(|max_worker_id| max_worker_id.checked_add(1));
    let Some(worker_count) = worker_count else {
        return;
    };
    let worker_count = NonZeroUsize::new(worker_count).expect("test worker count is nonzero");

    let error = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [ParallelTreeWalkRoot::expression(lower(
            "builtins.throw \"not reached\"",
        ))],
        [worker_count],
        TreeWalkOptions::default(),
    )
    .expect_err("oversized worker count is rejected before serial evaluation");

    assert!(matches!(
        error,
        ParallelTreeWalkDrvDifferentialError::WorkerCountOutOfRange {
            worker_count: rejected_count,
            worker_id,
        } if rejected_count == worker_count.get() && worker_id == worker_count.get() - 1
    ));
}

#[test]
fn parallel_raw_differential_rejects_persistent_cache_roots() {
    let options = TreeWalkOptions::with_parse_cache_root("/tmp/aos-parallel-diff-parse-cache");

    let error = compare_parallel_tree_walk_raw_across_worker_counts(
        [ParallelTreeWalkRoot::expression(lower("1"))],
        [workers(1)],
        options,
    )
    .expect_err("persistent cache roots are rejected");

    assert_eq!(
        error,
        ParallelTreeWalkDifferentialError::StatefulCacheOptionsUnsupported {
            parse_cache_root: true,
            persist_cache_root: false,
        }
    );
}

#[test]
fn chase_lev_parallel_raw_differential_rejects_persistent_eval_cache_roots() {
    let options = TreeWalkOptions::with_persist_cache_root("/tmp/aos-chase-lev-diff-persist-cache");

    let error = compare_parallel_tree_walk_raw_chase_lev_across_worker_counts(
        [ParallelTreeWalkRoot::expression(lower("1"))],
        [workers(1)],
        options,
    )
    .expect_err("persistent eval-cache roots are rejected");

    assert_eq!(
        error,
        ParallelTreeWalkDifferentialError::StatefulCacheOptionsUnsupported {
            parse_cache_root: false,
            persist_cache_root: true,
        }
    );
}

#[test]
fn chase_lev_parallel_raw_differential_rejects_persistent_cache_roots() {
    let options = TreeWalkOptions::with_parse_cache_root("/tmp/aos-chase-lev-diff-parse-cache");

    let error = compare_parallel_tree_walk_raw_chase_lev_across_worker_counts(
        [ParallelTreeWalkRoot::expression(lower("1"))],
        [workers(1)],
        options,
    )
    .expect_err("persistent cache roots are rejected");

    assert_eq!(
        error,
        ParallelTreeWalkDifferentialError::StatefulCacheOptionsUnsupported {
            parse_cache_root: true,
            persist_cache_root: false,
        }
    );
}

#[test]
fn chase_lev_parallel_drv_output_differential_rejects_persistent_cache_roots() {
    let options = TreeWalkOptions::with_parse_cache_root("/tmp/aos-chase-lev-drv-diff-parse-cache");

    let error = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [derivation_root("parallel-drv-persistent-cache")],
        [workers(1)],
        options,
    )
    .expect_err("persistent cache roots are rejected");

    assert_eq!(
        error,
        ParallelTreeWalkDrvDifferentialError::StatefulCacheOptionsUnsupported {
            parse_cache_root: true,
            persist_cache_root: false,
        }
    );
}

#[test]
fn chase_lev_parallel_drv_output_differential_rejects_persistent_eval_cache_roots() {
    let options =
        TreeWalkOptions::with_persist_cache_root("/tmp/aos-chase-lev-drv-diff-persist-cache");

    let error = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [derivation_root("parallel-drv-persistent-eval-cache")],
        [workers(1)],
        options,
    )
    .expect_err("persistent eval-cache roots are rejected");

    assert_eq!(
        error,
        ParallelTreeWalkDrvDifferentialError::StatefulCacheOptionsUnsupported {
            parse_cache_root: false,
            persist_cache_root: true,
        }
    );
}

#[test]
fn chase_lev_parallel_drv_output_differential_reports_serial_root_errors() {
    let error = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        [ParallelTreeWalkRoot::expression(lower(
            "builtins.throw \"drv surface failed\"",
        ))],
        [workers(1)],
        TreeWalkOptions::default(),
    )
    .expect_err("serial derivation-surface errors are reported before parallel runs");

    assert!(
        matches!(
            error,
            ParallelTreeWalkDrvDifferentialError::SerialRoot {
                task_index: 0,
                source: ParallelTreeWalkDrvEvaluationError::TreeWalk { source },
            } if matches!(source.kind(), TreeWalkErrorKind::Thrown { .. })
        ),
        "serial root-local errors are reported with stable task index"
    );
}

#[test]
fn parallel_raw_differential_rejects_incomplete_collect_all_reports() {
    let roots = [
        lower("0"),
        lower("1"),
        lower("2"),
        lower("builtins.throw \"stop\""),
    ];
    let report = eval_raw_bytes_parallel_top_level(
        roots,
        workers(1),
        ParallelFailurePolicy::CancelQueuedAfterFirstError,
        TreeWalkOptions::default(),
    )
    .expect("fail-fast run completes with cancellation");

    let error = canonical_outcomes_from_parallel_report(workers(1), 4, &report)
        .expect_err("cancelled fail-fast reports are incomplete for differential use");

    assert_eq!(
        error,
        ParallelTreeWalkDifferentialError::IncompleteRun {
            worker_count: 1,
            reported_worker_count: 1,
            task_count: 4,
            reported_task_count: 4,
            completed_task_count: 1,
            cancelled_before_start_count: 3,
            cancelled: true,
            outcome_count: 1,
        }
    );
}

#[test]
fn parallel_raw_differential_reports_normalized_outcome_divergence() {
    let serial = [ParallelTreeWalkCanonicalOutcome::new(
        0,
        Ok(b"serial".to_vec()),
    )];
    let parallel = [ParallelTreeWalkCanonicalOutcome::new(
        0,
        Ok(b"parallel".to_vec()),
    )];

    let error = compare_parallel_tree_walk_outcomes(2, &serial, &parallel)
        .expect_err("different normalized outcomes diverge");

    assert_eq!(
        error,
        ParallelTreeWalkDifferentialError::Divergence {
            worker_count: 2,
            task_index: 0,
            serial: serial[0].clone(),
            parallel: parallel[0].clone(),
        }
    );
}

#[test]
fn parallel_raw_eval_selects_canonical_tree_walk_error_by_task_order() {
    let roots = [
        lower("1"),
        lower("builtins.throw \"first\""),
        lower("assert false; 0"),
        lower("builtins.throw \"second\""),
    ];

    let report = eval_raw_bytes_parallel_top_level(
        roots,
        workers(2),
        ParallelFailurePolicy::CollectAll,
        TreeWalkOptions::default(),
    )
    .expect("parallel tree-walk raw evaluation completes");

    assert_eq!(report.completed_task_count(), 4);
    assert_eq!(
        report
            .outcomes()
            .iter()
            .filter(|outcome| outcome.is_err())
            .map(|outcome| outcome.task_index())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let canonical = report
        .canonical_error()
        .expect("canonical observed tree-walk error exists");
    assert_eq!(canonical.task_index(), 1);
    let ParallelTreeWalkEvaluationError::TreeWalk { source } =
        canonical.outcome().as_ref().expect_err("root failed");
    assert!(matches!(source.kind(), TreeWalkErrorKind::Thrown { .. }));
}

#[test]
fn chase_lev_parallel_raw_eval_selects_canonical_tree_walk_error_by_task_order() {
    let roots = [
        lower("1"),
        lower("builtins.throw \"first\""),
        lower("assert false; 0"),
        lower("builtins.throw \"second\""),
    ];

    let report = eval_raw_bytes_parallel_chase_lev_top_level(
        roots,
        workers(2),
        ParallelFailurePolicy::CollectAll,
        TreeWalkOptions::default(),
    )
    .expect("Chase-Lev tree-walk raw evaluation completes");

    assert_eq!(report.completed_task_count(), 4);
    assert_eq!(
        report
            .outcomes()
            .iter()
            .filter(|outcome| outcome.is_err())
            .map(|outcome| outcome.task_index())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let canonical = report
        .canonical_error()
        .expect("canonical observed tree-walk error exists");
    assert_eq!(canonical.task_index(), 1);
    let ParallelTreeWalkEvaluationError::TreeWalk { source } =
        canonical.outcome().as_ref().expect_err("root failed");
    assert!(matches!(source.kind(), TreeWalkErrorKind::Thrown { .. }));
}

#[test]
fn fail_fast_parallel_raw_eval_cancels_queued_roots_at_task_boundary() {
    let roots = [
        lower("0"),
        lower("1"),
        lower("2"),
        lower("3"),
        lower("builtins.throw \"stop\""),
    ];

    let report = eval_raw_bytes_parallel_top_level(
        roots,
        workers(1),
        ParallelFailurePolicy::CancelQueuedAfterFirstError,
        TreeWalkOptions::default(),
    )
    .expect("parallel tree-walk raw evaluation completes");

    assert!(report.cancelled());
    assert_eq!(report.completed_task_count(), 1);
    assert_eq!(report.cancelled_before_start_count(), 4);
    assert_eq!(
        report
            .canonical_error()
            .expect("canonical observed tree-walk error exists")
            .task_index(),
        4
    );
}

#[test]
fn chase_lev_fail_fast_parallel_raw_eval_cancels_queued_roots_at_task_boundary() {
    let roots = [
        lower("0"),
        lower("1"),
        lower("2"),
        lower("3"),
        lower("builtins.throw \"stop\""),
    ];

    let report = eval_raw_bytes_parallel_chase_lev_top_level(
        roots,
        workers(1),
        ParallelFailurePolicy::CancelQueuedAfterFirstError,
        TreeWalkOptions::default(),
    )
    .expect("Chase-Lev tree-walk raw evaluation completes");

    assert!(report.cancelled());
    assert_eq!(report.completed_task_count(), 1);
    assert_eq!(report.cancelled_before_start_count(), 4);
    assert_eq!(
        report
            .canonical_error()
            .expect("canonical observed tree-walk error exists")
            .task_index(),
        4
    );
}

#[test]
fn scheduler_worker_ids_must_fit_parallel_thunk_worker_ids() {
    let worker_count = usize::try_from(crate::eval::PARALLEL_THUNK_MAX_WORKER_ID)
        .ok()
        .and_then(|max_worker_id| max_worker_id.checked_add(1));
    let Some(worker_count) = worker_count else {
        return;
    };
    let worker_count = NonZeroUsize::new(worker_count).expect("test worker count is nonzero");

    let error = eval_raw_bytes_parallel_top_level(
        std::iter::empty::<Ir>(),
        worker_count,
        ParallelFailurePolicy::CollectAll,
        TreeWalkOptions::default(),
    )
    .expect_err("oversized scheduler worker count is rejected before queue allocation");

    assert!(matches!(
        error,
        ParallelTreeWalkTopLevelError::WorkerIdOutOfRange {
            worker_id,
            worker_count: rejected_count,
        } if worker_id == worker_count.get() - 1 && rejected_count == worker_count.get()
    ));
}

#[test]
fn chase_lev_scheduler_worker_ids_must_fit_parallel_thunk_worker_ids() {
    let worker_count = usize::try_from(crate::eval::PARALLEL_THUNK_MAX_WORKER_ID)
        .ok()
        .and_then(|max_worker_id| max_worker_id.checked_add(1));
    let Some(worker_count) = worker_count else {
        return;
    };
    let worker_count = NonZeroUsize::new(worker_count).expect("test worker count is nonzero");

    let error = eval_raw_bytes_parallel_chase_lev_top_level(
        std::iter::empty::<Ir>(),
        worker_count,
        ParallelFailurePolicy::CollectAll,
        TreeWalkOptions::default(),
    )
    .expect_err("oversized Chase-Lev scheduler worker count is rejected before queue allocation");

    assert!(matches!(
        error,
        ParallelTreeWalkTopLevelError::WorkerIdOutOfRange {
            worker_id,
            worker_count: rejected_count,
        } if worker_id == worker_count.get() - 1 && rejected_count == worker_count.get()
    ));
}
