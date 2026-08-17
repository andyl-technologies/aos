//! Unit tests for the parallel tree-walk drivers and differentials.

mod part_1;

use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
};

use super::*;
use crate::{
    compile::resolve as resolve_ast,
    eval::tree_walk::{
        TreeWalkErrorKind, eval_raw_bytes_with_options, eval_raw_bytes_with_options_source,
    },
    string::ContextElement,
    syntax::parse_str,
};

fn workers(count: usize) -> NonZeroUsize {
    NonZeroUsize::new(count).expect("test worker count is nonzero")
}

fn lower(source: &str) -> Ir {
    aos_nix_dialect::nix_lower(
        resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers")
}

fn derivation_root(name: &str) -> ParallelTreeWalkRoot {
    ParallelTreeWalkRoot::expression(lower(&format!(
        r#"let d = derivation {{ name = "{name}"; system = ":"; builder = ":"; }}; in d.drvPath"#
    )))
}

fn derivation_out_path_root(name: &str) -> ParallelTreeWalkRoot {
    ParallelTreeWalkRoot::expression(lower(&format!(
        r#"let d = derivation {{ name = "{name}"; system = ":"; builder = ":"; }}; in d.outPath"#
    )))
}

fn derivation_attrset_root(name: &str) -> ParallelTreeWalkRoot {
    ParallelTreeWalkRoot::expression(lower(&format!(
        r#"let d = derivation {{ name = "{name}"; system = ":"; builder = ":"; }}; in builtins.seq d.drvPath (d // {{ nested = builtins.throw "non-string root context forced"; }})"#
    )))
}

fn unforced_derivation_attrset_root(name: &str) -> ParallelTreeWalkRoot {
    ParallelTreeWalkRoot::expression(lower(&format!(
        r#"derivation {{ name = "{name}"; system = ":"; builder = ":"; }}"#
    )))
}

fn derivation_attrset_list_root(prefix: &str) -> ParallelTreeWalkRoot {
    ParallelTreeWalkRoot::expression(lower(&format!(
        r#"[
            (derivation {{ name = "{prefix}-alpha"; system = ":"; builder = ":"; }})
            (derivation {{ name = "{prefix}-beta"; system = ":"; builder = ":"; }})
        ]"#
    )))
}

fn expression_root(source: &str) -> ParallelTreeWalkRoot {
    ParallelTreeWalkRoot::expression(lower(source))
}

#[test]
fn standard_parallel_tree_walk_differential_worker_counts_follow_rfc_matrix_order() {
    let counts = parallel_tree_walk_standard_differential_worker_counts()
        .iter()
        .map(|count| count.get())
        .collect::<Vec<_>>();

    assert_eq!(counts[0], 1);
    assert_eq!(counts[1], 2);
    assert_eq!(counts[2], 8);
    assert!(counts.len() <= 4);
    for (index, count) in counts.iter().enumerate() {
        assert!(!counts[..index].contains(count));
    }
    if let Ok(available) = std::thread::available_parallelism() {
        assert!(counts.contains(&available.get()));
    }
}

#[test]
fn parallel_raw_eval_matches_serial_raw_bytes_in_stable_task_order() {
    let sources = [
        "1 + 2",
        "{ b = 2; a = [ 1 true null ]; }",
        "let x = 41; in x + 1",
        "let shared = 1 + 2; in { first = shared; second = shared; }",
        "builtins.toJSON { z = 1; a = [ true null ]; }",
    ];
    let roots = sources
        .iter()
        .map(|source| lower(source))
        .collect::<Vec<_>>();
    let mut options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(ParallelThunkWorkerId::FIRST);
    let expected = roots
        .iter()
        .map(|ir| {
            eval_raw_bytes_with_options(ir, options.clone())
                .expect("serial tree-walk raw evaluation succeeds")
        })
        .collect::<Vec<_>>();

    let report = eval_raw_bytes_parallel_top_level(
        roots,
        workers(3),
        ParallelFailurePolicy::CollectAll,
        options,
    )
    .expect("parallel tree-walk raw evaluation completes");

    assert_eq!(report.worker_count(), 3);
    assert_eq!(report.task_count(), sources.len());
    assert_eq!(report.completed_task_count(), sources.len());
    assert_eq!(report.cancelled_before_start_count(), 0);
    assert!(!report.cancelled());
    assert_eq!(
        report
            .outcomes()
            .iter()
            .map(|outcome| {
                outcome
                    .outcome()
                    .as_ref()
                    .expect("root succeeded")
                    .raw_bytes()
                    .to_vec()
            })
            .collect::<Vec<_>>(),
        expected
    );
    assert!(report.outcomes().iter().all(|outcome| {
        let evaluation = outcome.outcome().as_ref().expect("root succeeded");
        evaluation.parallel_thunk_worker_id().get()
            == u64::try_from(outcome.worker_id()).expect("test worker id fits") + 1
            && evaluation.heap_uses_thread_local_tier_a()
    }));
}

#[test]
fn chase_lev_parallel_raw_eval_matches_serial_raw_bytes_in_stable_task_order() {
    let sources = [
        "1 + 2",
        "{ b = 2; a = [ 1 true null ]; }",
        "let x = 41; in x + 1",
        "let shared = 1 + 2; in { first = shared; second = shared; }",
        "builtins.toJSON { z = 1; a = [ true null ]; }",
    ];
    let roots = sources
        .iter()
        .map(|source| lower(source))
        .collect::<Vec<_>>();
    let mut options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(ParallelThunkWorkerId::FIRST);
    let expected = roots
        .iter()
        .map(|ir| {
            eval_raw_bytes_with_options(ir, options.clone())
                .expect("serial tree-walk raw evaluation succeeds")
        })
        .collect::<Vec<_>>();

    let report = eval_raw_bytes_parallel_chase_lev_top_level(
        roots,
        workers(3),
        ParallelFailurePolicy::CollectAll,
        options,
    )
    .expect("Chase-Lev tree-walk raw evaluation completes");

    assert_eq!(report.worker_count(), 3);
    assert_eq!(report.task_count(), sources.len());
    assert_eq!(report.completed_task_count(), sources.len());
    assert_eq!(report.cancelled_before_start_count(), 0);
    assert!(!report.cancelled());
    assert_eq!(
        report
            .outcomes()
            .iter()
            .map(|outcome| {
                outcome
                    .outcome()
                    .as_ref()
                    .expect("root succeeded")
                    .raw_bytes()
                    .to_vec()
            })
            .collect::<Vec<_>>(),
        expected
    );
    assert!(report.outcomes().iter().all(|outcome| {
        let evaluation = outcome.outcome().as_ref().expect("root succeeded");
        evaluation.parallel_thunk_worker_id().get()
            == u64::try_from(outcome.worker_id()).expect("test worker id fits") + 1
            && evaluation.heap_uses_thread_local_tier_a()
    }));
}

#[test]
fn raw_eval_worker_bridge_installs_context_worker_id_in_evaluator() {
    let worker_ids = parallel_thunk_worker_ids_for_scheduler(workers(3)).expect("worker ids fit");
    let sentinel_worker_id = ParallelThunkWorkerId::new(99).expect("valid worker id");
    let mut options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(sentinel_worker_id);

    let evaluation = eval_raw_bytes_for_parallel_worker(
        ParallelFallibleTaskContext::for_test(0, 0, 1, 3),
        ParallelTreeWalkRoot::expression(lower("1 + 2")),
        &options,
        &worker_ids,
    )
    .expect("worker raw evaluation completes");

    assert_eq!(evaluation.raw_bytes(), b"3");
    assert_eq!(
        evaluation.parallel_thunk_worker_id(),
        ParallelThunkWorkerId::new(2).expect("valid worker id")
    );
    assert_ne!(
        evaluation.parallel_thunk_worker_id(),
        ParallelThunkWorkerId::FIRST
    );
    assert_ne!(evaluation.parallel_thunk_worker_id(), sentinel_worker_id);
    assert!(evaluation.heap_uses_thread_local_tier_a());
    assert!(evaluation.worker_heap_report().uses_thread_local_tier_a());
}

#[test]
fn chase_lev_parallel_raw_eval_overrides_base_worker_id_with_scheduler_worker_id() {
    let roots = ["1 + 2", "let x = 4; in x * 2"]
        .into_iter()
        .map(|source| ParallelTreeWalkRoot::expression(lower(source)));
    let sentinel_worker_id = ParallelThunkWorkerId::new(99).expect("valid worker id");
    let mut options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(sentinel_worker_id);

    let report = eval_raw_bytes_parallel_chase_lev_top_level_roots(
        roots,
        workers(1),
        ParallelFailurePolicy::CollectAll,
        options,
    )
    .expect("Chase-Lev raw evaluation completes");

    assert_eq!(report.worker_count(), 1);
    assert_eq!(report.task_count(), 2);
    assert_eq!(report.completed_task_count(), 2);
    assert_eq!(report.cancelled_before_start_count(), 0);
    assert!(!report.cancelled());
    assert_eq!(
        report
            .outcomes()
            .iter()
            .map(|outcome| {
                let evaluation = outcome.outcome().as_ref().expect("root succeeded");
                assert_eq!(outcome.worker_id(), 0);
                assert_eq!(
                    evaluation.parallel_thunk_worker_id(),
                    ParallelThunkWorkerId::FIRST
                );
                assert_ne!(evaluation.parallel_thunk_worker_id(), sentinel_worker_id);
                assert!(evaluation.heap_uses_thread_local_tier_a());
                assert!(evaluation.worker_heap_report().uses_thread_local_tier_a());
                evaluation.raw_bytes().to_vec()
            })
            .collect::<Vec<_>>(),
        vec![b"3".to_vec(), b"8".to_vec()]
    );
}

#[test]
fn chase_lev_parallel_raw_eval_summarizes_successful_worker_heaps() {
    let roots = [
        "{ a = [ 1 true null ]; b = \"x\"; }",
        "let shared = [ 1 2 3 ]; in { first = shared; second = shared; }",
    ]
    .into_iter()
    .map(|source| ParallelTreeWalkRoot::expression(lower(source)));

    let report = eval_raw_bytes_parallel_chase_lev_top_level_roots(
        roots,
        workers(1),
        ParallelFailurePolicy::CollectAll,
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev raw evaluation completes");
    let summaries = summarize_parallel_tree_walk_raw_worker_heaps(&report);
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
fn parallel_raw_eval_preserves_source_provenance_for_file_roots() {
    let source_name = b"/tmp/aos-parallel-tree-walk-source.nix";
    let source = b"# comment\nbuiltins.toJSON __curPos";
    let ir = lower(std::str::from_utf8(source).expect("test source is UTF-8"));
    let expected =
        eval_raw_bytes_with_options_source(&ir, TreeWalkOptions::default(), source_name, source)
            .expect("serial source-backed tree-walk raw evaluation succeeds");

    let report = eval_raw_bytes_parallel_top_level_roots(
        [ParallelTreeWalkRoot::source(
            ir,
            source_name.to_vec(),
            source.to_vec(),
        )],
        workers(2),
        ParallelFailurePolicy::CollectAll,
        TreeWalkOptions::default(),
    )
    .expect("parallel source-backed tree-walk raw evaluation completes");

    assert_eq!(
        report.outcomes()[0]
            .outcome()
            .as_ref()
            .expect("root succeeded")
            .raw_bytes(),
        expected.as_slice()
    );
}

#[test]
fn chase_lev_parallel_raw_eval_preserves_source_provenance_for_file_roots() {
    let source_name = b"/tmp/aos-chase-lev-tree-walk-source.nix";
    let source = b"# comment\nbuiltins.toJSON __curPos";
    let ir = lower(std::str::from_utf8(source).expect("test source is UTF-8"));
    let expected =
        eval_raw_bytes_with_options_source(&ir, TreeWalkOptions::default(), source_name, source)
            .expect("serial source-backed tree-walk raw evaluation succeeds");

    let report = eval_raw_bytes_parallel_chase_lev_top_level_roots(
        [ParallelTreeWalkRoot::source(
            ir,
            source_name.to_vec(),
            source.to_vec(),
        )],
        workers(2),
        ParallelFailurePolicy::CollectAll,
        TreeWalkOptions::default(),
    )
    .expect("Chase-Lev source-backed tree-walk raw evaluation completes");

    assert_eq!(
        report.outcomes()[0]
            .outcome()
            .as_ref()
            .expect("root succeeded")
            .raw_bytes(),
        expected.as_slice()
    );
}

#[test]
fn parallel_raw_differential_matches_serial_across_worker_counts() {
    let source_name = b"/tmp/aos-parallel-tree-walk-diff-source.nix";
    let source = b"# comment\nbuiltins.toJSON __curPos";
    let source_ir = lower(std::str::from_utf8(source).expect("test source is UTF-8"));
    let source_error = b"# comment\nbuiltins.throw \"source error\"";
    let source_error_ir = lower(std::str::from_utf8(source_error).expect("test source is UTF-8"));
    let roots = [
        ParallelTreeWalkRoot::expression(lower("1 + 2")),
        ParallelTreeWalkRoot::source(source_ir, source_name.to_vec(), source.to_vec()),
        ParallelTreeWalkRoot::expression(lower("builtins.throw \"same error\"")),
        ParallelTreeWalkRoot::source(source_error_ir, source_name.to_vec(), source_error.to_vec()),
    ];

    let report = compare_parallel_tree_walk_raw_across_worker_counts(
        roots,
        [workers(1), workers(3)],
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("parallel tree-walk differential matches serial");

    assert_eq!(report.task_count(), 4);
    assert_eq!(report.worker_counts(), &[1, 3]);
    assert_eq!(
        report.serial_outcomes()[0]
            .outcome()
            .as_ref()
            .expect("first root succeeds"),
        b"3"
    );
    assert!(
        matches!(
            report.serial_outcomes()[2].outcome(),
            Err(ParallelTreeWalkCanonicalError::TreeWalk { source })
                if matches!(source.kind(), TreeWalkErrorKind::Thrown { .. })
        ),
        "root-local serial errors are comparable outcomes"
    );
    assert!(
        matches!(
            report.serial_outcomes()[3].outcome(),
            Err(ParallelTreeWalkCanonicalError::TreeWalk { source })
                if matches!(source.kind(), TreeWalkErrorKind::Thrown { .. })
        ),
        "source-backed root-local serial errors are comparable outcomes"
    );
}

#[test]
fn chase_lev_parallel_raw_differential_matches_serial_across_worker_counts() {
    let source_name = b"/tmp/aos-chase-lev-tree-walk-diff-source.nix";
    let source = b"# comment\nbuiltins.toJSON __curPos";
    let source_ir = lower(std::str::from_utf8(source).expect("test source is UTF-8"));
    let source_error = b"# comment\nbuiltins.throw \"source error\"";
    let source_error_ir = lower(std::str::from_utf8(source_error).expect("test source is UTF-8"));
    let roots = [
        ParallelTreeWalkRoot::expression(lower("1 + 2")),
        ParallelTreeWalkRoot::source(source_ir, source_name.to_vec(), source.to_vec()),
        ParallelTreeWalkRoot::expression(lower("builtins.throw \"same error\"")),
        ParallelTreeWalkRoot::source(source_error_ir, source_name.to_vec(), source_error.to_vec()),
    ];

    let report = compare_parallel_tree_walk_raw_chase_lev_across_worker_counts(
        roots,
        [workers(1), workers(3)],
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev tree-walk differential matches serial");

    assert_eq!(report.task_count(), 4);
    assert_eq!(report.worker_counts(), &[1, 3]);
    assert_eq!(
        report.serial_outcomes()[0]
            .outcome()
            .as_ref()
            .expect("first root succeeds"),
        b"3"
    );
    assert!(
        matches!(
            report.serial_outcomes()[2].outcome(),
            Err(ParallelTreeWalkCanonicalError::TreeWalk { source })
                if matches!(source.kind(), TreeWalkErrorKind::Thrown { .. })
        ),
        "root-local serial errors are comparable outcomes"
    );
    assert!(
        matches!(
            report.serial_outcomes()[3].outcome(),
            Err(ParallelTreeWalkCanonicalError::TreeWalk { source })
                if matches!(source.kind(), TreeWalkErrorKind::Thrown { .. })
        ),
        "source-backed root-local serial errors are comparable outcomes"
    );
}

#[test]
fn chase_lev_parallel_drv_output_differential_matches_serial_across_worker_counts() {
    let roots = [
        derivation_root("parallel-drv-alpha"),
        derivation_root("parallel-drv-beta"),
        derivation_root("parallel-drv-gamma"),
    ];

    let expected_worker_counts = parallel_tree_walk_standard_differential_worker_counts()
        .iter()
        .map(|count| count.get())
        .collect::<Vec<_>>();
    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_standard_worker_counts(
        roots,
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev .drv differential matches serial");

    assert_eq!(report.task_count(), 3);
    assert_eq!(report.worker_counts(), expected_worker_counts.as_slice());
    assert!(report.worker_counts().contains(&1));
    assert!(report.worker_counts().contains(&2));
    assert!(report.worker_counts().contains(&8));
    assert_eq!(report.collation().fragment_count(), 3);
    assert_eq!(report.collation().drv_output_count(), 3);
    assert_eq!(report.collation().string_context().len(), 3);
    assert!(report.collation().drv_outputs().iter().all(|output| {
        output.path().ends_with(b".drv")
            && output.bytes().starts_with(b"Derive(")
            && output.content_sha256()
                == crate::eval::parallel_drv_output_content_sha256(output.bytes())
    }));
    let paths = report
        .collation()
        .drv_outputs()
        .iter()
        .map(|output| output.path().to_vec())
        .collect::<Vec<_>>();
    let mut sorted_paths = paths.clone();
    sorted_paths.sort();
    assert_eq!(paths, sorted_paths);
    assert!(report.collation().drv_outputs().iter().all(|output| {
        report.collation().string_context().contains(
            &ContextElement::deep_derivation(output.path().to_vec())
                .expect("deep .drv context builds"),
        )
    }));
}

#[test]
fn chase_lev_parallel_drv_output_differential_collates_root_output_string_contexts() {
    let roots = [
        derivation_out_path_root("parallel-drv-output-context-alpha"),
        derivation_out_path_root("parallel-drv-output-context-beta"),
    ];

    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        roots,
        [workers(1), workers(3)],
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .expect("Chase-Lev .drv differential matches serial root output contexts");

    assert_eq!(report.task_count(), 2);
    assert_eq!(report.worker_counts(), &[1, 3]);
    assert_eq!(report.collation().fragment_count(), 2);
    assert_eq!(report.collation().drv_output_count(), 2);
    assert_eq!(report.collation().string_context().len(), 2);
    assert!(report.collation().drv_outputs().iter().all(|output| {
        report.collation().string_context().contains(
            &ContextElement::single_output(output.path().to_vec(), b"out".to_vec())
                .expect("single-output .drv context builds"),
        )
    }));
}

#[test]
fn drv_output_worker_bridge_installs_context_worker_id_in_evaluator() {
    let worker_ids = parallel_thunk_worker_ids_for_scheduler(workers(3)).expect("worker ids fit");
    let sentinel_worker_id = ParallelThunkWorkerId::new(99).expect("valid worker id");
    let mut options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(sentinel_worker_id);

    let evaluation = eval_drv_outputs_for_parallel_worker(
        ParallelFallibleTaskContext::for_test(0, 0, 1, 3),
        derivation_root("parallel-drv-context-worker-id"),
        &options,
        &worker_ids,
    )
    .expect("worker .drv evaluation completes");

    assert_eq!(
        evaluation.parallel_thunk_worker_id(),
        ParallelThunkWorkerId::new(2).expect("valid worker id")
    );
    assert_ne!(
        evaluation.parallel_thunk_worker_id(),
        ParallelThunkWorkerId::FIRST
    );
    assert_ne!(evaluation.parallel_thunk_worker_id(), sentinel_worker_id);
    assert!(evaluation.heap_uses_thread_local_tier_a());
    assert!(evaluation.worker_heap_report().uses_thread_local_tier_a());
    assert!(evaluation.worker_heap_report().heap_records() > 0);
    assert_eq!(evaluation.output().drv_outputs().len(), 1);
    assert!(
        evaluation.output().drv_outputs()[0]
            .path()
            .ends_with(b".drv")
    );
}

#[test]
fn chase_lev_parallel_drv_output_eval_overrides_base_worker_id_with_scheduler_worker_id() {
    let roots = [
        derivation_root("parallel-drv-worker-id-alpha"),
        derivation_root("parallel-drv-worker-id-beta"),
    ];
    let sentinel_worker_id = ParallelThunkWorkerId::new(99).expect("valid worker id");
    let mut options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(sentinel_worker_id);

    let report = eval_drv_outputs_parallel_chase_lev_top_level_roots(
        roots,
        workers(1),
        ParallelFailurePolicy::CollectAll,
        options,
    )
    .expect("Chase-Lev .drv evaluation completes");

    assert_eq!(report.worker_count(), 1);
    assert_eq!(report.task_count(), 2);
    assert_eq!(report.completed_task_count(), 2);
    assert_eq!(report.cancelled_before_start_count(), 0);
    assert!(!report.cancelled());
    assert!(report.outcomes().iter().all(|outcome| {
        let evaluation = outcome.outcome().as_ref().expect("root succeeded");
        outcome.worker_id() == 0
            && evaluation.parallel_thunk_worker_id() == ParallelThunkWorkerId::FIRST
            && evaluation.parallel_thunk_worker_id() != sentinel_worker_id
            && evaluation.heap_uses_thread_local_tier_a()
            && evaluation.worker_heap_report().uses_thread_local_tier_a()
            && evaluation.output().drv_outputs().len() == 1
            && evaluation.output().drv_outputs()[0]
                .path()
                .ends_with(b".drv")
    }));
}
