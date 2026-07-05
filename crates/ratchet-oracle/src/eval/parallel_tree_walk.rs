//! Scheduler-backed tree-walk evaluation precursors.
//!
//! This module bridges the safe Phase 3.5 L1 scheduler to real tree-walk
//! evaluation of independent lowered roots. Each task owns a separate
//! `TreeWalk` evaluator and heap, receives the active parallel thunk worker id
//! for the scheduler worker that actually executes it, and opts into the
//! current thread-local Tier-A worker arena backend. This is still a coarse-root
//! bridge: it does not share thunk graphs between roots, keep a final
//! never-free nursery alive for the whole CLI, or replace the serial tree-walk
//! force path.

use std::num::NonZeroUsize;

use thiserror::Error;

use crate::compile::Ir;
use crate::string::StringContext;
use crate::value::{Value, ValueTag};

use super::{
    heap::EvalHeapError,
    parallel_failure::{
        ParallelFailurePolicy, ParallelFallibleTaskContext, ParallelFallibleTopLevelError,
        ParallelFallibleTopLevelReport, execute_parallel_top_level_fallible_chase_lev_with_worker,
        execute_parallel_top_level_fallible_with_worker,
    },
    parallel_output::{
        ParallelDrvOutput, ParallelOutputCollation, ParallelOutputDeterminismError,
        ParallelOutputFragment, ParallelOutputTaskResult, collate_parallel_output_fragments,
    },
    thunk_cas::ParallelThunkWorkerId,
    tree_walk::{
        EvalDerivation, TreeWalk, TreeWalkError, TreeWalkOptions, eval_raw_bytes_with_evaluator,
    },
};

/// A scheduler-backed tree-walk raw-evaluation report.
pub type ParallelTreeWalkRawEvaluationReport =
    ParallelFallibleTopLevelReport<ParallelTreeWalkRawEvaluation, ParallelTreeWalkEvaluationError>;

/// A scheduler-backed tree-walk derivation-surface report.
pub type ParallelTreeWalkDrvEvaluationReport = ParallelFallibleTopLevelReport<
    ParallelTreeWalkDrvEvaluation,
    ParallelTreeWalkDrvEvaluationError,
>;

/// Compares scheduler-backed raw tree-walk evaluation against serial tree-walk.
///
/// The supplied roots are first evaluated serially with the tree-walk raw
/// renderer, producing the oracle outcomes. Every worker count and cache-bearing
/// option is preflighted before those serial roots run. The same roots are then
/// evaluated through the scheduler-backed bridge for every supplied worker count
/// using [`ParallelFailurePolicy::CollectAll`], and each parallel run is
/// normalized to raw bytes or exact tree-walk errors before comparison.
/// Scheduler completion metadata is deliberately ignored for successful raw
/// evaluations.
///
/// # Errors
///
/// Returns [`ParallelTreeWalkDifferentialError::NoWorkerCounts`] if no worker
/// counts are supplied,
/// [`ParallelTreeWalkDifferentialError::WorkerCountOutOfRange`] if a worker
/// count cannot be encoded by the parallel thunk state-word format, or
/// [`ParallelTreeWalkDifferentialError::StatefulCacheOptionsUnsupported`] if
/// options configure persistent parse/eval cache roots that could make later
/// runs observe state warmed by earlier runs. Returns
/// [`ParallelTreeWalkDifferentialError::Scheduler`] if one scheduler-backed run
/// fails before all root outcomes are reported,
/// [`ParallelTreeWalkDifferentialError::IncompleteRun`] if a scheduler-backed
/// run does not report every root under collect-all policy, or
/// [`ParallelTreeWalkDifferentialError::Divergence`] if any normalized parallel
/// outcome differs from the serial tree-walk oracle.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped scheduler
/// worker threads. Task panics are caught and returned as
/// [`ParallelTreeWalkDifferentialError::Scheduler`].
pub fn compare_parallel_tree_walk_raw_across_worker_counts<I, W>(
    roots: I,
    worker_counts: W,
    options: TreeWalkOptions,
) -> Result<ParallelTreeWalkDifferentialReport, ParallelTreeWalkDifferentialError>
where
    I: IntoIterator<Item = ParallelTreeWalkRoot>,
    W: IntoIterator<Item = NonZeroUsize>,
{
    compare_parallel_tree_walk_raw_across_worker_counts_with(
        roots,
        worker_counts,
        options,
        eval_raw_bytes_for_root,
        eval_raw_bytes_parallel_top_level_roots,
    )
}

/// Compares Chase-Lev-backed raw tree-walk evaluation against serial tree-walk.
///
/// This is the Chase-Lev scheduler variant of
/// [`compare_parallel_tree_walk_raw_across_worker_counts`]. It uses the same
/// serial tree-walk oracle, worker-count/cache-option preflight, collect-all
/// policy, canonical outcome normalization, and stable task-order comparison,
/// but evaluates each parallel run through
/// [`eval_raw_bytes_parallel_chase_lev_top_level_roots`].
///
/// # Errors
///
/// Returns [`ParallelTreeWalkDifferentialError::NoWorkerCounts`] if no worker
/// counts are supplied,
/// [`ParallelTreeWalkDifferentialError::WorkerCountOutOfRange`] if a worker
/// count cannot be encoded by the parallel thunk state-word format, or
/// [`ParallelTreeWalkDifferentialError::StatefulCacheOptionsUnsupported`] if
/// options configure persistent parse/eval cache roots that could make later
/// runs observe state warmed by earlier runs. Returns
/// [`ParallelTreeWalkDifferentialError::Scheduler`] if one Chase-Lev-backed run
/// fails before all root outcomes are reported,
/// [`ParallelTreeWalkDifferentialError::IncompleteRun`] if a Chase-Lev-backed
/// run does not report every root under collect-all policy, or
/// [`ParallelTreeWalkDifferentialError::Divergence`] if any normalized parallel
/// outcome differs from the serial tree-walk oracle.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped scheduler
/// worker threads. Task panics are caught and returned as
/// [`ParallelTreeWalkDifferentialError::Scheduler`].
pub fn compare_parallel_tree_walk_raw_chase_lev_across_worker_counts<I, W>(
    roots: I,
    worker_counts: W,
    options: TreeWalkOptions,
) -> Result<ParallelTreeWalkDifferentialReport, ParallelTreeWalkDifferentialError>
where
    I: IntoIterator<Item = ParallelTreeWalkRoot>,
    W: IntoIterator<Item = NonZeroUsize>,
{
    compare_parallel_tree_walk_raw_across_worker_counts_with(
        roots,
        worker_counts,
        options,
        eval_raw_bytes_for_root,
        eval_raw_bytes_parallel_chase_lev_top_level_roots,
    )
}

/// Compares Chase-Lev-backed `.drv` surfaces against serial tree-walk.
///
/// The supplied roots are first evaluated serially to the tree-walk derivation
/// snapshot and collated through the deterministic output collector. Each
/// requested worker count then evaluates the same roots through the Chase-Lev
/// top-level executor, extracts the observed `.drv` paths and ATerm bytes from
/// every completed root, and compares the path-sorted content-only collation to
/// the serial baseline. Scheduler worker ids and completion order are not part
/// of the observable output.
///
/// # Errors
///
/// Returns [`ParallelTreeWalkDrvDifferentialError::NoWorkerCounts`] if no
/// worker counts are supplied,
/// [`ParallelTreeWalkDrvDifferentialError::WorkerCountOutOfRange`] if a worker
/// count cannot be encoded by the parallel thunk state-word format, or
/// [`ParallelTreeWalkDrvDifferentialError::StatefulCacheOptionsUnsupported`] if
/// options configure persistent parse/eval cache roots that could make later
/// runs observe state warmed by earlier runs. Returns
/// [`ParallelTreeWalkDrvDifferentialError::SerialRoot`] if a serial root cannot
/// produce its derivation surface,
/// [`ParallelTreeWalkDrvDifferentialError::Scheduler`] if one Chase-Lev-backed
/// run fails before every root reports an outcome,
/// [`ParallelTreeWalkDrvDifferentialError::IncompleteRun`] if a scheduler run
/// does not report every root under collect-all policy,
/// [`ParallelTreeWalkDrvDifferentialError::ParallelRoot`] if a scheduler root
/// cannot produce its derivation surface,
/// [`ParallelTreeWalkDrvDifferentialError::Collation`] if duplicate/conflicting
/// `.drv` fragments are observed, or
/// [`ParallelTreeWalkDrvDifferentialError::Divergence`] if a worker count
/// produces a different canonical `.drv` collation than the serial oracle.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped scheduler
/// worker threads. Task panics are caught and returned as
/// [`ParallelTreeWalkDrvDifferentialError::Scheduler`].
pub fn compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts<I, W>(
    roots: I,
    worker_counts: W,
    options: TreeWalkOptions,
) -> Result<ParallelTreeWalkDrvDifferentialReport, ParallelTreeWalkDrvDifferentialError>
where
    I: IntoIterator<Item = ParallelTreeWalkRoot>,
    W: IntoIterator<Item = NonZeroUsize>,
{
    let roots = roots.into_iter().collect::<Vec<_>>();
    let worker_counts = worker_counts.into_iter().collect::<Vec<_>>();
    if worker_counts.is_empty() {
        return Err(ParallelTreeWalkDrvDifferentialError::NoWorkerCounts);
    }
    preflight_parallel_tree_walk_drv_differential_worker_counts(&worker_counts)?;
    preflight_parallel_tree_walk_drv_differential_options(&options)?;

    let serial = serial_drv_output_collation(&roots, options.clone())?;
    for &worker_count in &worker_counts {
        let report = eval_drv_outputs_parallel_chase_lev_top_level_roots(
            roots.clone().into_iter(),
            worker_count,
            ParallelFailurePolicy::CollectAll,
            options.clone(),
        )
        .map_err(|source| ParallelTreeWalkDrvDifferentialError::Scheduler {
            worker_count: worker_count.get(),
            source,
        })?;
        let parallel =
            drv_output_collation_from_parallel_report(worker_count, roots.len(), &report)?;
        if parallel != serial {
            return Err(ParallelTreeWalkDrvDifferentialError::Divergence {
                worker_count: worker_count.get(),
                serial,
                parallel,
            });
        }
    }

    Ok(ParallelTreeWalkDrvDifferentialReport {
        task_count: roots.len(),
        worker_counts: worker_counts.iter().map(|count| count.get()).collect(),
        collation: serial,
    })
}

/// Compares Chase-Lev-backed `.drv` surfaces over the RFC standard worker matrix.
///
/// This convenience entry point uses
/// [`parallel_tree_walk_standard_differential_worker_counts`] for the requested
/// worker counts. It otherwise has the same serial oracle, cache-option
/// preflight, collect-all execution, collation, and divergence behavior as
/// [`compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts`].
///
/// # Errors
///
/// Returns the same errors as
/// [`compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts`].
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped scheduler
/// worker threads. Task panics are caught and returned as
/// [`ParallelTreeWalkDrvDifferentialError::Scheduler`].
pub fn compare_parallel_tree_walk_drv_outputs_chase_lev_standard_worker_counts<I>(
    roots: I,
    options: TreeWalkOptions,
) -> Result<ParallelTreeWalkDrvDifferentialReport, ParallelTreeWalkDrvDifferentialError>
where
    I: IntoIterator<Item = ParallelTreeWalkRoot>,
{
    compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        roots,
        parallel_tree_walk_standard_differential_worker_counts(),
        options,
    )
}

/// Returns the standard worker-count matrix for parallel tree-walk differentials.
///
/// The matrix follows RFC0007's `{1, 2, 8, N}` shape, where `N` is the host
/// available parallelism reported by [`std::thread::available_parallelism`].
/// Duplicate counts are removed while preserving matrix order. If the host does
/// not report available parallelism, `4` is used as a deterministic fallback for
/// `N`.
pub fn parallel_tree_walk_standard_differential_worker_counts() -> Vec<NonZeroUsize> {
    let mut counts = Vec::with_capacity(4);
    push_standard_worker_count(&mut counts, 1);
    push_standard_worker_count(&mut counts, 2);
    push_standard_worker_count(&mut counts, 8);
    match std::thread::available_parallelism() {
        Ok(count) => push_unique_worker_count(&mut counts, count),
        Err(_) => push_standard_worker_count(&mut counts, 4),
    }
    counts
}

fn push_standard_worker_count(counts: &mut Vec<NonZeroUsize>, count: usize) {
    if let Some(count) = NonZeroUsize::new(count) {
        push_unique_worker_count(counts, count);
    }
}

fn push_unique_worker_count(counts: &mut Vec<NonZeroUsize>, count: NonZeroUsize) {
    if counts.iter().all(|existing| *existing != count) {
        counts.push(count);
    }
}

fn compare_parallel_tree_walk_raw_across_worker_counts_with<I, W, S, F>(
    roots: I,
    worker_counts: W,
    options: TreeWalkOptions,
    eval_serial_root: S,
    eval_parallel_roots: F,
) -> Result<ParallelTreeWalkDifferentialReport, ParallelTreeWalkDifferentialError>
where
    I: IntoIterator<Item = ParallelTreeWalkRoot>,
    W: IntoIterator<Item = NonZeroUsize>,
    S: Fn(ParallelTreeWalkRoot, TreeWalkOptions) -> Result<Vec<u8>, TreeWalkError>,
    F: Fn(
        std::vec::IntoIter<ParallelTreeWalkRoot>,
        NonZeroUsize,
        ParallelFailurePolicy,
        TreeWalkOptions,
    ) -> Result<ParallelTreeWalkRawEvaluationReport, ParallelTreeWalkTopLevelError>,
{
    let roots = roots.into_iter().collect::<Vec<_>>();
    let worker_counts = worker_counts.into_iter().collect::<Vec<_>>();
    if worker_counts.is_empty() {
        return Err(ParallelTreeWalkDifferentialError::NoWorkerCounts);
    }
    preflight_parallel_tree_walk_differential_worker_counts(&worker_counts)?;
    preflight_parallel_tree_walk_differential_options(&options)?;

    let serial_outcomes = roots
        .iter()
        .cloned()
        .enumerate()
        .map(|(task_index, root)| {
            ParallelTreeWalkCanonicalOutcome::new(
                task_index,
                eval_serial_root(root, options.clone())
                    .map_err(ParallelTreeWalkCanonicalError::from_tree_walk_error),
            )
        })
        .collect::<Vec<_>>();

    for &worker_count in &worker_counts {
        let report = eval_parallel_roots(
            roots.clone().into_iter(),
            worker_count,
            ParallelFailurePolicy::CollectAll,
            options.clone(),
        )
        .map_err(|source| ParallelTreeWalkDifferentialError::Scheduler {
            worker_count: worker_count.get(),
            source,
        })?;
        let parallel_outcomes =
            canonical_outcomes_from_parallel_report(worker_count, roots.len(), &report)?;
        compare_parallel_tree_walk_outcomes(
            worker_count.get(),
            &serial_outcomes,
            &parallel_outcomes,
        )?;
    }

    Ok(ParallelTreeWalkDifferentialReport {
        task_count: roots.len(),
        worker_counts: worker_counts.iter().map(|count| count.get()).collect(),
        serial_outcomes,
    })
}

fn preflight_parallel_tree_walk_differential_worker_counts(
    worker_counts: &[NonZeroUsize],
) -> Result<(), ParallelTreeWalkDifferentialError> {
    for &worker_count in worker_counts {
        if let Err(worker_id) = parallel_thunk_worker_id_for_scheduler_worker_count(worker_count) {
            return Err(ParallelTreeWalkDifferentialError::WorkerCountOutOfRange {
                worker_count: worker_count.get(),
                worker_id,
            });
        }
    }
    Ok(())
}

fn preflight_parallel_tree_walk_differential_options(
    options: &TreeWalkOptions,
) -> Result<(), ParallelTreeWalkDifferentialError> {
    if options.parse_cache_root().is_some() || options.persist_cache_root().is_some() {
        return Err(
            ParallelTreeWalkDifferentialError::StatefulCacheOptionsUnsupported {
                parse_cache_root: options.parse_cache_root().is_some(),
                persist_cache_root: options.persist_cache_root().is_some(),
            },
        );
    }
    Ok(())
}

fn preflight_parallel_tree_walk_drv_differential_worker_counts(
    worker_counts: &[NonZeroUsize],
) -> Result<(), ParallelTreeWalkDrvDifferentialError> {
    for &worker_count in worker_counts {
        if let Err(worker_id) = parallel_thunk_worker_id_for_scheduler_worker_count(worker_count) {
            return Err(
                ParallelTreeWalkDrvDifferentialError::WorkerCountOutOfRange {
                    worker_count: worker_count.get(),
                    worker_id,
                },
            );
        }
    }
    Ok(())
}

fn preflight_parallel_tree_walk_drv_differential_options(
    options: &TreeWalkOptions,
) -> Result<(), ParallelTreeWalkDrvDifferentialError> {
    if options.parse_cache_root().is_some() || options.persist_cache_root().is_some() {
        return Err(
            ParallelTreeWalkDrvDifferentialError::StatefulCacheOptionsUnsupported {
                parse_cache_root: options.parse_cache_root().is_some(),
                persist_cache_root: options.persist_cache_root().is_some(),
            },
        );
    }
    Ok(())
}

/// Evaluates independent expression-style lowered roots through the safe L1 scheduler.
///
/// This convenience entry point treats every root as source-less expression
/// evaluation with the same raw rendering semantics as
/// [`eval_raw_bytes_with_options`](crate::eval::tree_walk::eval_raw_bytes_with_options),
/// while scheduler workers still install their scheduler worker id and
/// thread-local Tier-A worker storage before evaluation.
/// Use
/// [`eval_raw_bytes_parallel_top_level_roots`] when file-backed roots need
/// source provenance for `__curPos` or `builtins.unsafeGetAttrPos`.
///
/// # Errors
///
/// Returns [`ParallelTreeWalkTopLevelError`] if the worker count cannot be
/// represented by the parallel thunk state-word format, or if the safe
/// scheduler fails while evaluating the submitted roots.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelTreeWalkTopLevelError::Scheduler`].
pub fn eval_raw_bytes_parallel_top_level<I>(
    roots: I,
    worker_count: NonZeroUsize,
    policy: ParallelFailurePolicy,
    options: TreeWalkOptions,
) -> Result<ParallelTreeWalkRawEvaluationReport, ParallelTreeWalkTopLevelError>
where
    I: IntoIterator<Item = Ir>,
{
    eval_raw_bytes_parallel_top_level_roots(
        roots.into_iter().map(ParallelTreeWalkRoot::expression),
        worker_count,
        policy,
        options,
    )
}

/// Evaluates independent expression-style lowered roots through Chase-Lev worker deques.
///
/// This convenience entry point treats every root as source-less expression
/// evaluation with the same raw rendering semantics as
/// [`eval_raw_bytes_with_options`](crate::eval::tree_walk::eval_raw_bytes_with_options),
/// while scheduler workers still install their scheduler worker id and
/// thread-local Tier-A worker storage before evaluation.
/// Use
/// [`eval_raw_bytes_parallel_chase_lev_top_level_roots`] when file-backed roots
/// need source provenance for `__curPos` or `builtins.unsafeGetAttrPos`.
///
/// # Errors
///
/// Returns [`ParallelTreeWalkTopLevelError`] if the worker count cannot be
/// represented by the parallel thunk state-word format, or if the Chase-Lev
/// scheduler precursor fails while evaluating the submitted roots.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelTreeWalkTopLevelError::Scheduler`].
pub fn eval_raw_bytes_parallel_chase_lev_top_level<I>(
    roots: I,
    worker_count: NonZeroUsize,
    policy: ParallelFailurePolicy,
    options: TreeWalkOptions,
) -> Result<ParallelTreeWalkRawEvaluationReport, ParallelTreeWalkTopLevelError>
where
    I: IntoIterator<Item = Ir>,
{
    eval_raw_bytes_parallel_chase_lev_top_level_roots(
        roots.into_iter().map(ParallelTreeWalkRoot::expression),
        worker_count,
        policy,
        options,
    )
}

/// Evaluates independent lowered roots through the safe L1 scheduler.
///
/// Each root is evaluated by a fresh tree-walk evaluator and rendered with the
/// same raw strict syntax as the tree-walk raw renderer. Source-less roots use
/// [`eval_raw_bytes_with_options`](crate::eval::tree_walk::eval_raw_bytes_with_options);
/// source-backed roots use
/// [`eval_raw_bytes_with_options_source`](crate::eval::tree_walk::eval_raw_bytes_with_options_source)
/// so position-sensitive builtins see the supplied source name and bytes. The
/// supplied options are cloned for every task, then the active parallel thunk
/// worker id is replaced with a non-zero id derived from the scheduler worker
/// that actually executes the root and the cloned options opt into
/// thread-local Tier-A worker storage.
///
/// Root-local tree-walk failures are stored in the returned report as
/// [`ParallelTreeWalkEvaluationError::TreeWalk`] outcomes. Scheduler
/// infrastructure failures are returned from this function.
///
/// # Errors
///
/// Returns [`ParallelTreeWalkTopLevelError`] if the worker count cannot be
/// represented by the parallel thunk state-word format, or if the safe
/// scheduler cannot complete because a worker queue or result buffer is
/// poisoned, an internal worker id is missing, or a worker thread panics while
/// evaluating a root.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelTreeWalkTopLevelError::Scheduler`].
pub fn eval_raw_bytes_parallel_top_level_roots<I>(
    roots: I,
    worker_count: NonZeroUsize,
    policy: ParallelFailurePolicy,
    options: TreeWalkOptions,
) -> Result<ParallelTreeWalkRawEvaluationReport, ParallelTreeWalkTopLevelError>
where
    I: IntoIterator<Item = ParallelTreeWalkRoot>,
{
    validate_parallel_tree_walk_worker_count(worker_count)?;
    let worker_ids = parallel_thunk_worker_ids_for_scheduler(worker_count)?;

    execute_parallel_top_level_fallible_with_worker(
        roots,
        worker_count,
        policy,
        move |context, root| {
            eval_raw_bytes_for_parallel_worker(context, root, &options, &worker_ids)
        },
    )
    .map_err(|source| ParallelTreeWalkTopLevelError::Scheduler { source })
}

/// Evaluates independent lowered roots through Chase-Lev worker deques.
///
/// Each root is evaluated by a fresh tree-walk evaluator and rendered with the
/// same raw strict syntax as the tree-walk raw renderer. Source-less roots use
/// [`eval_raw_bytes_with_options`](crate::eval::tree_walk::eval_raw_bytes_with_options);
/// source-backed roots use
/// [`eval_raw_bytes_with_options_source`](crate::eval::tree_walk::eval_raw_bytes_with_options_source)
/// so position-sensitive builtins see the supplied source name and bytes. The
/// supplied options are cloned for every task, then the active parallel thunk
/// worker id is replaced with a non-zero id derived from the Chase-Lev
/// scheduler worker that actually executes the root and the cloned options opt
/// into thread-local Tier-A worker storage.
///
/// Root-local tree-walk failures are stored in the returned report as
/// [`ParallelTreeWalkEvaluationError::TreeWalk`] outcomes. Scheduler
/// infrastructure failures are returned from this function.
///
/// # Errors
///
/// Returns [`ParallelTreeWalkTopLevelError`] if the worker count cannot be
/// represented by the parallel thunk state-word format, or if the Chase-Lev
/// scheduler precursor cannot complete because a result buffer is poisoned or a
/// worker thread panics while evaluating a root.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelTreeWalkTopLevelError::Scheduler`].
pub fn eval_raw_bytes_parallel_chase_lev_top_level_roots<I>(
    roots: I,
    worker_count: NonZeroUsize,
    policy: ParallelFailurePolicy,
    options: TreeWalkOptions,
) -> Result<ParallelTreeWalkRawEvaluationReport, ParallelTreeWalkTopLevelError>
where
    I: IntoIterator<Item = ParallelTreeWalkRoot>,
{
    validate_parallel_tree_walk_worker_count(worker_count)?;
    let worker_ids = parallel_thunk_worker_ids_for_scheduler(worker_count)?;

    execute_parallel_top_level_fallible_chase_lev_with_worker(
        roots,
        worker_count,
        policy,
        move |context, root| {
            eval_raw_bytes_for_parallel_worker(context, root, &options, &worker_ids)
        },
    )
    .map_err(|source| ParallelTreeWalkTopLevelError::Scheduler { source })
}

/// Evaluates independent lowered roots to `.drv` surfaces through Chase-Lev deques.
///
/// Each root is evaluated by a fresh tree-walk evaluator, then its derivation
/// snapshot is converted into task-local `.drv` output candidates keyed by
/// absolute path and serialized ATerm bytes. The supplied options are cloned
/// per task, then the active parallel thunk worker id is replaced with a
/// non-zero id derived from the Chase-Lev scheduler worker that actually
/// executes the root and the cloned options opt into thread-local Tier-A worker
/// storage.
///
/// Root-local tree-walk or derivation-surface failures are stored in the
/// returned report as [`ParallelTreeWalkDrvEvaluationError`] outcomes.
/// Scheduler infrastructure failures are returned from this function.
///
/// # Errors
///
/// Returns [`ParallelTreeWalkTopLevelError`] if the worker count cannot be
/// represented by the parallel thunk state-word format, or if the Chase-Lev
/// scheduler precursor cannot complete because a result buffer is poisoned or a
/// worker thread panics while evaluating a root.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelTreeWalkTopLevelError::Scheduler`].
pub fn eval_drv_outputs_parallel_chase_lev_top_level_roots<I>(
    roots: I,
    worker_count: NonZeroUsize,
    policy: ParallelFailurePolicy,
    options: TreeWalkOptions,
) -> Result<ParallelTreeWalkDrvEvaluationReport, ParallelTreeWalkTopLevelError>
where
    I: IntoIterator<Item = ParallelTreeWalkRoot>,
{
    validate_parallel_tree_walk_worker_count(worker_count)?;
    let worker_ids = parallel_thunk_worker_ids_for_scheduler(worker_count)?;

    execute_parallel_top_level_fallible_chase_lev_with_worker(
        roots,
        worker_count,
        policy,
        move |context, root| {
            eval_drv_outputs_for_parallel_worker(context, root, &options, &worker_ids)
        },
    )
    .map_err(|source| ParallelTreeWalkTopLevelError::Scheduler { source })
}

fn eval_raw_bytes_for_parallel_worker(
    context: ParallelFallibleTaskContext,
    root: ParallelTreeWalkRoot,
    base_options: &TreeWalkOptions,
    worker_ids: &[ParallelThunkWorkerId],
) -> Result<ParallelTreeWalkRawEvaluation, ParallelTreeWalkEvaluationError> {
    let options = tree_walk_options_for_parallel_worker(context, base_options, worker_ids);
    let (raw_bytes, metadata) = eval_raw_bytes_for_root_with_metadata(root, options)?;

    Ok(ParallelTreeWalkRawEvaluation {
        raw_bytes,
        parallel_thunk_worker_id: metadata.parallel_thunk_worker_id,
        heap_uses_thread_local_tier_a: metadata.heap_uses_thread_local_tier_a,
    })
}

fn eval_drv_outputs_for_parallel_worker(
    context: ParallelFallibleTaskContext,
    root: ParallelTreeWalkRoot,
    base_options: &TreeWalkOptions,
    worker_ids: &[ParallelThunkWorkerId],
) -> Result<ParallelTreeWalkDrvEvaluation, ParallelTreeWalkDrvEvaluationError> {
    let options = tree_walk_options_for_parallel_worker(context, base_options, worker_ids);
    let (output, metadata) = eval_drv_outputs_for_root_with_metadata(root, options)?;

    Ok(ParallelTreeWalkDrvEvaluation {
        output,
        parallel_thunk_worker_id: metadata.parallel_thunk_worker_id,
        heap_uses_thread_local_tier_a: metadata.heap_uses_thread_local_tier_a,
    })
}

fn tree_walk_options_for_parallel_worker(
    context: ParallelFallibleTaskContext,
    base_options: &TreeWalkOptions,
    worker_ids: &[ParallelThunkWorkerId],
) -> TreeWalkOptions {
    let mut options = base_options.clone();
    options.set_parallel_thunk_worker_id(worker_ids[context.worker_id()]);
    options.set_heap_thread_local_tier_a_enabled(true);
    options
}

fn eval_raw_bytes_for_root(
    root: ParallelTreeWalkRoot,
    options: TreeWalkOptions,
) -> Result<Vec<u8>, TreeWalkError> {
    let (raw_bytes, _) = eval_raw_bytes_for_root_with_metadata(root, options)?;
    Ok(raw_bytes)
}

fn eval_raw_bytes_for_root_with_metadata(
    root: ParallelTreeWalkRoot,
    options: TreeWalkOptions,
) -> Result<(Vec<u8>, ParallelTreeWalkWorkerMetadata), TreeWalkError> {
    let ParallelTreeWalkRoot { ir, source } = root;
    let evaluator = match source {
        Some(source) => {
            TreeWalk::with_options_and_source(&ir, options, source.source_name, source.source_bytes)
        }
        None => TreeWalk::with_options(&ir, options),
    };
    let metadata = ParallelTreeWalkWorkerMetadata::from_evaluator(&evaluator);
    let raw_bytes = eval_raw_bytes_with_evaluator(&ir, evaluator)?;
    Ok((raw_bytes, metadata))
}

fn eval_drv_outputs_for_root(
    root: ParallelTreeWalkRoot,
    options: TreeWalkOptions,
) -> Result<ParallelOutputTaskResult, ParallelTreeWalkDrvEvaluationError> {
    let (output, _) = eval_drv_outputs_for_root_with_metadata(root, options)?;
    Ok(output)
}

fn eval_drv_outputs_for_root_with_metadata(
    root: ParallelTreeWalkRoot,
    options: TreeWalkOptions,
) -> Result<
    (ParallelOutputTaskResult, ParallelTreeWalkWorkerMetadata),
    ParallelTreeWalkDrvEvaluationError,
> {
    let ParallelTreeWalkRoot { ir, source } = root;
    let mut evaluator = match source {
        Some(source) => {
            TreeWalk::with_options_and_source(&ir, options, source.source_name, source.source_bytes)
        }
        None => TreeWalk::with_options(&ir, options),
    };
    let metadata = ParallelTreeWalkWorkerMetadata::from_evaluator(&evaluator);
    let value = evaluator.eval_root()?;
    let string_context = root_string_context(&evaluator, value)?;
    evaluator.force_root_derivation_surfaces(value)?;
    let derivations = evaluator.derivation_snapshot()?;
    Ok((
        ParallelOutputTaskResult::new(string_context, drv_outputs_from_derivations(derivations)?),
        metadata,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParallelTreeWalkWorkerMetadata {
    parallel_thunk_worker_id: ParallelThunkWorkerId,
    heap_uses_thread_local_tier_a: bool,
}

impl ParallelTreeWalkWorkerMetadata {
    fn from_evaluator(evaluator: &TreeWalk) -> Self {
        Self {
            parallel_thunk_worker_id: evaluator.parallel_thunk_worker_id(),
            heap_uses_thread_local_tier_a: evaluator.heap().uses_thread_local_tier_a(),
        }
    }
}

fn root_string_context(
    evaluator: &TreeWalk,
    value: Value,
) -> Result<StringContext, ParallelTreeWalkDrvEvaluationError> {
    if value.tag() != ValueTag::String {
        return Ok(StringContext::empty());
    }
    evaluator
        .heap()
        .get_string(value)
        .map(|string| string.context().clone())
        .map_err(|source| ParallelTreeWalkDrvEvaluationError::RootStringContext { source })
}

fn drv_outputs_from_derivations<I>(
    derivations: I,
) -> Result<Vec<ParallelDrvOutput>, ParallelTreeWalkDrvEvaluationError>
where
    I: IntoIterator<Item = EvalDerivation>,
{
    derivations
        .into_iter()
        .map(|derivation| {
            let path = derivation.absolute_path().as_bytes().to_vec();
            let bytes = derivation.aterm_bytes().ok_or_else(|| {
                ParallelTreeWalkDrvEvaluationError::MissingDerivationAterm {
                    path: derivation.absolute_path().to_owned(),
                }
            })?;
            ParallelDrvOutput::try_new(path, bytes.to_vec()).map_err(Into::into)
        })
        .collect()
}

fn serial_drv_output_collation(
    roots: &[ParallelTreeWalkRoot],
    options: TreeWalkOptions,
) -> Result<ParallelOutputCollation, ParallelTreeWalkDrvDifferentialError> {
    let fragments = roots
        .iter()
        .cloned()
        .enumerate()
        .map(|(task_index, root)| {
            let output = eval_drv_outputs_for_root(root, options.clone()).map_err(|source| {
                ParallelTreeWalkDrvDifferentialError::SerialRoot { task_index, source }
            })?;
            Ok(ParallelOutputFragment::new(
                task_index,
                0,
                output.string_context().clone(),
                output.drv_outputs().to_vec(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    collate_parallel_output_fragments(fragments).map_err(|source| {
        ParallelTreeWalkDrvDifferentialError::Collation {
            worker_count: None,
            source,
        }
    })
}

fn canonical_outcomes_from_parallel_report(
    worker_count: NonZeroUsize,
    task_count: usize,
    report: &ParallelTreeWalkRawEvaluationReport,
) -> Result<Vec<ParallelTreeWalkCanonicalOutcome>, ParallelTreeWalkDifferentialError> {
    if report.worker_count() != worker_count.get()
        || report.task_count() != task_count
        || report.completed_task_count() != task_count
        || report.cancelled_before_start_count() != 0
        || report.cancelled()
        || report.outcomes().len() != task_count
    {
        return Err(ParallelTreeWalkDifferentialError::IncompleteRun {
            worker_count: worker_count.get(),
            reported_worker_count: report.worker_count(),
            task_count,
            reported_task_count: report.task_count(),
            completed_task_count: report.completed_task_count(),
            cancelled_before_start_count: report.cancelled_before_start_count(),
            cancelled: report.cancelled(),
            outcome_count: report.outcomes().len(),
        });
    }

    report
        .outcomes()
        .iter()
        .enumerate()
        .map(|(expected_task_index, outcome)| {
            if outcome.task_index() != expected_task_index {
                return Err(ParallelTreeWalkDifferentialError::UnexpectedTaskOrder {
                    worker_count: worker_count.get(),
                    expected_task_index,
                    actual_task_index: outcome.task_index(),
                });
            }
            Ok(ParallelTreeWalkCanonicalOutcome::new(
                outcome.task_index(),
                outcome
                    .outcome()
                    .as_ref()
                    .map(|evaluation| evaluation.raw_bytes().to_vec())
                    .map_err(ParallelTreeWalkCanonicalError::from_evaluation_error),
            ))
        })
        .collect()
}

fn drv_output_collation_from_parallel_report(
    worker_count: NonZeroUsize,
    task_count: usize,
    report: &ParallelTreeWalkDrvEvaluationReport,
) -> Result<ParallelOutputCollation, ParallelTreeWalkDrvDifferentialError> {
    if report.worker_count() != worker_count.get()
        || report.task_count() != task_count
        || report.completed_task_count() != task_count
        || report.cancelled_before_start_count() != 0
        || report.cancelled()
        || report.outcomes().len() != task_count
    {
        return Err(ParallelTreeWalkDrvDifferentialError::IncompleteRun {
            worker_count: worker_count.get(),
            reported_worker_count: report.worker_count(),
            task_count,
            reported_task_count: report.task_count(),
            completed_task_count: report.completed_task_count(),
            cancelled_before_start_count: report.cancelled_before_start_count(),
            cancelled: report.cancelled(),
            outcome_count: report.outcomes().len(),
        });
    }

    let fragments = report
        .outcomes()
        .iter()
        .enumerate()
        .map(|(expected_task_index, outcome)| {
            if outcome.task_index() != expected_task_index {
                return Err(ParallelTreeWalkDrvDifferentialError::UnexpectedTaskOrder {
                    worker_count: worker_count.get(),
                    expected_task_index,
                    actual_task_index: outcome.task_index(),
                });
            }
            let evaluation = outcome.outcome().as_ref().map_err(|source| {
                ParallelTreeWalkDrvDifferentialError::ParallelRoot {
                    worker_count: worker_count.get(),
                    task_index: outcome.task_index(),
                    source: source.clone(),
                }
            })?;
            let output = evaluation.output();
            Ok(ParallelOutputFragment::new(
                outcome.task_index(),
                outcome.worker_id(),
                output.string_context().clone(),
                output.drv_outputs().to_vec(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;

    collate_parallel_output_fragments(fragments).map_err(|source| {
        ParallelTreeWalkDrvDifferentialError::Collation {
            worker_count: Some(worker_count.get()),
            source,
        }
    })
}

fn compare_parallel_tree_walk_outcomes(
    worker_count: usize,
    serial_outcomes: &[ParallelTreeWalkCanonicalOutcome],
    parallel_outcomes: &[ParallelTreeWalkCanonicalOutcome],
) -> Result<(), ParallelTreeWalkDifferentialError> {
    for (task_index, serial) in serial_outcomes.iter().enumerate() {
        let Some(parallel) = parallel_outcomes.get(task_index) else {
            return Err(ParallelTreeWalkDifferentialError::IncompleteRun {
                worker_count,
                reported_worker_count: worker_count,
                task_count: serial_outcomes.len(),
                reported_task_count: serial_outcomes.len(),
                completed_task_count: parallel_outcomes.len(),
                cancelled_before_start_count: 0,
                cancelled: false,
                outcome_count: parallel_outcomes.len(),
            });
        };
        if serial != parallel {
            return Err(ParallelTreeWalkDifferentialError::Divergence {
                worker_count,
                task_index,
                serial: serial.clone(),
                parallel: parallel.clone(),
            });
        }
    }

    Ok(())
}

fn validate_parallel_tree_walk_worker_count(
    worker_count: NonZeroUsize,
) -> Result<(), ParallelTreeWalkTopLevelError> {
    parallel_thunk_worker_id_for_scheduler_worker_count(worker_count)
        .map(|_| ())
        .map_err(
            |worker_id| ParallelTreeWalkTopLevelError::WorkerIdOutOfRange {
                worker_id,
                worker_count: worker_count.get(),
            },
        )
}

fn parallel_thunk_worker_ids_for_scheduler(
    worker_count: NonZeroUsize,
) -> Result<Vec<ParallelThunkWorkerId>, ParallelTreeWalkTopLevelError> {
    validate_parallel_tree_walk_worker_count(worker_count)?;
    (0..worker_count.get())
        .map(|worker_id| {
            parallel_thunk_worker_id_for_scheduler_worker_id(worker_id).ok_or(
                ParallelTreeWalkTopLevelError::WorkerIdOutOfRange {
                    worker_id,
                    worker_count: worker_count.get(),
                },
            )
        })
        .collect()
}

fn parallel_thunk_worker_id_for_scheduler_worker_count(
    worker_count: NonZeroUsize,
) -> Result<ParallelThunkWorkerId, usize> {
    let worker_id = worker_count.get() - 1;
    parallel_thunk_worker_id_for_scheduler_worker_id(worker_id).ok_or(worker_id)
}

fn parallel_thunk_worker_id_for_scheduler_worker_id(
    worker_id: usize,
) -> Option<ParallelThunkWorkerId> {
    u64::try_from(worker_id)
        .ok()
        .and_then(|worker_id| worker_id.checked_add(1))
        .and_then(ParallelThunkWorkerId::new)
}

/// A lowered root submitted to scheduler-backed tree-walk evaluation.
#[derive(Clone, Debug)]
pub struct ParallelTreeWalkRoot {
    ir: Ir,
    source: Option<ParallelTreeWalkRootSource>,
}

impl ParallelTreeWalkRoot {
    /// Creates a source-less expression-style root.
    pub fn expression(ir: Ir) -> Self {
        Self { ir, source: None }
    }

    /// Creates a source-backed root with file provenance.
    pub fn source(
        ir: Ir,
        source_name: impl Into<Vec<u8>>,
        source_bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            ir,
            source: Some(ParallelTreeWalkRootSource {
                source_name: source_name.into(),
                source_bytes: source_bytes.into(),
            }),
        }
    }

    /// Returns the lowered root IR.
    pub const fn ir(&self) -> &Ir {
        &self.ir
    }

    /// Returns the configured source name, if this root has file provenance.
    pub fn source_name(&self) -> Option<&[u8]> {
        self.source
            .as_ref()
            .map(ParallelTreeWalkRootSource::source_name)
    }

    /// Returns the configured source bytes, if this root has file provenance.
    pub fn source_bytes(&self) -> Option<&[u8]> {
        self.source
            .as_ref()
            .map(ParallelTreeWalkRootSource::source_bytes)
    }
}

/// File provenance carried by a scheduler-backed tree-walk root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelTreeWalkRootSource {
    source_name: Vec<u8>,
    source_bytes: Vec<u8>,
}

impl ParallelTreeWalkRootSource {
    /// Returns the source name used for position-sensitive builtins.
    pub fn source_name(&self) -> &[u8] {
        &self.source_name
    }

    /// Returns the source bytes used for position-sensitive builtins.
    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }
}

/// A successful raw value produced by a scheduler-backed tree-walk task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelTreeWalkRawEvaluation {
    raw_bytes: Vec<u8>,
    parallel_thunk_worker_id: ParallelThunkWorkerId,
    heap_uses_thread_local_tier_a: bool,
}

impl ParallelTreeWalkRawEvaluation {
    /// Returns the strict raw value bytes.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Returns the parallel thunk worker id installed for this task.
    pub const fn parallel_thunk_worker_id(&self) -> ParallelThunkWorkerId {
        self.parallel_thunk_worker_id
    }

    /// Returns whether the task heap used thread-local Tier-A worker storage.
    pub const fn heap_uses_thread_local_tier_a(&self) -> bool {
        self.heap_uses_thread_local_tier_a
    }

    /// Consumes the evaluation and returns the strict raw value bytes.
    pub fn into_raw_bytes(self) -> Vec<u8> {
        self.raw_bytes
    }
}

/// A successful `.drv` surface produced by a scheduler-backed tree-walk task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelTreeWalkDrvEvaluation {
    output: ParallelOutputTaskResult,
    parallel_thunk_worker_id: ParallelThunkWorkerId,
    heap_uses_thread_local_tier_a: bool,
}

impl ParallelTreeWalkDrvEvaluation {
    /// Returns the task-local deterministic output surface.
    pub const fn output(&self) -> &ParallelOutputTaskResult {
        &self.output
    }

    /// Returns the parallel thunk worker id installed for this task.
    pub const fn parallel_thunk_worker_id(&self) -> ParallelThunkWorkerId {
        self.parallel_thunk_worker_id
    }

    /// Returns whether the task heap used thread-local Tier-A worker storage.
    pub const fn heap_uses_thread_local_tier_a(&self) -> bool {
        self.heap_uses_thread_local_tier_a
    }
}

/// A raw tree-walk task outcome after scheduler metadata has been removed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelTreeWalkCanonicalOutcome {
    task_index: usize,
    outcome: Result<Vec<u8>, ParallelTreeWalkCanonicalError>,
}

impl ParallelTreeWalkCanonicalOutcome {
    /// Builds a canonical raw tree-walk task outcome for comparison.
    pub fn new(
        task_index: usize,
        outcome: Result<Vec<u8>, ParallelTreeWalkCanonicalError>,
    ) -> Self {
        Self {
            task_index,
            outcome,
        }
    }

    /// Returns the stable top-level task index.
    pub const fn task_index(&self) -> usize {
        self.task_index
    }

    /// Returns the normalized raw result or exact tree-walk error.
    pub const fn outcome(&self) -> &Result<Vec<u8>, ParallelTreeWalkCanonicalError> {
        &self.outcome
    }
}

/// An exact tree-walk error used for serial-vs-parallel comparison.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParallelTreeWalkCanonicalError {
    /// A tree-walk evaluation or rendering error with no scheduler-owned metadata stripped.
    #[error("tree-walk raw evaluation failed: {source}")]
    TreeWalk {
        /// The tree-walk evaluation or rendering error.
        source: TreeWalkError,
    },
}

impl ParallelTreeWalkCanonicalError {
    fn from_tree_walk_error(source: TreeWalkError) -> Self {
        Self::TreeWalk { source }
    }

    fn from_evaluation_error(source: &ParallelTreeWalkEvaluationError) -> Self {
        match source {
            ParallelTreeWalkEvaluationError::TreeWalk { source } => {
                Self::from_tree_walk_error(source.clone())
            }
        }
    }
}

/// Successful serial-vs-parallel raw tree-walk differential comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelTreeWalkDifferentialReport {
    task_count: usize,
    worker_counts: Vec<usize>,
    serial_outcomes: Vec<ParallelTreeWalkCanonicalOutcome>,
}

impl ParallelTreeWalkDifferentialReport {
    /// Returns the number of top-level roots compared in every run.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns all scheduler worker counts compared against the serial oracle.
    pub fn worker_counts(&self) -> &[usize] {
        &self.worker_counts
    }

    /// Returns the serial tree-walk oracle outcomes in stable task order.
    pub fn serial_outcomes(&self) -> &[ParallelTreeWalkCanonicalOutcome] {
        &self.serial_outcomes
    }
}

/// Successful serial-vs-Chase-Lev `.drv` surface differential comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelTreeWalkDrvDifferentialReport {
    task_count: usize,
    worker_counts: Vec<usize>,
    collation: ParallelOutputCollation,
}

impl ParallelTreeWalkDrvDifferentialReport {
    /// Returns the number of top-level roots compared in every run.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns all scheduler worker counts compared against the serial oracle.
    pub fn worker_counts(&self) -> &[usize] {
        &self.worker_counts
    }

    /// Returns the canonical `.drv` output collation shared by all runs.
    pub const fn collation(&self) -> &ParallelOutputCollation {
        &self.collation
    }
}

/// A top-level failure from scheduler-backed tree-walk evaluation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParallelTreeWalkTopLevelError {
    /// The configured scheduler worker count cannot fit in the thunk state word.
    #[error(
        "parallel tree-walk worker {worker_id} of {worker_count} cannot be encoded as a thunk worker id"
    )]
    WorkerIdOutOfRange {
        /// The largest zero-based scheduler worker id that would be assigned.
        worker_id: usize,
        /// The configured scheduler worker count.
        worker_count: usize,
    },
    /// The safe L1 scheduler failed before all root-local outcomes were reported.
    #[error("parallel tree-walk scheduler failed: {source}")]
    Scheduler {
        /// The scheduler infrastructure failure.
        #[from]
        source: ParallelFallibleTopLevelError,
    },
}

/// A failure while comparing scheduler-backed tree-walk raw output.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParallelTreeWalkDifferentialError {
    /// No worker counts were supplied for comparison.
    #[error("parallel tree-walk differential requires at least one worker count")]
    NoWorkerCounts,
    /// A requested worker count cannot fit in the parallel thunk state-word format.
    #[error(
        "parallel tree-walk differential worker {worker_id} of {worker_count} cannot be encoded as a thunk worker id"
    )]
    WorkerCountOutOfRange {
        /// The configured scheduler worker count.
        worker_count: usize,
        /// The largest zero-based scheduler worker id that would be assigned.
        worker_id: usize,
    },
    /// Cache-bearing options could make later runs observe state from earlier runs.
    #[error(
        "parallel tree-walk differential does not support persistent cache roots (parse_cache_root={parse_cache_root}, persist_cache_root={persist_cache_root})"
    )]
    StatefulCacheOptionsUnsupported {
        /// Whether a parse-cache root was configured.
        parse_cache_root: bool,
        /// Whether a persistent eval-cache root was configured.
        persist_cache_root: bool,
    },
    /// A scheduler-backed run failed before normalized outcomes could be compared.
    #[error(
        "parallel tree-walk differential failed while executing {worker_count} worker(s): {source}"
    )]
    Scheduler {
        /// The worker count used by the failed run.
        worker_count: usize,
        /// The scheduler-backed tree-walk top-level failure.
        #[source]
        source: ParallelTreeWalkTopLevelError,
    },
    /// A collect-all scheduler-backed run did not report every submitted root.
    #[error(
        "parallel tree-walk differential expected {worker_count} worker(s) and {task_count} submitted root(s), but the run reported {reported_worker_count} worker(s), {reported_task_count} submitted root(s), {completed_task_count} completed task(s), {cancelled_before_start_count} cancelled task(s), cancelled={cancelled}, and {outcome_count} outcome(s)"
    )]
    IncompleteRun {
        /// The expected worker count.
        worker_count: usize,
        /// The worker count reported by the run.
        reported_worker_count: usize,
        /// The expected number of roots submitted.
        task_count: usize,
        /// The submitted root count reported by the run.
        reported_task_count: usize,
        /// The run's completed task count.
        completed_task_count: usize,
        /// The run's cancelled-before-start task count.
        cancelled_before_start_count: usize,
        /// Whether the run reported cooperative cancellation.
        cancelled: bool,
        /// The number of reported outcomes.
        outcome_count: usize,
    },
    /// A collect-all scheduler-backed run returned outcomes out of task order.
    #[error(
        "parallel tree-walk differential with {worker_count} worker(s) reported task {actual_task_index} where task {expected_task_index} was expected"
    )]
    UnexpectedTaskOrder {
        /// The worker count used by the malformed run.
        worker_count: usize,
        /// The expected stable task index at this output position.
        expected_task_index: usize,
        /// The actual stable task index at this output position.
        actual_task_index: usize,
    },
    /// A scheduler-backed run produced a normalized outcome different from serial tree-walk.
    #[error(
        "parallel tree-walk differential diverged from serial tree-walk for task {task_index} with {worker_count} worker(s)"
    )]
    Divergence {
        /// The worker count used by the divergent run.
        worker_count: usize,
        /// The stable task index that diverged.
        task_index: usize,
        /// The serial tree-walk oracle outcome.
        serial: ParallelTreeWalkCanonicalOutcome,
        /// The scheduler-backed tree-walk outcome.
        parallel: ParallelTreeWalkCanonicalOutcome,
    },
}

/// A failure while comparing Chase-Lev-backed tree-walk `.drv` surfaces.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParallelTreeWalkDrvDifferentialError {
    /// No worker counts were supplied for comparison.
    #[error("parallel tree-walk .drv differential requires at least one worker count")]
    NoWorkerCounts,
    /// A requested worker count cannot fit in the parallel thunk state-word format.
    #[error(
        "parallel tree-walk .drv differential worker {worker_id} of {worker_count} cannot be encoded as a thunk worker id"
    )]
    WorkerCountOutOfRange {
        /// The configured scheduler worker count.
        worker_count: usize,
        /// The largest zero-based scheduler worker id that would be assigned.
        worker_id: usize,
    },
    /// Cache-bearing options could make later runs observe state from earlier runs.
    #[error(
        "parallel tree-walk .drv differential does not support persistent cache roots (parse_cache_root={parse_cache_root}, persist_cache_root={persist_cache_root})"
    )]
    StatefulCacheOptionsUnsupported {
        /// Whether a parse-cache root was configured.
        parse_cache_root: bool,
        /// Whether a persistent eval-cache root was configured.
        persist_cache_root: bool,
    },
    /// A serial root failed before the baseline `.drv` surface could be collated.
    #[error("serial tree-walk .drv differential root {task_index} failed: {source}")]
    SerialRoot {
        /// The stable task index that failed.
        task_index: usize,
        /// The root-local derivation-surface failure.
        #[source]
        source: ParallelTreeWalkDrvEvaluationError,
    },
    /// A scheduler-backed run failed before normalized outcomes could be compared.
    #[error(
        "parallel tree-walk .drv differential failed while executing {worker_count} worker(s): {source}"
    )]
    Scheduler {
        /// The worker count used by the failed run.
        worker_count: usize,
        /// The scheduler-backed tree-walk top-level failure.
        #[source]
        source: ParallelTreeWalkTopLevelError,
    },
    /// A collect-all scheduler-backed run did not report every submitted root.
    #[error(
        "parallel tree-walk .drv differential expected {worker_count} worker(s) and {task_count} submitted root(s), but the run reported {reported_worker_count} worker(s), {reported_task_count} submitted root(s), {completed_task_count} completed task(s), {cancelled_before_start_count} cancelled task(s), cancelled={cancelled}, and {outcome_count} outcome(s)"
    )]
    IncompleteRun {
        /// The expected worker count.
        worker_count: usize,
        /// The worker count reported by the run.
        reported_worker_count: usize,
        /// The expected number of roots submitted.
        task_count: usize,
        /// The submitted root count reported by the run.
        reported_task_count: usize,
        /// The run's completed task count.
        completed_task_count: usize,
        /// The run's cancelled-before-start task count.
        cancelled_before_start_count: usize,
        /// Whether the run reported cooperative cancellation.
        cancelled: bool,
        /// The number of reported outcomes.
        outcome_count: usize,
    },
    /// A collect-all scheduler-backed run returned outcomes out of task order.
    #[error(
        "parallel tree-walk .drv differential with {worker_count} worker(s) reported task {actual_task_index} where task {expected_task_index} was expected"
    )]
    UnexpectedTaskOrder {
        /// The worker count used by the malformed run.
        worker_count: usize,
        /// The expected stable task index at this output position.
        expected_task_index: usize,
        /// The actual stable task index at this output position.
        actual_task_index: usize,
    },
    /// A scheduler-backed root failed before its `.drv` surface could be collated.
    #[error(
        "parallel tree-walk .drv differential root {task_index} failed with {worker_count} worker(s): {source}"
    )]
    ParallelRoot {
        /// The worker count used by the failed run.
        worker_count: usize,
        /// The stable task index that failed.
        task_index: usize,
        /// The root-local derivation-surface failure.
        #[source]
        source: ParallelTreeWalkDrvEvaluationError,
    },
    /// A serial or parallel `.drv` output collation failed.
    #[error("parallel tree-walk .drv differential collation failed: {source}")]
    Collation {
        /// The worker count used by the failed run, or `None` for the serial baseline.
        worker_count: Option<usize>,
        /// The output collation failure.
        #[source]
        source: ParallelOutputDeterminismError,
    },
    /// A scheduler-backed run produced a `.drv` collation different from serial tree-walk.
    #[error(
        "parallel tree-walk .drv differential diverged from serial tree-walk with {worker_count} worker(s)"
    )]
    Divergence {
        /// The worker count used by the divergent run.
        worker_count: usize,
        /// The serial tree-walk oracle collation.
        serial: ParallelOutputCollation,
        /// The scheduler-backed tree-walk collation.
        parallel: ParallelOutputCollation,
    },
}

/// A root-local tree-walk failure from raw evaluation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParallelTreeWalkEvaluationError {
    /// The tree-walk evaluator failed while evaluating or rendering the root.
    #[error("tree-walk raw evaluation failed: {source}")]
    TreeWalk {
        /// The tree-walk evaluation or rendering error.
        #[from]
        source: TreeWalkError,
    },
}

/// A root-local tree-walk failure from `.drv` surface evaluation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParallelTreeWalkDrvEvaluationError {
    /// The tree-walk evaluator failed while evaluating the root.
    #[error("tree-walk .drv surface evaluation failed: {source}")]
    TreeWalk {
        /// The tree-walk evaluation error.
        #[from]
        source: TreeWalkError,
    },
    /// A recorded derivation did not expose materialized ATerm bytes.
    #[error("tree-walk derivation {path} did not expose ATerm bytes")]
    MissingDerivationAterm {
        /// The recorded derivation path.
        path: String,
    },
    /// The evaluated root was a string but its heap record could not be inspected.
    #[error("tree-walk .drv root string context lookup failed: {source}")]
    RootStringContext {
        /// The heap lookup failure.
        #[source]
        source: EvalHeapError,
    },
    /// The deterministic output collector rejected the derivation surface.
    #[error(transparent)]
    Output(#[from] ParallelOutputDeterminismError),
}

#[cfg(test)]
mod tests {
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
        let worker_ids =
            parallel_thunk_worker_ids_for_scheduler(workers(3)).expect("worker ids fit");
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
                    evaluation.raw_bytes().to_vec()
                })
                .collect::<Vec<_>>(),
            vec![b"3".to_vec(), b"8".to_vec()]
        );
    }

    #[test]
    fn parallel_raw_eval_preserves_source_provenance_for_file_roots() {
        let source_name = b"/tmp/aos-parallel-tree-walk-source.nix";
        let source = b"# comment\nbuiltins.toJSON __curPos";
        let ir = lower(std::str::from_utf8(source).expect("test source is UTF-8"));
        let expected = eval_raw_bytes_with_options_source(
            &ir,
            TreeWalkOptions::default(),
            source_name,
            source,
        )
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
        let expected = eval_raw_bytes_with_options_source(
            &ir,
            TreeWalkOptions::default(),
            source_name,
            source,
        )
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
        let source_error_ir =
            lower(std::str::from_utf8(source_error).expect("test source is UTF-8"));
        let roots = [
            ParallelTreeWalkRoot::expression(lower("1 + 2")),
            ParallelTreeWalkRoot::source(source_ir, source_name.to_vec(), source.to_vec()),
            ParallelTreeWalkRoot::expression(lower("builtins.throw \"same error\"")),
            ParallelTreeWalkRoot::source(
                source_error_ir,
                source_name.to_vec(),
                source_error.to_vec(),
            ),
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
        let source_error_ir =
            lower(std::str::from_utf8(source_error).expect("test source is UTF-8"));
        let roots = [
            ParallelTreeWalkRoot::expression(lower("1 + 2")),
            ParallelTreeWalkRoot::source(source_ir, source_name.to_vec(), source.to_vec()),
            ParallelTreeWalkRoot::expression(lower("builtins.throw \"same error\"")),
            ParallelTreeWalkRoot::source(
                source_error_ir,
                source_name.to_vec(),
                source_error.to_vec(),
            ),
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
        let worker_ids =
            parallel_thunk_worker_ids_for_scheduler(workers(3)).expect("worker ids fit");
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
                && evaluation.output().drv_outputs().len() == 1
                && evaluation.output().drv_outputs()[0]
                    .path()
                    .ends_with(b".drv")
        }));
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
        let options =
            TreeWalkOptions::with_persist_cache_root("/tmp/aos-chase-lev-diff-persist-cache");

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
        let options =
            TreeWalkOptions::with_parse_cache_root("/tmp/aos-chase-lev-drv-diff-parse-cache");

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
        .expect_err(
            "oversized Chase-Lev scheduler worker count is rejected before queue allocation",
        );

        assert!(matches!(
            error,
            ParallelTreeWalkTopLevelError::WorkerIdOutOfRange {
                worker_id,
                worker_count: rejected_count,
            } if worker_id == worker_count.get() - 1 && rejected_count == worker_count.get()
        ));
    }
}
