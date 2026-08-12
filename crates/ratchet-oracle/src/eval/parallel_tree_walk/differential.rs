//! Serial-vs-parallel differential comparison drivers.
//!
//! Runs the same roots serially and across a ladder of worker counts (mutex
//! ring and Chase-Lev schedulers), comparing raw renderings or .drv output
//! collations for byte equality, with preflights that surface option
//! combinations the differential cannot support.

use super::*;

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

pub(crate) fn compare_parallel_tree_walk_raw_across_worker_counts_with<I, W, S, F>(
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
