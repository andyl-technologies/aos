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
        EvalDerivation, TreeWalk, TreeWalkError, TreeWalkOptions,
        eval_raw_bytes_with_evaluator_owned,
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

mod differential;
mod types;

pub use differential::*;
pub use types::*;

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
        worker_heap_report: metadata.heap_report,
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
        worker_heap_report: metadata.heap_report,
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
    let (raw_bytes, evaluator) = eval_raw_bytes_with_evaluator_owned(&ir, evaluator)?;
    let metadata = ParallelTreeWalkWorkerMetadata::from_evaluator(&evaluator);
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
    let value = evaluator.eval_root()?;
    let string_context = root_string_context(&evaluator, value)?;
    evaluator.force_root_derivation_surfaces(value)?;
    let derivations = evaluator.derivation_snapshot()?;
    let metadata = ParallelTreeWalkWorkerMetadata::from_evaluator(&evaluator);
    Ok((
        ParallelOutputTaskResult::new(string_context, drv_outputs_from_derivations(derivations)?),
        metadata,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParallelTreeWalkWorkerMetadata {
    parallel_thunk_worker_id: ParallelThunkWorkerId,
    heap_report: ParallelTreeWalkWorkerHeapReport,
}

impl ParallelTreeWalkWorkerMetadata {
    fn from_evaluator(evaluator: &TreeWalk) -> Self {
        Self {
            parallel_thunk_worker_id: evaluator.parallel_thunk_worker_id(),
            heap_report: ParallelTreeWalkWorkerHeapReport::from_evaluator(evaluator),
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

#[cfg(test)]
mod tests;
