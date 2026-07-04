//! Scheduler-backed tree-walk evaluation precursors.
//!
//! This module bridges the safe Phase 3.5 L1 scheduler to real tree-walk
//! evaluation of independent lowered roots. Each task owns a separate
//! `TreeWalk` evaluator and heap, and receives the active parallel thunk worker
//! id for the scheduler worker that actually executes it. This is still a
//! coarse-root bridge: it does not share thunk graphs between roots, allocate
//! from live per-worker nurseries, or replace the serial tree-walk force path.

use std::num::NonZeroUsize;

use thiserror::Error;

use crate::compile::Ir;

use super::{
    parallel_failure::{
        ParallelFailurePolicy, ParallelFallibleTaskContext, ParallelFallibleTopLevelError,
        ParallelFallibleTopLevelReport, execute_parallel_top_level_fallible_with_worker,
    },
    thunk_cas::ParallelThunkWorkerId,
    tree_walk::{
        TreeWalkError, TreeWalkOptions, eval_raw_bytes_with_options,
        eval_raw_bytes_with_options_source,
    },
};

/// A scheduler-backed tree-walk raw-evaluation report.
pub type ParallelTreeWalkRawEvaluationReport =
    ParallelFallibleTopLevelReport<ParallelTreeWalkRawEvaluation, ParallelTreeWalkEvaluationError>;

/// Evaluates independent expression-style lowered roots through the safe L1 scheduler.
///
/// This convenience entry point treats every root as source-less expression
/// evaluation, matching [`eval_raw_bytes_with_options`]. Use
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

/// Evaluates independent lowered roots through the safe L1 scheduler.
///
/// Each root is evaluated by a fresh tree-walk evaluator and rendered with the
/// same raw strict syntax as the tree-walk raw renderer. Source-less roots use
/// [`eval_raw_bytes_with_options`]; source-backed roots use
/// [`eval_raw_bytes_with_options_source`] so position-sensitive builtins see
/// the supplied source name and bytes. The supplied options are cloned for
/// every task, then the active parallel thunk worker id is replaced with a
/// non-zero id derived from the scheduler worker that actually executes the
/// root.
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

fn eval_raw_bytes_for_parallel_worker(
    context: ParallelFallibleTaskContext,
    root: ParallelTreeWalkRoot,
    base_options: &TreeWalkOptions,
    worker_ids: &[ParallelThunkWorkerId],
) -> Result<ParallelTreeWalkRawEvaluation, ParallelTreeWalkEvaluationError> {
    let parallel_thunk_worker_id = worker_ids[context.worker_id()];
    let mut options = base_options.clone();
    options.set_parallel_thunk_worker_id(parallel_thunk_worker_id);
    let ParallelTreeWalkRoot { ir, source } = root;
    let raw_bytes = match source {
        Some(source) => eval_raw_bytes_with_options_source(
            &ir,
            options,
            source.source_name,
            source.source_bytes,
        )?,
        None => eval_raw_bytes_with_options(&ir, options)?,
    };

    Ok(ParallelTreeWalkRawEvaluation {
        raw_bytes,
        parallel_thunk_worker_id,
    })
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

    /// Consumes the evaluation and returns the strict raw value bytes.
    pub fn into_raw_bytes(self) -> Vec<u8> {
        self.raw_bytes
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

/// A root-local failure from scheduler-backed tree-walk evaluation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParallelTreeWalkEvaluationError {
    /// The tree-walk evaluator failed while evaluating or rendering the root.
    #[error("tree-walk raw evaluation failed: {source}")]
    TreeWalk {
        /// The tree-walk evaluation or rendering error.
        #[from]
        source: TreeWalkError,
    },
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crate::{
        compile::resolve as resolve_ast,
        eval::tree_walk::{
            TreeWalkErrorKind, eval_raw_bytes_with_options, eval_raw_bytes_with_options_source,
        },
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
        }));
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
}
