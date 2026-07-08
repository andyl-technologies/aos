//! Parallel output collation precursors.
//!
//! This module owns the deterministic collation boundary that the future
//! parallel evaluator must preserve after tasks complete in nondeterministic
//! order. It models three RFC-0007 output rules before the real evaluator is
//! wired in:
//!
//! ```text
//! worker fragments -> stable task order
//! string contexts  -> order-independent canonical union
//! .drv outputs     -> path-sorted collection with content-only SHA-256 hashes
//! ```
//!
//! The implementation is a planning and test surface. It does not execute
//! thunks, materialize derivations, iterate live attrsets, or run the final
//! full-closure `.drv` differential harness.

use std::{collections::BTreeMap, num::NonZeroUsize};

use thiserror::Error;

use crate::string::{NixStringError, StringContext};

use super::parallel::{ParallelTopLevelError, execute_parallel_top_level};

/// Compares scheduler-backed output collation across worker counts.
///
/// The first worker count is the baseline. Each run executes the same cloned
/// top-level task payloads through the safe L1 scheduler precursor, stamps task
/// outputs with scheduler-observed task and worker metadata, collates the
/// fragments, and compares the resulting canonical output against the baseline.
///
/// # Errors
///
/// Returns [`ParallelOutputDifferentialError::NoWorkerCounts`] if no worker
/// counts are supplied. Returns [`ParallelOutputDifferentialError::Scheduler`]
/// if the safe scheduler fails, [`ParallelOutputDifferentialError::Collation`]
/// if one run emits invalid fragments, or
/// [`ParallelOutputDifferentialError::Divergence`] if any candidate worker count
/// produces canonical output that differs from the baseline.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped scheduler
/// worker threads.
pub fn compare_parallel_output_across_worker_counts<I, T, W, F>(
    tasks: I,
    worker_counts: W,
    worker: F,
) -> Result<ParallelOutputDifferentialReport, ParallelOutputDifferentialError>
where
    I: IntoIterator<Item = T>,
    T: Clone + Send,
    W: IntoIterator<Item = NonZeroUsize>,
    F: Fn(T) -> ParallelOutputTaskResult + Sync,
{
    let tasks = tasks.into_iter().collect::<Vec<_>>();
    let worker_counts = worker_counts.into_iter().collect::<Vec<_>>();
    let Some((&baseline_worker_count, candidate_worker_counts)) = worker_counts.split_first()
    else {
        return Err(ParallelOutputDifferentialError::NoWorkerCounts);
    };

    let baseline = run_parallel_output_collation(&tasks, baseline_worker_count, &worker)?;
    for &candidate_worker_count in candidate_worker_counts {
        let candidate = run_parallel_output_collation(&tasks, candidate_worker_count, &worker)?;
        if candidate != baseline {
            return Err(ParallelOutputDifferentialError::Divergence {
                baseline_worker_count: baseline_worker_count.get(),
                candidate_worker_count: candidate_worker_count.get(),
                baseline,
                candidate,
            });
        }
    }

    Ok(ParallelOutputDifferentialReport {
        task_count: tasks.len(),
        baseline_worker_count: baseline_worker_count.get(),
        worker_counts: worker_counts.iter().map(|count| count.get()).collect(),
        collation: baseline,
    })
}

fn run_parallel_output_collation<T, F>(
    tasks: &[T],
    worker_count: NonZeroUsize,
    worker: &F,
) -> Result<ParallelOutputCollation, ParallelOutputDifferentialError>
where
    T: Clone + Send,
    F: Fn(T) -> ParallelOutputTaskResult + Sync,
{
    let report = execute_parallel_top_level(tasks.iter().cloned(), worker_count, worker).map_err(
        |source| ParallelOutputDifferentialError::Scheduler {
            worker_count: worker_count.get(),
            source,
        },
    )?;
    let fragments = report.results().iter().map(|execution| {
        let result = execution.result();
        ParallelOutputFragment::new(
            execution.task_index(),
            execution.worker_id(),
            result.string_context.clone(),
            result.drv_outputs.clone(),
        )
    });
    collate_parallel_output_fragments(fragments).map_err(|source| {
        ParallelOutputDifferentialError::Collation {
            worker_count: worker_count.get(),
            source,
        }
    })
}

/// Collates worker-emitted output fragments into canonical output order.
///
/// Fragments are sorted by stable top-level task index before collation.
/// Duplicate task fragments are rejected because the L1 scheduler contract is
/// one visible result per task. String contexts are merged with
/// [`StringContext::union`], and `.drv` outputs are collected by path in
/// lexicographic order. Repeated `.drv` paths with identical bytes converge to
/// one output; repeated paths with different bytes are reported as conflicts.
///
/// # Errors
///
/// Returns [`ParallelOutputDeterminismError::DuplicateTaskFragment`] when more
/// than one fragment has the same task index. Returns
/// [`ParallelOutputDeterminismError::ConflictingDrvOutput`] when the same `.drv`
/// path is emitted with different bytes. Returns
/// [`ParallelOutputDeterminismError::StringContext`] if context union fails.
pub fn collate_parallel_output_fragments<I>(
    fragments: I,
) -> Result<ParallelOutputCollation, ParallelOutputDeterminismError>
where
    I: IntoIterator<Item = ParallelOutputFragment>,
{
    let mut ordered_fragments = fragments.into_iter().collect::<Vec<_>>();
    ordered_fragments.sort_by_key(ParallelOutputFragment::task_index);

    for pair in ordered_fragments.windows(2) {
        if pair[0].task_index == pair[1].task_index {
            return Err(ParallelOutputDeterminismError::DuplicateTaskFragment {
                task_index: pair[0].task_index,
            });
        }
    }

    let fragment_count = ordered_fragments.len();
    let mut string_context = StringContext::empty();
    let mut drv_outputs = BTreeMap::<Vec<u8>, ParallelDrvOutput>::new();

    for fragment in ordered_fragments {
        string_context = string_context.union(&fragment.string_context)?;
        for output in fragment.drv_outputs {
            let Some(existing) = drv_outputs.get(output.path()) else {
                drv_outputs.insert(output.path.clone(), output);
                continue;
            };
            if existing.bytes() != output.bytes() {
                return Err(ParallelOutputDeterminismError::ConflictingDrvOutput {
                    path: output.path,
                    existing_sha256: existing.content_sha256,
                    incoming_sha256: output.content_sha256,
                });
            }
        }
    }

    Ok(ParallelOutputCollation {
        fragment_count,
        string_context,
        drv_outputs: drv_outputs.into_values().collect(),
    })
}

/// Computes the content-only SHA-256 digest for `.drv` output bytes.
pub fn parallel_drv_output_content_sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut fixed = [0_u8; 32];
    fixed.copy_from_slice(digest.as_ref());
    fixed
}

/// Output produced by one top-level task before scheduler metadata is attached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelOutputTaskResult {
    string_context: StringContext,
    drv_outputs: Vec<ParallelDrvOutput>,
}

impl ParallelOutputTaskResult {
    /// Builds one task-local output result.
    pub fn new(string_context: StringContext, drv_outputs: Vec<ParallelDrvOutput>) -> Self {
        Self {
            string_context,
            drv_outputs,
        }
    }

    /// Returns the string context contributed by this task.
    pub const fn string_context(&self) -> &StringContext {
        &self.string_context
    }

    /// Returns `.drv` outputs contributed by this task.
    pub fn drv_outputs(&self) -> &[ParallelDrvOutput] {
        &self.drv_outputs
    }
}

/// One output fragment emitted after a top-level task completes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelOutputFragment {
    task_index: usize,
    worker_id: usize,
    string_context: StringContext,
    drv_outputs: Vec<ParallelDrvOutput>,
}

impl ParallelOutputFragment {
    /// Builds one worker-emitted output fragment.
    pub fn new(
        task_index: usize,
        worker_id: usize,
        string_context: StringContext,
        drv_outputs: Vec<ParallelDrvOutput>,
    ) -> Self {
        Self {
            task_index,
            worker_id,
            string_context,
            drv_outputs,
        }
    }

    /// Returns the stable top-level task index.
    pub const fn task_index(&self) -> usize {
        self.task_index
    }

    /// Returns the worker that emitted this fragment.
    pub const fn worker_id(&self) -> usize {
        self.worker_id
    }

    /// Returns the string context contributed by this fragment.
    pub const fn string_context(&self) -> &StringContext {
        &self.string_context
    }

    /// Returns `.drv` outputs contributed by this fragment.
    pub fn drv_outputs(&self) -> &[ParallelDrvOutput] {
        &self.drv_outputs
    }
}

/// One materialized `.drv` output candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelDrvOutput {
    path: Vec<u8>,
    bytes: Vec<u8>,
    content_sha256: [u8; 32],
}

impl ParallelDrvOutput {
    /// Creates a `.drv` output candidate and hashes its bytes.
    ///
    /// This precursor only validates that a path is present. Store-path syntax
    /// and the `.drv` suffix remain caller-owned invariants until this boundary
    /// is wired to derivation materialization.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelOutputDeterminismError::EmptyDrvOutputPath`] when
    /// `path` is empty.
    pub fn try_new(path: Vec<u8>, bytes: Vec<u8>) -> Result<Self, ParallelOutputDeterminismError> {
        if path.is_empty() {
            return Err(ParallelOutputDeterminismError::EmptyDrvOutputPath);
        }
        let content_sha256 = parallel_drv_output_content_sha256(&bytes);
        Ok(Self {
            path,
            bytes,
            content_sha256,
        })
    }

    /// Returns the raw `.drv` path bytes.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Returns the materialized `.drv` bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the content-only SHA-256 digest of [`Self::bytes`].
    pub const fn content_sha256(&self) -> [u8; 32] {
        self.content_sha256
    }
}

/// Canonical output state after parallel fragment collation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelOutputCollation {
    fragment_count: usize,
    string_context: StringContext,
    drv_outputs: Vec<ParallelDrvOutput>,
}

impl ParallelOutputCollation {
    /// Returns how many fragments were accepted.
    pub const fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    /// Returns the order-independent union of all fragment string contexts.
    pub const fn string_context(&self) -> &StringContext {
        &self.string_context
    }

    /// Returns `.drv` outputs in lexicographic path order.
    pub fn drv_outputs(&self) -> &[ParallelDrvOutput] {
        &self.drv_outputs
    }

    /// Returns the number of unique `.drv` output paths.
    pub fn drv_output_count(&self) -> usize {
        self.drv_outputs.len()
    }
}

/// Successful scheduler-backed thread-count output comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelOutputDifferentialReport {
    task_count: usize,
    baseline_worker_count: usize,
    worker_counts: Vec<usize>,
    collation: ParallelOutputCollation,
}

impl ParallelOutputDifferentialReport {
    /// Returns the number of top-level tasks compared in every run.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns the worker count used as the baseline run.
    pub const fn baseline_worker_count(&self) -> usize {
        self.baseline_worker_count
    }

    /// Returns all worker counts compared, with the baseline first.
    pub fn worker_counts(&self) -> &[usize] {
        &self.worker_counts
    }

    /// Returns the canonical output shared by all compared worker counts.
    pub const fn collation(&self) -> &ParallelOutputCollation {
        &self.collation
    }
}

/// A failure while collating parallel output fragments.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParallelOutputDeterminismError {
    /// More than one fragment was emitted for the same top-level task.
    #[error("parallel output fragment for task {task_index} was emitted more than once")]
    DuplicateTaskFragment {
        /// The duplicated task index.
        task_index: usize,
    },
    /// A `.drv` output path was empty.
    #[error("parallel drv output path is empty")]
    EmptyDrvOutputPath,
    /// The same `.drv` path was emitted with different content bytes.
    #[error("parallel drv output path {path:?} was emitted with conflicting bytes")]
    ConflictingDrvOutput {
        /// The conflicting `.drv` path bytes.
        path: Vec<u8>,
        /// The SHA-256 digest of the first bytes seen for this path.
        existing_sha256: [u8; 32],
        /// The SHA-256 digest of the later conflicting bytes.
        incoming_sha256: [u8; 32],
    },
    /// String context union failed.
    #[error(transparent)]
    StringContext(#[from] NixStringError),
}

/// A failure while comparing scheduler-backed output across worker counts.
#[derive(Debug, Error)]
pub enum ParallelOutputDifferentialError {
    /// No worker counts were supplied for comparison.
    #[error("parallel output differential requires at least one worker count")]
    NoWorkerCounts,
    /// The safe top-level scheduler failed for one worker count.
    #[error(
        "parallel output differential failed while executing {worker_count} worker(s): {source}"
    )]
    Scheduler {
        /// The worker count used by the failed run.
        worker_count: usize,
        /// The scheduler failure.
        #[source]
        source: ParallelTopLevelError,
    },
    /// Output collation failed for one worker count.
    #[error(
        "parallel output differential failed while collating {worker_count} worker(s): {source}"
    )]
    Collation {
        /// The worker count used by the failed run.
        worker_count: usize,
        /// The output collation failure.
        #[source]
        source: ParallelOutputDeterminismError,
    },
    /// A candidate worker count produced output that differed from the baseline.
    #[error(
        "parallel output differential diverged between {baseline_worker_count} and {candidate_worker_count} worker(s)"
    )]
    Divergence {
        /// The baseline worker count.
        baseline_worker_count: usize,
        /// The worker count that differed from the baseline.
        candidate_worker_count: usize,
        /// The canonical output produced by the baseline run.
        baseline: ParallelOutputCollation,
        /// The canonical output produced by the candidate run.
        candidate: ParallelOutputCollation,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::ContextElement;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn opaque(path: &[u8]) -> ContextElement {
        ContextElement::opaque_path(path.to_vec()).expect("opaque context builds")
    }

    fn output(path: &[u8], name: &[u8]) -> ContextElement {
        ContextElement::single_output(path.to_vec(), name.to_vec()).expect("output context builds")
    }

    fn deep(path: &[u8]) -> ContextElement {
        ContextElement::deep_derivation(path.to_vec()).expect("deep context builds")
    }

    fn context(elements: Vec<ContextElement>) -> StringContext {
        StringContext::new(elements)
    }

    fn drv(path: &[u8], bytes: &[u8]) -> ParallelDrvOutput {
        ParallelDrvOutput::try_new(path.to_vec(), bytes.to_vec()).expect("drv output builds")
    }

    fn task_result(
        string_context: StringContext,
        drv_outputs: Vec<ParallelDrvOutput>,
    ) -> ParallelOutputTaskResult {
        ParallelOutputTaskResult::new(string_context, drv_outputs)
    }

    fn fragment(
        task_index: usize,
        worker_id: usize,
        string_context: StringContext,
        drv_outputs: Vec<ParallelDrvOutput>,
    ) -> ParallelOutputFragment {
        ParallelOutputFragment::new(task_index, worker_id, string_context, drv_outputs)
    }

    fn workers(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("test worker count is nonzero")
    }

    #[test]
    fn scheduler_backed_differential_matches_across_worker_counts() {
        let source = opaque(b"/nix/store/aaa-source");
        let dep = output(b"/nix/store/bbb-pkg.drv", b"out");
        let report = compare_parallel_output_across_worker_counts(
            0..6,
            [workers(1), workers(2), workers(4)],
            |task| {
                let context = if task % 2 == 0 {
                    context(vec![source.clone()])
                } else {
                    context(vec![dep.clone()])
                };
                task_result(
                    context,
                    vec![drv(
                        format!("/nix/store/task-{task}.drv").as_bytes(),
                        format!("drv-bytes-{task}").as_bytes(),
                    )],
                )
            },
        )
        .expect("thread-count output comparison succeeds");

        assert_eq!(report.task_count(), 6);
        assert_eq!(report.baseline_worker_count(), 1);
        assert_eq!(report.worker_counts(), &[1, 2, 4]);
        assert_eq!(report.collation().fragment_count(), 6);
        assert_eq!(
            report.collation().string_context().elements(),
            &[source, dep]
        );
        assert_eq!(report.collation().drv_output_count(), 6);
    }

    #[test]
    fn scheduler_backed_differential_rejects_empty_worker_counts() {
        let error = compare_parallel_output_across_worker_counts(0..1, [], |_| {
            task_result(StringContext::empty(), Vec::new())
        })
        .expect_err("empty worker-count list rejects");

        assert!(matches!(
            error,
            ParallelOutputDifferentialError::NoWorkerCounts
        ));
    }

    #[test]
    fn scheduler_backed_differential_reports_collation_failures() {
        let error = compare_parallel_output_across_worker_counts(0..2, [workers(2)], |task| {
            task_result(
                StringContext::empty(),
                vec![drv(
                    b"/nix/store/shared.drv",
                    format!("bytes-{task}").as_bytes(),
                )],
            )
        })
        .expect_err("conflicting drv outputs reject");

        assert!(matches!(
            error,
            ParallelOutputDifferentialError::Collation {
                worker_count: 2,
                source: ParallelOutputDeterminismError::ConflictingDrvOutput { .. },
            }
        ));
    }

    #[test]
    fn scheduler_backed_differential_reports_thread_count_divergence() {
        let serial = AtomicUsize::new(0);

        let error =
            compare_parallel_output_across_worker_counts(0..2, [workers(1), workers(2)], |task| {
                let observed = serial.fetch_add(1, Ordering::SeqCst);
                task_result(
                    StringContext::empty(),
                    vec![drv(
                        format!("/nix/store/task-{task}.drv").as_bytes(),
                        format!("observed-{observed}").as_bytes(),
                    )],
                )
            })
            .expect_err("stateful task output diverges across runs");

        match error {
            ParallelOutputDifferentialError::Divergence {
                baseline_worker_count,
                candidate_worker_count,
                baseline,
                candidate,
            } => {
                assert_eq!(baseline_worker_count, 1);
                assert_eq!(candidate_worker_count, 2);
                assert_ne!(baseline, candidate);
            }
            other => panic!("unexpected differential error: {other}"),
        }
    }

    #[test]
    fn collation_is_independent_of_fragment_completion_order() {
        let source = opaque(b"/nix/store/aaa-source");
        let dep = output(b"/nix/store/bbb-pkg.drv", b"out");
        let toolchain = deep(b"/nix/store/ccc-toolchain.drv");

        let first = collate_parallel_output_fragments([
            fragment(
                2,
                0,
                context(vec![toolchain.clone()]),
                vec![drv(b"/nix/store/zzz-third.drv", b"third")],
            ),
            fragment(
                0,
                1,
                context(vec![source.clone(), dep.clone()]),
                vec![drv(b"/nix/store/aaa-first.drv", b"first")],
            ),
            fragment(
                1,
                0,
                context(vec![dep.clone()]),
                vec![drv(b"/nix/store/zzz-third.drv", b"third")],
            ),
        ])
        .expect("first collation succeeds");
        let second = collate_parallel_output_fragments([
            fragment(
                1,
                0,
                context(vec![dep.clone()]),
                vec![drv(b"/nix/store/zzz-third.drv", b"third")],
            ),
            fragment(
                2,
                0,
                context(vec![toolchain.clone()]),
                vec![drv(b"/nix/store/zzz-third.drv", b"third")],
            ),
            fragment(
                0,
                1,
                context(vec![source.clone(), dep.clone()]),
                vec![drv(b"/nix/store/aaa-first.drv", b"first")],
            ),
        ])
        .expect("second collation succeeds");

        assert_eq!(first, second);
        assert_eq!(first.fragment_count(), 3);
        assert_eq!(first.string_context().elements(), &[source, dep, toolchain]);
        assert_eq!(first.drv_output_count(), 2);
        assert_eq!(
            first
                .drv_outputs()
                .iter()
                .map(ParallelDrvOutput::path)
                .collect::<Vec<_>>(),
            vec![
                b"/nix/store/aaa-first.drv".as_slice(),
                b"/nix/store/zzz-third.drv".as_slice()
            ]
        );
    }

    #[test]
    fn drv_output_hashes_depend_only_on_content_bytes() {
        let left = drv(b"/nix/store/aaa-left.drv", b"same bytes");
        let right = drv(b"/nix/store/zzz-right.drv", b"same bytes");
        let different = drv(b"/nix/store/aaa-left.drv", b"different bytes");

        assert_eq!(left.content_sha256(), right.content_sha256());
        assert_eq!(
            left.content_sha256(),
            parallel_drv_output_content_sha256(b"same bytes")
        );
        assert_ne!(left.content_sha256(), different.content_sha256());
    }

    #[test]
    fn duplicate_task_fragments_are_rejected() {
        let error = collate_parallel_output_fragments([
            fragment(0, 0, StringContext::empty(), Vec::new()),
            fragment(0, 1, StringContext::empty(), Vec::new()),
        ])
        .expect_err("duplicate task fragments reject");

        assert_eq!(
            error,
            ParallelOutputDeterminismError::DuplicateTaskFragment { task_index: 0 }
        );
    }

    #[test]
    fn conflicting_drv_outputs_are_rejected() {
        let path = b"/nix/store/conflict.drv";
        let error = collate_parallel_output_fragments([
            fragment(1, 0, StringContext::empty(), vec![drv(path, b"incoming")]),
            fragment(0, 0, StringContext::empty(), vec![drv(path, b"existing")]),
        ])
        .expect_err("conflicting drv outputs reject");

        assert_eq!(
            error,
            ParallelOutputDeterminismError::ConflictingDrvOutput {
                path: path.to_vec(),
                existing_sha256: parallel_drv_output_content_sha256(b"existing"),
                incoming_sha256: parallel_drv_output_content_sha256(b"incoming"),
            }
        );
    }

    #[test]
    fn duplicate_drv_outputs_inside_one_fragment_are_collated_the_same_way() {
        let path = b"/nix/store/repeated.drv";
        let ok = collate_parallel_output_fragments([fragment(
            0,
            0,
            StringContext::empty(),
            vec![drv(path, b"same"), drv(path, b"same")],
        )])
        .expect("identical duplicate drv outputs converge");

        assert_eq!(ok.drv_output_count(), 1);
        assert_eq!(ok.drv_outputs()[0].bytes(), b"same");

        let error = collate_parallel_output_fragments([fragment(
            0,
            0,
            StringContext::empty(),
            vec![drv(path, b"left"), drv(path, b"right")],
        )])
        .expect_err("conflicting duplicate drv outputs reject");

        assert_eq!(
            error,
            ParallelOutputDeterminismError::ConflictingDrvOutput {
                path: path.to_vec(),
                existing_sha256: parallel_drv_output_content_sha256(b"left"),
                incoming_sha256: parallel_drv_output_content_sha256(b"right"),
            }
        );
    }

    #[test]
    fn empty_drv_output_paths_are_rejected() {
        let error = ParallelDrvOutput::try_new(Vec::new(), b"bytes".to_vec())
            .expect_err("empty paths reject");

        assert_eq!(error, ParallelOutputDeterminismError::EmptyDrvOutputPath);
    }

    #[test]
    fn empty_collation_has_no_outputs() {
        let collation = collate_parallel_output_fragments(Vec::<ParallelOutputFragment>::new())
            .expect("empty collation succeeds");

        assert_eq!(collation.fragment_count(), 0);
        assert!(collation.string_context().is_empty());
        assert!(collation.drv_outputs().is_empty());
    }
}
