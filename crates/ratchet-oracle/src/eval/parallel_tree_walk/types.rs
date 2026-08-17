//! Root, evaluation-result, heap-report, and error types for parallel tree-walk.

use super::*;

/// A lowered root submitted to scheduler-backed tree-walk evaluation.
#[derive(Clone, Debug)]
pub struct ParallelTreeWalkRoot {
    pub(crate) ir: Ir,
    pub(crate) source: Option<ParallelTreeWalkRootSource>,
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
    pub(crate) source_name: Vec<u8>,
    pub(crate) source_bytes: Vec<u8>,
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
    pub(crate) raw_bytes: Vec<u8>,
    pub(crate) parallel_thunk_worker_id: ParallelThunkWorkerId,
    pub(crate) worker_heap_report: ParallelTreeWalkWorkerHeapReport,
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
        self.worker_heap_report.uses_thread_local_tier_a()
    }

    /// Returns the heap counters observed after this task completed.
    pub const fn worker_heap_report(&self) -> ParallelTreeWalkWorkerHeapReport {
        self.worker_heap_report
    }

    /// Consumes the evaluation and returns the strict raw value bytes.
    pub fn into_raw_bytes(self) -> Vec<u8> {
        self.raw_bytes
    }
}

/// A successful `.drv` surface produced by a scheduler-backed tree-walk task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelTreeWalkDrvEvaluation {
    pub(crate) output: ParallelOutputTaskResult,
    pub(crate) parallel_thunk_worker_id: ParallelThunkWorkerId,
    pub(crate) worker_heap_report: ParallelTreeWalkWorkerHeapReport,
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
        self.worker_heap_report.uses_thread_local_tier_a()
    }

    /// Returns the heap counters observed after this task completed.
    pub const fn worker_heap_report(&self) -> ParallelTreeWalkWorkerHeapReport {
        self.worker_heap_report
    }
}

/// Heap counters observed after one successful scheduler-backed tree-walk task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParallelTreeWalkWorkerHeapReport {
    heap_records: usize,
    worker_allocation_safepoints: u64,
    permanent_allocation_safepoints: u64,
    uses_thread_local_tier_a: bool,
}

impl ParallelTreeWalkWorkerHeapReport {
    pub(crate) fn from_evaluator(evaluator: &TreeWalk) -> Self {
        let heap = evaluator.heap();
        Self {
            heap_records: heap.len(),
            worker_allocation_safepoints: heap.allocation_safepoints().count(),
            permanent_allocation_safepoints: heap.permanent_allocation_safepoints().count(),
            uses_thread_local_tier_a: heap.uses_thread_local_tier_a(),
        }
    }

    /// Returns the number of typed heap records owned by the completed task.
    pub const fn heap_records(self) -> usize {
        self.heap_records
    }

    /// Returns worker-domain allocation safepoints observed by the task heap.
    pub const fn worker_allocation_safepoints(self) -> u64 {
        self.worker_allocation_safepoints
    }

    /// Returns permanent-domain allocation safepoints observed by the task heap.
    pub const fn permanent_allocation_safepoints(self) -> u64 {
        self.permanent_allocation_safepoints
    }

    /// Returns whether worker allocations used thread-local Tier-A storage.
    pub const fn uses_thread_local_tier_a(self) -> bool {
        self.uses_thread_local_tier_a
    }
}

/// Worker-local heap totals aggregated from successful tree-walk tasks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParallelTreeWalkWorkerHeapSummary {
    worker_id: usize,
    successful_tasks: usize,
    heap_records: usize,
    worker_allocation_safepoints: u64,
    permanent_allocation_safepoints: u64,
    all_successful_tasks_used_thread_local_tier_a: bool,
}

impl ParallelTreeWalkWorkerHeapSummary {
    const fn empty(worker_id: usize) -> Self {
        Self {
            worker_id,
            successful_tasks: 0,
            heap_records: 0,
            worker_allocation_safepoints: 0,
            permanent_allocation_safepoints: 0,
            all_successful_tasks_used_thread_local_tier_a: true,
        }
    }

    fn record_success(&mut self, report: ParallelTreeWalkWorkerHeapReport) {
        self.successful_tasks = self.successful_tasks.saturating_add(1);
        self.heap_records = self.heap_records.saturating_add(report.heap_records());
        self.worker_allocation_safepoints = self
            .worker_allocation_safepoints
            .saturating_add(report.worker_allocation_safepoints());
        self.permanent_allocation_safepoints = self
            .permanent_allocation_safepoints
            .saturating_add(report.permanent_allocation_safepoints());
        self.all_successful_tasks_used_thread_local_tier_a &= report.uses_thread_local_tier_a();
    }

    /// Returns the scheduler worker this summary describes.
    pub const fn worker_id(self) -> usize {
        self.worker_id
    }

    /// Returns how many successful tasks contributed heap counters.
    pub const fn successful_tasks(self) -> usize {
        self.successful_tasks
    }

    /// Returns the summed typed heap records from successful tasks.
    pub const fn heap_records(self) -> usize {
        self.heap_records
    }

    /// Returns the summed worker-domain allocation safepoints.
    pub const fn worker_allocation_safepoints(self) -> u64 {
        self.worker_allocation_safepoints
    }

    /// Returns the summed permanent-domain allocation safepoints.
    pub const fn permanent_allocation_safepoints(self) -> u64 {
        self.permanent_allocation_safepoints
    }

    /// Returns whether every successful task used thread-local Tier-A storage.
    pub const fn all_successful_tasks_used_thread_local_tier_a(self) -> bool {
        self.all_successful_tasks_used_thread_local_tier_a
    }
}

/// Summarizes successful raw tree-walk task heap counters by executing worker.
///
/// Root-local errors do not contribute to the returned heap counters because no
/// final task heap snapshot is available for failed evaluations.
pub fn summarize_parallel_tree_walk_raw_worker_heaps(
    report: &ParallelTreeWalkRawEvaluationReport,
) -> Vec<ParallelTreeWalkWorkerHeapSummary> {
    let mut summaries = (0..report.worker_count())
        .map(ParallelTreeWalkWorkerHeapSummary::empty)
        .collect::<Vec<_>>();
    for outcome in report.outcomes() {
        if let (Some(summary), Ok(evaluation)) = (
            summaries.get_mut(outcome.worker_id()),
            outcome.outcome().as_ref(),
        ) {
            summary.record_success(evaluation.worker_heap_report());
        }
    }
    summaries
}

/// Summarizes successful `.drv` tree-walk task heap counters by executing worker.
///
/// Root-local errors do not contribute to the returned heap counters because no
/// final task heap snapshot is available for failed evaluations.
pub fn summarize_parallel_tree_walk_drv_worker_heaps(
    report: &ParallelTreeWalkDrvEvaluationReport,
) -> Vec<ParallelTreeWalkWorkerHeapSummary> {
    let mut summaries = (0..report.worker_count())
        .map(ParallelTreeWalkWorkerHeapSummary::empty)
        .collect::<Vec<_>>();
    for outcome in report.outcomes() {
        if let (Some(summary), Ok(evaluation)) = (
            summaries.get_mut(outcome.worker_id()),
            outcome.outcome().as_ref(),
        ) {
            summary.record_success(evaluation.worker_heap_report());
        }
    }
    summaries
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
    pub(crate) fn from_tree_walk_error(source: TreeWalkError) -> Self {
        Self::TreeWalk { source }
    }

    pub(crate) fn from_evaluation_error(source: &ParallelTreeWalkEvaluationError) -> Self {
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
    pub(crate) task_count: usize,
    pub(crate) worker_counts: Vec<usize>,
    pub(crate) serial_outcomes: Vec<ParallelTreeWalkCanonicalOutcome>,
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
    pub(crate) task_count: usize,
    pub(crate) worker_counts: Vec<usize>,
    pub(crate) collation: ParallelOutputCollation,
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
