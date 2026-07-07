//! Shared-graph parallel forcing substrate and worker-pool harness.
//!
//! This module is the L2 correctness seam for RFC-0007 parallel evaluation:
//! K OS worker threads force *overlapping* sets of parallel thunk cells in one
//! shared demand graph, with the semantics the later scheduler phase builds
//! on:
//!
//! - the first claimer runs the thunk body exactly once;
//! - losing workers park on the cell's wait/notify protocol and replay the
//!   published result;
//! - a published error replays as the identical [`TreeWalkError`] for every
//!   later force;
//! - same-worker re-entry is the serial infinite-recursion error;
//! - cross-worker waiting cycles are detected through the shared
//!   [`ParallelForceCycleRegistry`] before parking and raise the same
//!   infinite-recursion error instead of deadlocking.
//!
//! # Shared versus per-worker state
//!
//! Shared across workers (all [`Sync`], published through release/acquire
//! edges of the thunk state words):
//!
//! - the parallel thunk cells of the demand graph ([`TreeWalkParallelThunkCell`],
//!   embedded in `Arc`-shared [`EvalThunk`](super::heap::EvalThunk) records);
//! - one [`ParallelForceCycleRegistry`] binding every cell (see
//!   [`super::thunk_registry`] for the registration/purge protocol and its
//!   soundness argument).
//!
//! Per-worker (worker-affine by design):
//!
//! - the `TreeWalk` evaluator instance, its environment stacks, scratch memos,
//!   store-validity SQLite reader, and [`EvalStats`](super::tree_walk::EvalStats)
//!   (merged after join via `EvalStats::merge_from`);
//! - the thread-local bump arena backing worker allocations;
//! - thunk claim guards (deliberately `!Send`).
//!
//! # What still blocks a shared production heap
//!
//! The value graph itself is `Sync` (P1), but `EvalHeap`'s *allocation and
//! resolution* machinery is per-evaluator: the record side table, hash-cons
//! tables, and allocators are `&mut`-mutated on every allocation. Until those
//! are made concurrent, K production `TreeWalk` instances cannot dereference
//! one another's freshly allocated heap values, so this harness exercises the
//! full claim/park/cycle/replay protocol on shared cells whose bodies produce
//! immediate values. Under parallel mode the production evaluator runs with
//! minor GC quiesced (production never runs minor collections; GC-stress
//! polling must stay off) and without the worker-affine tier-1 JIT engine.
//!
//! The scheduler phase (P3) replaces this harness's fixed per-worker root
//! iteration with demand-driven fan-out; the forcing protocol underneath is
//! unchanged.

use std::num::NonZeroUsize;
use std::sync::Arc;

use thiserror::Error;

use crate::compile::IrId;
use crate::syntax::Span;
use crate::value::Value;

use super::thunk::ForceError;
use super::thunk_cas::ParallelThunkWorkerId;
use super::thunk_payload::{TreeWalkParallelThunkCell, TreeWalkParallelThunkForceOutcome};
use super::thunk_registry::ParallelForceCycleRegistry;
use super::tree_walk::{TreeWalkError, TreeWalkErrorKind};

/// Builds `count` suspended parallel cells bound to one shared registry.
///
/// This is the shared-graph construction helper for the worker-pool harness:
/// every cell of one demand graph must share a single registry so cross-worker
/// wait cycles are visible to the pre-park walk. `dropped_claim_error` builds
/// the failure payload published if a claim guard unwinds without publishing
/// (a body panic).
pub fn shared_parallel_thunk_cells(
    count: usize,
    registry: &Arc<ParallelForceCycleRegistry>,
    mut dropped_claim_error: impl FnMut(usize) -> TreeWalkError,
) -> Vec<TreeWalkParallelThunkCell> {
    (0..count)
        .map(|index| {
            TreeWalkParallelThunkCell::with_cycle_registry(
                dropped_claim_error(index),
                Some(Arc::clone(registry)),
            )
        })
        .collect()
}

/// The thunk-body callback evaluated by the claim winner for one shared cell.
///
/// The body receives the claiming worker's forcer so it can recursively force
/// dependency cells through the same claim/park/cycle protocol, plus the index
/// of the cell whose body is being evaluated.
pub type ParallelSharedGraphBody<'a> =
    dyn Fn(&ParallelSharedGraphForcer<'_>, usize) -> Result<Value, TreeWalkError> + Sync + 'a;

/// A worker's handle for forcing cells of one shared demand graph.
///
/// The forcer carries the worker identity and re-enters the caller-supplied
/// body for recursive demand, so bodies can force their dependencies through
/// the same claim/park/cycle protocol.
pub struct ParallelSharedGraphForcer<'a> {
    cells: &'a [TreeWalkParallelThunkCell],
    body: &'a ParallelSharedGraphBody<'a>,
    worker: ParallelThunkWorkerId,
}

impl ParallelSharedGraphForcer<'_> {
    /// Returns the worker identity this forcer claims and waits with.
    pub const fn worker(&self) -> ParallelThunkWorkerId {
        self.worker
    }

    /// Forces the shared cell at `index` to its terminal result.
    ///
    /// The first claimer runs `body(self, index)` and publishes the result;
    /// contending workers park and replay the published value or error. An
    /// ownership cycle back to this worker (direct re-entry or a transitive
    /// cross-worker wait cycle) returns the serial infinite-recursion error.
    ///
    /// # Errors
    ///
    /// Returns the body's published [`TreeWalkError`] replay, the
    /// infinite-recursion error on evaluation cycles, or a
    /// [`TreeWalkErrorKind::ParallelThunkPayload`] error if the underlying
    /// cell synchronization fails.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of range for the shared graph, or if the body
    /// panics while this worker owns the claim (the cell then publishes its
    /// dropped-claim error for other workers).
    pub fn force(&self, index: usize) -> Result<Value, TreeWalkError> {
        let cell = &self.cells[index];
        match cell
            .force_or_wait_with(self.worker, || (self.body)(self, index))
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ParallelThunkPayload {
                        id: harness_node(index),
                        source,
                    },
                    HARNESS_SPAN,
                )
            })? {
            TreeWalkParallelThunkForceOutcome::Ready(result) => result,
            TreeWalkParallelThunkForceOutcome::SelfCycle { .. } => {
                Err(infinite_recursion_error(index))
            }
        }
    }
}

/// The synthetic span used for harness-issued diagnostics.
const HARNESS_SPAN: Span = Span::new(0, 1);

/// Returns the synthetic IR node id for the shared cell at `index`.
fn harness_node(index: usize) -> IrId {
    IrId::new(u32::try_from(index).unwrap_or(u32::MAX))
}

/// Returns the serial infinite-recursion error for the cell at `index`.
///
/// This is the same error class serial forcing raises when a blackholed thunk
/// is re-entered, so cycle outcomes under the parallel protocol stay
/// error-identical to serial evaluation.
pub fn infinite_recursion_error(index: usize) -> TreeWalkError {
    TreeWalkError::new(
        TreeWalkErrorKind::Force {
            id: harness_node(index),
            source: ForceError::InfiniteRecursion,
        },
        HARNESS_SPAN,
    )
}

/// One worker's per-root outcomes from a shared-graph force run.
#[derive(Clone, Debug)]
pub struct ParallelSharedForceWorkerReport {
    /// The worker identity installed for this OS thread.
    pub worker: ParallelThunkWorkerId,
    /// The outcome of forcing each requested root, in root order.
    pub root_results: Vec<Result<Value, TreeWalkError>>,
}

/// A shared-graph force run failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParallelSharedForceError {
    /// The worker count cannot be encoded in the thunk state-word format.
    #[error("worker count {worker_count} exceeds the parallel thunk worker-id range")]
    WorkerCountOutOfRange {
        /// The requested worker count.
        worker_count: usize,
    },
    /// A requested root index does not name a cell of the shared graph.
    #[error("root index {index} is out of range for a shared graph of {cells} cells")]
    RootIndexOutOfRange {
        /// The offending root index.
        index: usize,
        /// The number of cells in the shared graph.
        cells: usize,
    },
}

/// Forces overlapping `roots` of one shared graph from `worker_count` threads.
///
/// Every worker thread installs a distinct [`ParallelThunkWorkerId`] and
/// forces *all* requested roots (rotated by worker index for schedule
/// diversity, reported in original root order), so workers contend on the same
/// cells: first claimer runs the body, losers park and replay, and evaluation
/// cycles surface as the serial infinite-recursion error. This function is the
/// worker-pool seam the P3 scheduler will drive with demand-driven fan-out
/// instead of a fixed root list.
///
/// The supplied `body` is invoked at most once per cell across all workers and
/// may recursively force other cells through the passed
/// [`ParallelSharedGraphForcer`].
///
/// # Errors
///
/// Returns [`ParallelSharedForceError::WorkerCountOutOfRange`] if a worker id
/// cannot be encoded, or [`ParallelSharedForceError::RootIndexOutOfRange`] if
/// a root does not name a cell. Per-root evaluation failures are reported in
/// the per-worker reports, not as harness errors.
///
/// # Panics
///
/// Panics if the operating system cannot spawn a worker thread or if `body`
/// panics on the claiming worker.
pub fn force_shared_parallel_roots(
    cells: &[TreeWalkParallelThunkCell],
    roots: &[usize],
    worker_count: NonZeroUsize,
    body: &ParallelSharedGraphBody<'_>,
) -> Result<Vec<ParallelSharedForceWorkerReport>, ParallelSharedForceError> {
    let worker_ids = (1..=worker_count.get())
        .map(|raw| {
            u64::try_from(raw)
                .ok()
                .and_then(ParallelThunkWorkerId::new)
                .ok_or(ParallelSharedForceError::WorkerCountOutOfRange {
                    worker_count: worker_count.get(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    for &index in roots {
        if index >= cells.len() {
            return Err(ParallelSharedForceError::RootIndexOutOfRange {
                index,
                cells: cells.len(),
            });
        }
    }

    let reports = std::thread::scope(|scope| {
        let handles = worker_ids
            .iter()
            .enumerate()
            .map(|(worker_index, &worker)| {
                scope.spawn(move || {
                    let forcer = ParallelSharedGraphForcer {
                        cells,
                        body,
                        worker,
                    };
                    // Rotate the traversal start per worker so different
                    // workers race to claim different cells first; results are
                    // restored to original root order below.
                    let mut rotated = Vec::with_capacity(roots.len());
                    for offset in 0..roots.len() {
                        let position = (worker_index + offset) % roots.len();
                        rotated.push((position, forcer.force(roots[position])));
                    }
                    rotated.sort_by_key(|(position, _)| *position);
                    ParallelSharedForceWorkerReport {
                        worker,
                        root_results: rotated.into_iter().map(|(_, result)| result).collect(),
                    }
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| match handle.join() {
                Ok(report) => report,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect::<Vec<_>>()
    });

    Ok(reports)
}

#[cfg(test)]
mod tests;
