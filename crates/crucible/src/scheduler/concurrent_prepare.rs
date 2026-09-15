//! Speculative scheduler preparation and authoritative concurrent commit.

use super::*;
use crate::backend::StepObservation;

/// Output produced by one bounded host-concurrent scheduler round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConcurrentQuantumOutcome {
    /// RUN set selected from the same scheduler boundary before host dispatch.
    pub run_set: SchedulerConcurrentRunSet,
    /// Serialized scheduler completions for the dispatched RUN set.
    pub outcomes: Vec<QuantumOutcome>,
}

/// Deterministic set of RUNs eligible for host-level concurrent dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConcurrentRunSet {
    /// RUN candidates selected in deterministic scheduler completion order.
    pub candidates: Vec<SchedulerConcurrentRunCandidate>,
}

/// One node RUN selected for bounded host-level concurrent dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConcurrentRunCandidate {
    /// Scheduler node selected by PICK for this concurrent round.
    pub node: SchedulerNodeId,
    /// Node-local virtual time before RUN.
    pub current_time: SimInstant,
    /// Conservative lookahead-bounded virtual time for this RUN.
    pub target_time: SimInstant,
    /// Icount ceiling published before host dispatch.
    pub max_advance_icount: u64,
}

/// One backend RUN whose observable coordinate was fixed before host dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcurrentBackendRun {
    /// Node advanced by this RUN.
    pub node: NodeId,
    /// Node-local ceiling fixed by the scheduler.
    pub ceiling: VirtualTime,
    /// Modeled preemptions applied before guest execution begins.
    pub preemptions: Vec<PreemptionDecision>,
}

/// Host-worker evidence for one completed backend RUN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcurrentBackendRunOutcome {
    /// Node advanced by this RUN.
    pub node: NodeId,
    /// Completed step observation at the fixed ceiling.
    pub step: StepObservation,
    /// Causal RNG evidence drained on the node owner thread.
    pub rng_evidence: Vec<BackendRngEvidence>,
    /// Network outputs drained on the node owner thread.
    pub network_outputs: Vec<BackendNetworkOutput>,
    /// Observational events drained on the node owner thread.
    pub observations: Vec<ObservableEvent>,
}

/// Backend collection capable of executing independent scheduler RUNs in parallel.
pub trait ConcurrentSimulationBackend: SimulationBackend {
    /// Executes every scheduler-fixed RUN and returns outcomes in input order.
    ///
    /// Implementations must retain exclusive ownership of every node until its
    /// result and boundary evidence have been captured. No host completion
    /// order may escape through the returned vector.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when a node is absent, a worker fails, or any
    /// backend cannot reach its fixed ceiling and drain boundary evidence.
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        max_host_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunOutcome>, BackendError>;
}

/// One scheduler round prepared without publishing any authoritative state.
///
/// The scheduler computes PICK, RUN ceilings, RESOLVE, EMIT, and STEP against
/// a private continuation. A live adapter may therefore execute the fixed RUN
/// set on host workers before atomically installing the resulting scheduler
/// continuation after every backend RUN and fallible publication step succeeds.
#[derive(Clone, Debug)]
pub(crate) struct PreparedSchedulerConcurrentQuantum {
    pub(super) next: SingleScheduler,
    pub(super) outcome: SchedulerConcurrentQuantumOutcome,
}

impl PreparedSchedulerConcurrentQuantum {
    /// Returns the scheduler-fixed RUN set that may execute concurrently.
    #[must_use]
    pub(super) const fn run_set(&self) -> &SchedulerConcurrentRunSet {
        &self.outcome.run_set
    }

    /// Returns the canonically ordered outcomes to publish after RUN success.
    #[must_use]
    pub(super) fn outcomes(&self) -> &[QuantumOutcome] {
        &self.outcome.outcomes
    }
}

impl SingleScheduler {
    pub(super) fn concurrent_run_set_from_candidates(
        &self,
        candidates: &[AdvanceCandidate],
    ) -> Result<SchedulerConcurrentRunSet, SchedulerError> {
        let mut selected = Vec::new();
        let frontier = SimInstant {
            nanos: self.frontier.ticks,
        };
        let target_time = candidates.first().map(|candidate| candidate.target_time);

        // A parked peer can hold the global frontier behind the canonical
        // global-minimum candidate. Batching frontier peers in that state would
        // reorder PICK relative to the authoritative serial path. Advance only
        // that canonical first candidate; normal independent batches resume
        // once the common frontier is restored.
        if let Some(candidate) = candidates.first() {
            let draft = self.advance_plan_draft(candidate)?;
            let current_time =
                self.node_time_for_counter(&self.nodes[draft.index], draft.before)?;
            if current_time != frontier {
                selected.push(SchedulerConcurrentRunCandidate {
                    node: draft.node,
                    current_time,
                    target_time: candidate.target_time,
                    max_advance_icount: draft.target_counter,
                });
                return Ok(SchedulerConcurrentRunSet {
                    candidates: selected,
                });
            }
        }

        for candidate in candidates {
            if Some(candidate.target_time) != target_time {
                break;
            }
            let draft = self.advance_plan_draft(candidate)?;
            let current_time =
                self.node_time_for_counter(&self.nodes[draft.index], draft.before)?;
            if current_time != frontier {
                continue;
            }
            selected.push(SchedulerConcurrentRunCandidate {
                node: draft.node,
                current_time,
                target_time: candidate.target_time,
                max_advance_icount: draft.target_counter,
            });
        }

        Ok(SchedulerConcurrentRunSet {
            candidates: selected,
        })
    }

    /// Returns the deterministic RUN set eligible for host-level concurrency.
    ///
    /// The set contains every same-boundary RUN admitted by the scheduler's
    /// conservative horizon computation. Host worker limits are deliberately
    /// absent from this semantic projection. RESOLVE and EMIT are not performed
    /// by this read-only query.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if horizon projection discovers inconsistent
    /// scheduler state.
    pub fn concurrent_run_set(&self) -> Result<SchedulerConcurrentRunSet, SchedulerError> {
        let candidates = self.advance_candidates()?;
        self.concurrent_run_set_from_candidates(&candidates)
    }

    /// Prepares one bounded host-concurrent round without changing this scheduler.
    ///
    /// The returned RUN ceilings and completion order are fixed entirely from
    /// the current modeled state. The speculative continuation remains private
    /// until a live backend reports successful completion for every RUN.
    pub(crate) fn prepare_concurrent_quantum(
        &self,
        request: QuantumRequest,
    ) -> Result<PreparedSchedulerConcurrentQuantum, SchedulerError> {
        let mut next = self.clone();
        let outcome = next.drive_concurrent_authoritative_quantum(request)?;
        Ok(PreparedSchedulerConcurrentQuantum { next, outcome })
    }
}
