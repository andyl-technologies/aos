//! Catch-up RUNs that keep held publication in canonical time order.
//!
//! A host-concurrent RUN set leaves nodes on different clocks. Before a held
//! RUN publishes at time `t`, every unheld live node must reach `t`, so no
//! earlier output can reach EMIT after it. This module plans those catch-up
//! RUNs as one concurrent batch, projects held evidence to emission floors
//! for their horizons, and refuses publication while a node still lags.

use super::held_boundary::{HeldBoundaryRun, backend_run};
use super::host_concurrent::{HeldHostRun, refresh_held_host_run_boundary};
use super::*;

/// Executes scheduler-fixed catch-up RUNs and returns results in input order.
pub(super) fn execute_host_runs<'a, B: ConcurrentSimulationBackend>(
    backend: &mut B,
    runs: impl Iterator<Item = &'a PreparedHostRun>,
    max_host_workers: usize,
) -> Result<Vec<ConcurrentBackendRunResult>, SchedulerError> {
    let mut backend_runs = Vec::new();
    for run in runs {
        if backend.dispatch_contract() != run.dispatch_contract {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("backend dispatch contract changed before physical RUN"),
            });
        }
        backend_runs.push(backend_run(run));
    }
    let expected = backend_runs.len();
    let results = backend.execute_concurrent_runs(backend_runs, max_host_workers.max(1))?;
    if results.len() != expected {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("host worker continuation changed cardinality"),
        });
    }
    Ok(results)
}

/// Why an unheld node needs a catch-up RUN before the next publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CatchupKind {
    /// The node was not part of the original RUN set.
    Omitted,
    /// The node's earlier RUN already published below the next publication.
    Lagging,
}

/// One planned catch-up RUN with the clock it starts from.
pub(super) struct PlannedCatchup {
    pub(super) node: NodeId,
    pub(super) current: SimInstant,
    pub(super) run: PreparedHostRun,
    pub(super) kind: CatchupKind,
}

/// Projects each held RUN to the evidence it proves about its node.
///
/// A held RUN stops at its first output, so a RUN with outputs emits at its
/// reached tick and its emission floor lies one tick before it. A RUN without
/// outputs emits nothing through its settled endpoint. An unresolved boundary
/// RUN may still emit at its stop. The executed-through point is where the
/// physical VM stands: the reached tick, the settled endpoint, or the stop.
pub(super) fn held_peer_evidence(
    scheduler: &SingleScheduler,
    held_runs: &BTreeMap<NodeId, HeldHostRun>,
    boundary_runs: &BTreeMap<NodeId, HeldBoundaryRun>,
) -> Result<BTreeMap<NodeId, HeldPeerEvidence>, SchedulerError> {
    let time = |node: &NodeId, ticks: u64| {
        scheduler
            .backend_network_output_time(node, Icount { retired: ticks })
            .map(|at| SimInstant { ticks: at.ticks })
    };

    let mut evidence = BTreeMap::new();
    for (node, held) in held_runs {
        let step = &held.completed.step;
        let proven = if held.completed.network_outputs.is_empty() {
            let settled = time(node, step.settled_through.ticks)?;
            HeldPeerEvidence {
                emission_floor: settled,
                executed_through: settled,
            }
        } else {
            let reached = time(node, step.reached.ticks)?;
            HeldPeerEvidence {
                emission_floor: SimInstant {
                    ticks: reached.ticks.saturating_sub(1),
                },
                executed_through: reached,
            }
        };
        evidence.insert(node.clone(), proven);
    }
    for (node, held) in boundary_runs {
        let stopped = time(node, held.boundary.stopped().ticks)?;
        evidence.insert(
            node.clone(),
            HeldPeerEvidence {
                emission_floor: SimInstant {
                    ticks: stopped.ticks.saturating_sub(1),
                },
                executed_through: stopped,
            },
        );
    }
    Ok(evidence)
}

/// Refuses to publish at `next_time` while an unheld live node lags behind it.
pub(super) fn require_caught_up(
    scheduler: &SingleScheduler,
    next_time: VirtualTime,
    held_runs: &BTreeMap<NodeId, HeldHostRun>,
    boundary_runs: &BTreeMap<NodeId, HeldBoundaryRun>,
) -> Result<(), SchedulerError> {
    for runtime in &scheduler.nodes {
        let node = &runtime.id.node;
        if held_runs.contains_key(node)
            || boundary_runs.contains_key(node)
            || runtime.campaign_parked
            || scheduler.effective_node_activity(runtime) != SchedulerNodeActivity::Runnable
        {
            continue;
        }
        if scheduler.node_scheduler_time(runtime)?.ticks < next_time.ticks {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "runnable node `{}` cannot catch up to held publication at {}",
                    node.name, next_time.ticks
                ),
            });
        }
    }
    Ok(())
}
impl<L, B, I> BackendQuantumLoop<L, B, I>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    /// Plans a catch-up RUN for every unheld live node behind `next_time`.
    ///
    /// Omitted nodes come first in node order, then lagging RUN-set members
    /// in node order. A node blocked behind an upstream node gets no RUN this
    /// round; it advances after that upstream node catches up.
    pub(super) fn plan_held_catchups(
        &mut self,
        staged_scheduler: &mut SingleScheduler,
        next_time: VirtualTime,
        initial_topology: &SchedulerLookaheadGraph,
        original_runs: &BTreeMap<NodeId, PreparedHostRun>,
        held_runs: &BTreeMap<NodeId, HeldHostRun>,
        boundary_runs: &BTreeMap<NodeId, HeldBoundaryRun>,
    ) -> Result<Vec<PlannedCatchup>, SchedulerError> {
        let catchup_at = SimInstant {
            ticks: next_time.ticks,
        };
        let contract = self.selected_dispatch_contract()?;
        let mut omitted_nodes = staged_scheduler
            .nodes
            .iter()
            .enumerate()
            .map(|(index, runtime)| (runtime.id.node.clone(), index))
            .collect::<Vec<_>>();
        omitted_nodes.sort_by(|left, right| left.0.cmp(&right.0));

        let mut catchups = Vec::new();
        for (node, index) in omitted_nodes {
            if original_runs.contains_key(&node) {
                continue;
            }
            let current = staged_scheduler.node_scheduler_time(&staged_scheduler.nodes[index])?;
            if current.ticks >= next_time.ticks {
                continue;
            }
            refresh_held_host_run_boundary(staged_scheduler, initial_topology)?;
            if let Some(run) = staged_scheduler
                .prepare_host_catchup_run_for_contract(index, catchup_at, contract)?
            {
                catchups.push(PlannedCatchup {
                    node,
                    current,
                    run,
                    kind: CatchupKind::Omitted,
                });
            }
        }

        for (node, original) in original_runs {
            if held_runs.contains_key(node) || boundary_runs.contains_key(node) {
                continue;
            }
            let runtime = &staged_scheduler.nodes[original.plan.index];
            if runtime.campaign_parked {
                // A parked VM abandons the rest of its RUN at the marker;
                // it receives a fresh RUN only after the all-VM join.
                continue;
            }
            let current = staged_scheduler.node_scheduler_time(runtime)?;
            let before = runtime.counter;
            let settled = runtime.settled;
            if current.ticks >= next_time.ticks {
                continue;
            }
            refresh_held_host_run_boundary(staged_scheduler, initial_topology)?;
            // Only an earlier authenticated stop leaves part of the original
            // RUN unsettled. A settled RUN whose clock stopped below its
            // ceiling has no remainder to republish.
            let run = if settled.ticks < original.plan.target_counter {
                Some(staged_scheduler.prepare_host_run_continuation(original, before)?)
            } else {
                staged_scheduler.prepare_host_catchup_run_after(original, catchup_at)?
            };
            if let Some(run) = run {
                catchups.push(PlannedCatchup {
                    node: node.clone(),
                    current,
                    run,
                    kind: CatchupKind::Lagging,
                });
            }
        }
        Ok(catchups)
    }
}
