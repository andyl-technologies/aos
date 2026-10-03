//! Physical delivery ceilings derived from retained canonical peer outputs.

use super::host_concurrent::{HeldHostRun, validate_host_run_outcome};
use super::*;

#[derive(Clone, Debug)]
pub(in crate::scheduler) struct HeldDeliveryCeiling {
    peers: Vec<HeldHostRun>,
    topology: SchedulerLookaheadGraph,
}

impl HeldDeliveryCeiling {
    pub(super) fn observe(
        scheduler: &SingleScheduler,
        peers: &BTreeMap<NodeId, HeldHostRun>,
    ) -> Self {
        Self {
            peers: peers
                .values()
                .filter(|held| !held.completed.network_outputs.is_empty())
                .cloned()
                .collect(),
            topology: scheduler.effective_topology.clone(),
        }
    }

    pub(in crate::scheduler) fn bound(
        &self,
        scheduler: &SingleScheduler,
        target: &RuntimeSchedulerNode,
    ) -> Result<Option<NodeCounter>, SchedulerError> {
        if self.topology != scheduler.effective_topology {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("held delivery ceiling changed its effective topology"),
            });
        }
        let mut earliest = None;
        for peer in &self.peers {
            validate_host_run_outcome(&peer.run, &peer.completed)?;
            let source = scheduler.nodes.get(peer.run.plan.index).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("held output lost its actual scheduler source"),
                }
            })?;
            if source.id != peer.run.plan.node || source.counter != peer.run.plan.before {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("held output changed its uncommitted source"),
                });
            }
            let emitted = scheduler.node_time_for_counter(
                source,
                NodeCounter {
                    ticks: peer.completed.step.reached.ticks,
                },
            )?;
            for edge in self.topology.edges() {
                if edge.from != source.id || edge.to != target.id {
                    continue;
                }
                let delivery = emitted
                    .ticks
                    .checked_add(edge.minimum_latency.ticks)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("held output delivery ceiling overflowed"),
                    })?;
                let counter = scheduler
                    .node_counter_for_time_floor(target, SimInstant { ticks: delivery })?;
                earliest =
                    Some(earliest.map_or(counter, |before: NodeCounter| before.min(counter)));
            }
        }
        Ok(earliest)
    }
}
