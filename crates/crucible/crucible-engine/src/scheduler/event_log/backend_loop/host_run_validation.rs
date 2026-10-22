//! Exact physical RUN receipts and held-peer network separation.
//!
//! Validation precedes causal publication; a physical dispatch cap cannot
//! complete its retained semantic RUN or overtake an earlier peer delivery.

use super::held_boundary::HeldBoundaryRun;
use super::held_stop::HeldHostStopKind;
use super::host_concurrent::HeldHostRun;
use super::*;
use crate::{AdvanceOutcome, BackendPhysicalStop};

pub(super) fn validate_host_run_outcome(
    planned: &PreparedHostRun,
    completed: &ConcurrentBackendRunOutcome,
) -> Result<(), SchedulerError> {
    let node = &planned.plan.node.node;
    let ceiling = VirtualTime {
        ticks: planned.plan.ceiling.max_advance_icount,
    };
    let reached = completed.step.reached;
    if planned.dispatch_contract == crate::BackendDispatchContract::PhysicalSource
        && reached.ticks < planned.admission.semantic_horizon().icount.retired
        && matches!(
            completed.step.physical_stop,
            BackendPhysicalStop::Horizon | BackendPhysicalStop::UnclassifiedPause
        )
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "internal physical cap cannot complete the original semantic RUN",
            ),
        });
    }
    if completed.node != *node
        || completed.step.requested_ceiling != ceiling
        || reached.ticks < planned.plan.before.ticks
        || reached.ticks > ceiling.ticks
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "host worker for `{}` reached {} outside requested scheduler window {}..={}",
                node.name, reached.ticks, planned.plan.before.ticks, ceiling.ticks,
            ),
        });
    }
    if reached < ceiling
        && !matches!(
            completed.step.outcome,
            AdvanceOutcome::Paused { at } if at.retired == reached.ticks
        )
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "host worker for `{}` did not report an exact output-yield pause at {}",
                node.name, reached.ticks,
            ),
        });
    }
    if reached < ceiling
        && matches!(
            completed.step.physical_stop,
            BackendPhysicalStop::Horizon | BackendPhysicalStop::UnclassifiedPause
        )
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "host worker for `{}` paused before {} without an authenticated stop cause",
                node.name, ceiling.ticks,
            ),
        });
    }
    if HeldHostStopKind::from_physical_stop(completed.step.physical_stop).is_some()
        && !matches!(completed.step.outcome, AdvanceOutcome::Paused { at } if at.retired == reached.ticks)
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "host worker for `{}` reported a guest stop without its exact physical pause",
                node.name
            ),
        });
    }
    if completed.step.physical_stop == BackendPhysicalStop::NetworkOutput
        && completed.network_outputs.is_empty()
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "host worker for `{}` reported network output without a frame batch",
                node.name,
            ),
        });
    }
    for output in &completed.network_outputs {
        if output.source != *node || output.emit_icount.retired != reached.ticks {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "host worker for `{}` returned frame {} at {} outside exact output-yield boundary {}",
                    node.name, output.sequence, output.emit_icount.retired, reached.ticks,
                ),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_held_network_lookahead(
    scheduler: &SingleScheduler,
    source: &SchedulerNodeId,
    earliest_output: VirtualTime,
    held_runs: &BTreeMap<NodeId, HeldHostRun>,
    boundary_runs: &BTreeMap<NodeId, HeldBoundaryRun>,
) -> Result<(), SchedulerError> {
    let reached = held_runs
        .values()
        .map(|held| {
            (
                &held.run.plan.node,
                held.completed.step.reached.ticks,
                false,
            )
        })
        .chain(
            boundary_runs
                .values()
                .map(|held| (&held.run.plan.node, held.boundary.stopped().ticks, true)),
        );
    for (peer, ticks, unresolved) in reached {
        if peer == source {
            continue;
        }
        let peer_reached =
            scheduler.backend_network_output_time(&peer.node, Icount { retired: ticks })?;
        for edge in scheduler.effective_topology.edges() {
            if edge.from != *source || edge.to != *peer {
                continue;
            }
            let Some(earliest_delivery) = earliest_output
                .ticks
                .checked_add(edge.minimum_latency.ticks)
            else {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("held RUN network lookahead overflowed"),
                });
            };
            // An unresolved fixed-T consumer may stop exactly at a delivery
            // cap. It must return to arbitration before consuming that input;
            // a publishable semantic STOP still requires strict separation.
            if earliest_delivery < peer_reached.ticks
                || (!unresolved && earliest_delivery == peer_reached.ticks)
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "held RUN for `{}` reached {} at or after earliest delivery {} from `{}`",
                        peer.node.name, peer_reached.ticks, earliest_delivery, source.node.name,
                    ),
                });
            }
        }
    }
    Ok(())
}
