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
    let settled = completed.step.settled_through;
    if planned.dispatch_contract == crate::BackendDispatchContract::PhysicalSource
        && settled.ticks < planned.admission.semantic_horizon().icount.retired
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
    // Settlement is all or nothing: a step attests either its whole ceiling
    // or only its own stop.
    if settled != reached && settled != ceiling {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "host worker for `{}` settled through {} instead of its stop {} or ceiling {}",
                node.name, settled.ticks, reached.ticks, ceiling.ticks,
            ),
        });
    }
    // A ceiling is an upper bound (SCHED-12). A completed horizon or an idle
    // park may settle the whole ceiling with its clock at its last retirement
    // or exact event below it; output must still stop at its exact clock.
    let settled_below_ceiling = settled == ceiling
        && reached < ceiling
        && matches!(
            completed.step.physical_stop,
            BackendPhysicalStop::Horizon | BackendPhysicalStop::Idle
        )
        && completed.network_outputs.is_empty();
    if settled == ceiling && reached < ceiling && !settled_below_ceiling {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "host worker for `{}` settled {} without a completed horizon or idle park at {}",
                node.name, ceiling.ticks, reached.ticks,
            ),
        });
    }
    // An exact-event ceiling is a modeled event for this node (SCHED-39), so
    // the node must arrive there; settling below it would hide the event.
    if settled_below_ceiling && planned.admission.dispatch_stop() == RunCeilingStop::ExactEvent {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "host worker for `{}` settled exact-event ceiling {} without arriving from {}",
                node.name, ceiling.ticks, reached.ticks,
            ),
        });
    }
    let settled_horizon = settled_below_ceiling
        && completed.step.physical_stop == BackendPhysicalStop::Horizon
        && completed.step.outcome == AdvanceOutcome::ReachedHorizon;
    if reached < ceiling
        && !settled_horizon
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
        && !settled_horizon
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
    validate_console_output(completed)?;
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

/// Requires the consumed operation endpoint in the actual canonical byte batch.
pub(super) fn validate_console_output(
    completed: &ConcurrentBackendRunOutcome,
) -> Result<(), SchedulerError> {
    let node = &completed.node;
    if let BackendPhysicalStop::ConsoleOutput { sequence } = completed.step.physical_stop
        && !completed.observations.iter().any(|event| {
            matches!(
                event.payload(),
                crate::ObservableEventPayload::NativeConsoleByte { node: source, origin }
                    if source == node && origin.node_sequence == sequence
            )
        })
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "host worker for `{}` reported console output without owned native byte origins",
                node.name,
            ),
        });
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
    // A held peer is compared at its settled endpoint: settlement through a
    // tick at or after a possible delivery would have skipped that delivery.
    let reached = held_runs
        .values()
        .map(|held| {
            (
                &held.run.plan.node,
                held.completed.step.settled_through.ticks,
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
