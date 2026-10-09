//! Conservative exact rounds for authentic installed whole-world capture cuts.
//!
//! Input staging and grant reservation use the same planner as observation.
//! Completed native rounds publish in canonical order before their original
//! acknowledgements. The installed synchronous models retain immutable receipt
//! bodies for subsequent authenticated whole-world capture.

use std::{
    collections::BTreeSet,
    task::{Context, Poll, Waker},
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{NodeRuntime, RuntimeError, RuntimePollFailure, WorldActivation},
    node_dispatch::DispatchRound,
    node_scheduling::{ExecutionPolicy, SchedulingError},
};
use crucible_node_contract::{Id, Position, U64, canonical};

use crate::node_execution::{ExactOperationNames, ExactOperationRequest, plan_exact_operation};

use crate::node_control::{NodeControlError, refused};

impl From<RuntimeError> for NodeControlError {
    fn from(error: RuntimeError) -> Self {
        refused(error)
    }
}

impl From<SchedulingError> for NodeControlError {
    fn from(error: SchedulingError) -> Self {
        refused(error)
    }
}

impl From<RuntimePollFailure> for NodeControlError {
    fn from(error: RuntimePollFailure) -> Self {
        refused(error)
    }
}

// crucible-lint: allow rust-allow -- source identity, complete authority, and original cut remain explicit.
#[allow(clippy::too_many_arguments)]
pub(super) fn advance(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    execution: &str,
    horizon: U64,
    original_cut: Position,
    original_ordinal: U64,
) -> Result<(Position, U64), NodeControlError> {
    if horizon < original_cut.time_ps {
        return Err(refused("exact advance would change the original cut"));
    }
    if horizon == original_cut.time_ps {
        return Ok((original_cut, original_ordinal));
    }

    let mut ordinal = original_ordinal.get();
    for round_index in 0..4096 {
        observe(runtime, graph, activation)?;
        if let Some(cut) = common_cut(runtime, graph, activation, horizon)? {
            return Ok((cut, U64::new(ordinal)));
        }

        let grants = plan_round(runtime, graph, activation, execution, horizon, round_index)?;
        if grants.is_empty() {
            return Err(refused(
                "complete world is causally blocked before capture; no grant was widened",
            ));
        }
        let mut round = DispatchRound::start(runtime, grants, graph.node_ids().count())
            .map_err(|_| refused("original exact round could not start"))?;
        let mut context = Context::from_waker(Waker::noop());
        match round.poll(runtime, &mut context) {
            Poll::Ready(Ok(())) => {}
            _ => {
                return Err(refused(
                    "installed synchronous exact round did not complete",
                ));
            }
        }
        let publication = round.publish(runtime).map_err(refused)?;
        ordinal = ordinal
            .checked_add(publication.operations.len() as u64)
            .ok_or_else(|| refused("state event ordinal overflow"))?;
    }
    Err(refused("exact capture exceeded its finite round budget"))
}

fn observe(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
) -> Result<(), NodeControlError> {
    for node in graph.node_ids() {
        let observed = runtime.observe_scheduling(activation, node)?;
        runtime
            .scheduler(graph, activation)?
            .accept_boundary_observation(observed)?;
    }
    Ok(())
}

fn plan_round(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    execution: &str,
    horizon: U64,
    round: u64,
) -> Result<Vec<crucible::node_scheduling::ExecutionAdmission>, NodeControlError> {
    let mut owners = BTreeSet::new();
    let mut dispatched = BTreeSet::new();
    let mut grants = Vec::new();
    for node in graph.node_ids() {
        let binding = graph
            .binding(node)
            .ok_or_else(|| refused("sealed exact node disappeared"))?;
        let owner = &binding.compatibility.execution_owner.id;
        if !owners.insert(owner.clone())
            || graph
                .owner_conflicts(owner)
                .is_some_and(|conflicts| conflicts.iter().any(|id| dispatched.contains(id)))
        {
            continue;
        }
        let scheduler = runtime.scheduler(graph, activation)?;
        if scheduler.output_backpressure(node)? || scheduler.position(node)?.time_ps >= horizon {
            continue;
        }
        if !matches!(
            graph.operating_policy(node),
            Some(ExecutionPolicy::Exact { .. })
        ) {
            return Err(refused("state capture requires qualified exact execution"));
        }
        let names = operation_names(execution, node, horizon, round)?;
        if let Some(grant) = plan_exact_operation(
            runtime,
            ExactOperationRequest {
                graph,
                activation,
                node,
                horizon,
                names,
            },
            |_| Ok::<(), NodeControlError>(()),
        )? {
            grants.push(grant);
            dispatched.insert(owner.clone());
        }
    }
    Ok(grants)
}

fn operation_names(
    execution: &str,
    node: &Id,
    horizon: U64,
    round: u64,
) -> Result<ExactOperationNames, NodeControlError> {
    // The first round preserves the original clock-only operation identity.
    // Later rounds need distinct original commitments for causal continuation.
    let mut identity = serde_json::json!({"execution":execution,"node":node,"horizon_ps":horizon});
    if round != 0 {
        identity["round"] = round.into();
    }
    let hash = canonical::json_hash("crucible.host-state-advance.v1", &identity)?;
    Ok(ExactOperationNames {
        operation: Id::new(format!("state-operation/{}", hash.digest))?,
        stage: Id::new(format!("state-stage/{}", hash.digest))?,
        batch: Id::new(format!("state-batch/{}", hash.digest))?,
    })
}

fn common_cut(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    horizon: U64,
) -> Result<Option<Position>, NodeControlError> {
    let mut cut = None;
    for node in graph.node_ids() {
        let position = runtime.scheduler(graph, activation)?.position(node)?;
        if position.time_ps < horizon {
            return Ok(None);
        }
        if position.time_ps != horizon || cut.is_some_and(|original| original != position) {
            return Err(refused(
                "exact nodes did not reach one unchanged coherent cut",
            ));
        }
        cut = Some(position);
    }
    cut.map(Some)
        .ok_or_else(|| refused("empty world has no actual stopped cut"))
}
