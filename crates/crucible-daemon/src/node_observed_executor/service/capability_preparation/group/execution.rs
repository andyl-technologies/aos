//! Uses the common planner, dispatch and original scheduling ACK for every owner.

use super::super::{NodeObservationServiceError, refused};
use crate::node_execution::{ExactOperationNames, ExactOperationRequest, plan_exact_operation};
use crucible::node_dispatch::DispatchRound;
use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{NodeRuntime, WorldActivation},
    node_scheduling::NativePublication,
};
use crucible_node_contract::{Id, U64};
use std::task::{Context, Poll, Waker};

pub(super) fn advance(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    execution: &str,
    horizon: U64,
    rounds: &mut super::round_credit::RoundCredit,
    publications: &mut Vec<(Id, NativePublication)>,
) -> Result<(), NodeObservationServiceError> {
    for round in rounds {
        for node in graph.node_ids() {
            let original = runtime
                .observe_scheduling(activation, node)
                .map_err(refused)?;
            runtime
                .scheduler(graph, activation)
                .map_err(refused)?
                .accept_boundary_observation(original)
                .map_err(refused)?;
        }

        let mut progressed = false;
        for node in graph.node_ids() {
            if runtime
                .scheduler(graph, activation)
                .map_err(refused)?
                .position(node)
                .map_err(refused)?
                .time_ps
                >= horizon
            {
                continue;
            }
            let operation = format!("capability/{execution}/{round}/{node}");
            let grant =
                plan_exact_operation::<crate::node_observed_executor::NodeObservedError, _>(
                    runtime,
                    ExactOperationRequest {
                        graph,
                        activation,
                        node,
                        horizon,
                        names: ExactOperationNames {
                            operation: Id::new(operation.clone()).map_err(refused)?,
                            stage: Id::new(format!("{operation}/stage")).map_err(refused)?,
                            batch: Id::new(format!("{operation}/batch")).map_err(refused)?,
                        },
                    },
                    |_| Ok(()),
                )
                .map_err(refused)?;
            let Some(grant) = grant else {
                continue;
            };
            let mut dispatched = DispatchRound::start(runtime, vec![grant], 1)
                .map_err(|failure| refused(&failure.reason))?;
            let mut context = Context::from_waker(Waker::noop());
            let mut complete = false;
            for _ in 0..4096 {
                if let Poll::Ready(result) = dispatched.poll(runtime, &mut context) {
                    result.map_err(refused)?;
                    complete = true;
                    break;
                }
            }
            if !complete {
                return Err(refused(
                    "original common dispatch exceeds finite poll credit",
                ));
            }
            let committed = dispatched.publish(runtime).map_err(refused)?;
            for outcome in &committed.outcomes {
                if let Some(observation) = &outcome.scheduling {
                    if publications
                        .len()
                        .checked_add(observation.publications.len())
                        .is_none_or(|count| count > 33)
                    {
                        return Err(refused(
                            "original publication roster exceeds predeclared credit",
                        ));
                    }
                    publications.extend(
                        observation
                            .publications
                            .iter()
                            .cloned()
                            .map(|original| (node.clone(), original)),
                    );
                }
            }
            progressed = true;
        }

        let mut complete = true;
        for node in graph.node_ids() {
            if runtime
                .scheduler(graph, activation)
                .map_err(refused)?
                .position(node)
                .map_err(refused)?
                .time_ps
                < horizon
            {
                complete = false;
            }
        }
        if complete {
            return Ok(());
        }
        if !progressed {
            return Err(refused("original common planner is causally blocked"));
        }
    }
    Err(refused(
        "original common planner exceeds bounded round credit",
    ))
}
