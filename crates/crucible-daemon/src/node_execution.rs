//! Reusable exact-operation planning beneath authentic graph and runtime authority.
//!
//! The planner fixes an immutable native input cut, stages and acknowledges its
//! actual buffers, records the authentic input inventory, and then asks the
//! scheduler to reserve the conservative original execution grant. It never
//! manufactures producer progress, native receipts, or a widened safe interval.

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{NodeRuntime, RuntimeError, RuntimePollFailure, WorldActivation},
    node_scheduling::{ExecutionAdmission, SchedulingError},
};
use crucible_node_contract::{Direction, Id, U64};

/// Retains original identities selected by the owning execution format.
pub(crate) struct ExactOperationNames {
    /// Names the original native execution operation.
    pub(crate) operation: Id,
    /// Names original native input staging when this node accepts inputs.
    pub(crate) stage: Id,
    /// Names the immutable original input batch.
    pub(crate) batch: Id,
}

/// Binds exact planning to the owning graph, activation, and requested horizon.
pub(crate) struct ExactOperationRequest<'a> {
    /// Supplies the independently admitted complete graph.
    pub(crate) graph: &'a AdmittedGraph,
    /// Supplies authentic current whole-world activation authority.
    pub(crate) activation: &'a WorldActivation,
    /// Selects an original node in that graph.
    pub(crate) node: &'a Id,
    /// Caps progress without asserting producer closure.
    pub(crate) horizon: U64,
    /// Retains the format's original operation and staging identities.
    pub(crate) names: ExactOperationNames,
}

/// Plans one exact original operation or preserves authentic causal blockage.
///
/// The recorder runs after the authentic staging acknowledgement is committed
/// and before native execution is reserved, preserving the caller's provenance
/// ordering. A recorder failure leaves original staging custody in the runtime.
///
/// # Errors
/// Refuses unsupported modes, stale authority, invalid native staging, incomplete
/// input closure, recording failure, or unsafe post-staging execution admission.
pub(crate) fn plan_exact_operation<E, F>(
    runtime: &mut NodeRuntime,
    request: ExactOperationRequest<'_>,
    mut record: F,
) -> Result<Option<ExecutionAdmission>, E>
where
    E: From<SchedulingError> + From<RuntimeError> + From<RuntimePollFailure>,
    F: FnMut(serde_json::Value) -> Result<(), E>,
{
    let graph = request.graph;
    let activation = request.activation;
    let node = request.node;
    let has_inputs = graph.descriptor(node).is_some_and(|descriptor| {
        descriptor.ports.iter().any(|port| {
            port.lanes
                .iter()
                .any(|lane| lane.direction == Direction::Input)
        })
    });
    if has_inputs {
        let cutoff = match runtime
            .scheduler(graph, activation)?
            .preview_exact_input_cut(node, request.horizon)
        {
            Ok(cutoff) => cutoff,
            Err(SchedulingError::InputBlocked(_) | SchedulingError::NoSafeProgress) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let scheduler = runtime.scheduler(graph, activation)?;
        let has_deliverable_input = scheduler
            .pending_inputs(node)?
            .iter()
            .any(|delivery| delivery.delivery < cutoff);
        if !has_deliverable_input {
            // An empty input acknowledgement cannot remove a producer limit.
            // Preserve the previous native custody and let another safe owner
            // advance before allocating or staging a redundant empty batch.
            match scheduler.preview_exact_limit(node, request.horizon) {
                Ok(_) => {}
                Err(SchedulingError::InputBlocked(_) | SchedulingError::NoSafeProgress) => {
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            }
        }

        let input = match runtime.scheduler(graph, activation)?.prepare_input_batch(
            node,
            request.names.stage,
            request.names.batch,
            cutoff,
        ) {
            Ok(input) => input,
            Err(SchedulingError::InputBlocked(_) | SchedulingError::NoSafeProgress) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let observed = serde_json::json!({
            "node": node,
            "batch": input.batch(),
            "inventory": input.inventory(),
            "cutoff": input.cutoff(),
            "deliveries": input.deliveries(),
            "payloads": input.payloads(),
        });
        let acknowledgement = runtime.stage_inputs(input)?;
        let commit = runtime.commit_input_acknowledgement(acknowledgement)?;
        runtime.commit_input_staging(&commit)?;
        record(observed)?;
    }

    match runtime.scheduler(graph, activation)?.admit_exact(
        node,
        request.names.operation,
        request.horizon,
    ) {
        Ok(grant) => Ok(Some(grant)),
        Err(SchedulingError::InputBlocked(_) | SchedulingError::NoSafeProgress) if !has_inputs => {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}
