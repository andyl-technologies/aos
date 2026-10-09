//! Structural route, permission and receipt checks before native publication.
//!
//! These checks complement authentic profile-specific native evidence. Portable
//! identities and syntactically valid references alone never prove execution.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::OperatingMode;

use super::{
    ActivationRecord, ExactBoundaryPolicy, OperationAdmission, OperationOutcome, OperationRequest,
    ProgressEvidence, RuntimeError, SimulationNode, StopReason,
};

pub(super) fn validate_roster(
    graph: &crate::node_admission::AdmittedGraph,
    nodes: &[Box<dyn SimulationNode>],
    activation: &ActivationRecord,
) -> Result<(), RuntimeError> {
    let expected: BTreeSet<_> = graph.node_ids().cloned().collect();
    let actual: BTreeSet<_> = nodes.iter().map(|node| node.route().node.clone()).collect();
    if actual != expected
        || actual.len() != nodes.len()
        || graph.world_binding_hash() != &activation.world_binding_hash
    {
        return Err(RuntimeError::InvalidRoute);
    }

    let mut owner_roster = BTreeMap::new();
    for node in nodes {
        if !node.thread_affinity().permits_current_thread() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let route = node.route();
        let binding = node.binding();
        if graph.binding(&route.node) != Some(binding)
            || graph.descriptor(&route.node) != Some(node.descriptor())
            || binding.compatibility.node_id != route.node
            || binding.authority.activation_id.is_some()
            || binding.authority.world_generation.get() != 0
        {
            return Err(RuntimeError::InvalidRoute);
        }
        let expected_owners: BTreeSet<_> = [
            binding.compatibility.execution_owner.id.clone(),
            binding.compatibility.capture_owner.id.clone(),
        ]
        .into_iter()
        .collect();
        let route_owners: BTreeSet<_> = route
            .owners
            .iter()
            .map(|owner| owner.owner.clone())
            .collect();
        if expected_owners != route_owners || route_owners.len() != route.owners.len() {
            return Err(RuntimeError::InvalidRoute);
        }
        if !route.owners.iter().any(|owner| {
            owner.owner == binding.compatibility.execution_owner.id
                && owner.incarnation == binding.authority.incarnation_id
                && owner.generation == binding.authority.owner_generation
        }) {
            return Err(RuntimeError::InvalidRoute);
        }
        for owner in &route.owners {
            if let Some(previous) = owner_roster.insert(owner.owner.clone(), owner.clone())
                && previous != *owner
            {
                return Err(RuntimeError::InvalidRoute);
            }
        }
    }
    let actual_owners: BTreeSet<_> = owner_roster.into_values().collect();
    let activation_owners: BTreeSet<_> = activation.owners.iter().cloned().collect();
    let graph_owners: BTreeSet<_> = graph.owners().map(|owner| owner.owner.id.clone()).collect();
    let actual_owner_ids: BTreeSet<_> = actual_owners
        .iter()
        .map(|owner| owner.owner.clone())
        .collect();
    if actual_owners != activation_owners || activation_owners.len() != activation.owners.len() {
        return Err(RuntimeError::InvalidRoute);
    }
    if graph_owners != actual_owner_ids {
        return Err(RuntimeError::InvalidRoute);
    }
    Ok(())
}

pub(super) fn validate_request(
    node: &dyn SimulationNode,
    request: &OperationRequest,
) -> Result<(), RuntimeError> {
    if request
        .required_facet()
        .is_some_and(|facet| !node.facets().contains(&facet))
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    match request {
        OperationRequest::ExactRun { start, limit, .. } => {
            if node.binding().compatibility.operating_contract.mode != OperatingMode::Exact
                || start >= limit
            {
                return Err(RuntimeError::InvalidTiming);
            }
        }
        OperationRequest::BoundarySettle { start, limit } => {
            if node.binding().compatibility.operating_contract.mode != OperatingMode::Exact
                || start.time_ps != limit.time_ps
                || start >= limit
            {
                return Err(RuntimeError::InvalidTiming);
            }
        }
        OperationRequest::QuantumBegin {
            start,
            end,
            host_budget,
            ..
        } => {
            if node.binding().compatibility.operating_contract.mode != OperatingMode::Quantized
                || start >= end
                || host_budget.is_zero()
            {
                return Err(RuntimeError::InvalidTiming);
            }
        }
        OperationRequest::QuantumClose { .. } => return Err(RuntimeError::InvalidTiming),
        _ => {}
    }
    Ok(())
}

pub(super) fn valid_outcome(admission: &OperationAdmission, outcome: &OperationOutcome) -> bool {
    let token = &admission.token;
    if outcome.operation != token.operation
        || outcome.node != token.route.node
        || outcome.owners != token.route.owners
        || outcome
            .retained_outputs
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != outcome.retained_outputs.len()
    {
        return false;
    }

    if let Some(observation) = &outcome.scheduling {
        if observation.node != outcome.node || observation.owners != outcome.owners {
            return false;
        }
        if let super::ProgressEvidence::Exact { reached, .. } = outcome.progress
            && observation.reached != reached
        {
            return false;
        }
    }
    let input_progress = outcome
        .scheduling
        .as_ref()
        .and_then(|observation| observation.input_progress.as_ref());
    match (admission.inputs(), input_progress) {
        (None, Some(_)) => return false,
        (Some(batch), None) if !batch.deliveries().is_empty() => return false,
        (Some(batch), Some(progress)) => {
            use crucible_node_contract::Validate;
            if progress.batch != *batch.batch()
                || progress.consumed.len() > batch.deliveries().len()
                || progress.proof_ref.validate().is_err()
                || progress.proof_ref.length.get() == 0
                || progress
                    .consumed
                    .iter()
                    .zip(batch.deliveries())
                    .any(|(consumed, original)| {
                        consumed.producer != original.producer
                            || consumed.source_sequence != original.source_sequence
                    })
            {
                return false;
            }
        }
        _ => {}
    }

    match (&admission.request, &outcome.progress) {
        (
            OperationRequest::ExactRun {
                start,
                limit,
                boundary_policy,
            },
            ProgressEvidence::Exact { reached, stop },
        ) => {
            start <= reached
                && reached <= limit
                && *stop != StopReason::Unclassified
                && (reached != limit
                    || *stop == StopReason::HorizonPark
                    || (*stop == StopReason::InputBlocked
                        && *boundary_policy == ExactBoundaryPolicy::InputBlockedPark))
                && (*stop != StopReason::HorizonPark || reached == limit)
        }
        (
            OperationRequest::BoundarySettle { start, limit },
            ProgressEvidence::Exact { reached, stop },
        ) => {
            start <= reached
                && reached <= limit
                && *stop != StopReason::Unclassified
                && (reached != limit || *stop == StopReason::HorizonPark)
                && (*stop != StopReason::HorizonPark || reached == limit)
        }
        (
            OperationRequest::QuantumBegin {
                window,
                end,
                input_batch,
                ..
            },
            ProgressEvidence::Quantized {
                window: actual_window,
                publication,
                closure,
                ..
            },
        ) => window == actual_window && publication == end && input_batch == &closure.input_batch,
        (OperationRequest::Pause, ProgressEvidence::Paused { .. }) => true,
        (
            OperationRequest::Observe | OperationRequest::Capture | OperationRequest::Shutdown,
            ProgressEvidence::Administrative,
        ) => true,
        _ => false,
    }
}
