//! Routes closed exact-boundary physical pause through original runtime custody.
//!
//! A pause has no semantic publication and does not move the coordinator cursor.
//! It nevertheless uses the actual committed activation, selected native facet,
//! exclusive owner reservation, original token, native receipt and native ACK.

use crucible_node_format::{Id, OperatingMode, Phase};

use super::*;
use crate::node_admission::AdmittedGraph;
use crate::node_contract::ProgressEvidence;

impl NodeRuntime {
    /// Begins physical pause at an already closed exact scheduler boundary.
    ///
    /// This narrow route does not interrupt an executing owner or infer physical
    /// suspension from logical closure. The actual adapter must return its
    /// authenticated paused outcome. No arbitrary administrative request is
    /// accepted, and no execution permission or modeled time is added.
    ///
    /// # Errors
    /// Refuses an unpublished/foreign world, changed complete graph, nonexact
    /// contract, unknown boundary, missing physical-pause facet, busy owner,
    /// reused operation, exhausted limits or refused original native submission.
    pub fn begin_exact_boundary_pause(
        &mut self,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        node: &Id,
        operation: Id,
    ) -> Result<BeginResult, RuntimeError> {
        self.validate_activation(activation)?;
        let binding = graph.binding(node).ok_or(RuntimeError::UnknownNode)?;
        if binding.compatibility.operating_contract.mode != OperatingMode::Exact {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let boundary = self
            .scheduler(graph, activation)?
            .position(node)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        if boundary.phase != Phase::BoundaryControl {
            return Err(RuntimeError::InvalidTiming);
        }
        self.begin_with_inputs(activation, node, operation, OperationRequest::Pause, None)
    }

    /// Acknowledges the same real physical pause without a fabricated event commit.
    ///
    /// Only a completed original Pause with no semantic publications qualifies.
    /// The runtime reauthenticates native stopped evidence and requires the
    /// observed logical boundary to equal the unchanged coordinator cursor.
    /// Unknown stopped position, a scheduling publication or an arbitrary output
    /// roster cannot be acknowledged through this route. Repeated ACK retries
    /// settle the same original, with no second pause submission.
    ///
    /// # Errors
    /// Refuses foreign/stale activation/token, another operation kind, pending
    /// or failed pause, changed actual native receipt, moved/unknown boundary,
    /// output obligations, unsupported exact source or native ACK failure.
    pub fn acknowledge_exact_boundary_pause(
        &mut self,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        token: &OperationToken,
    ) -> Result<(), RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        let entry = self
            .operations
            .get(token.operation())
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        if entry.admission.request() != &OperationRequest::Pause
            || !entry.admission.activation().same_authority(activation)
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let outcome = match &entry.result {
            RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome)
                if outcome.retained_outputs.is_empty() && outcome.scheduling.is_none() =>
            {
                outcome
            }
            _ => {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OutstandingObligations,
                ));
            }
        };
        let ProgressEvidence::Paused {
            reached: Some(reached),
            stop_receipt,
        } = &outcome.progress
        else {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        };
        if stop_receipt.length.get() == 0 {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        let reached = *reached;
        let admission = entry.admission.clone();
        let outcome = outcome.clone();
        let binding = graph
            .binding(&token.route.node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        if binding.compatibility.operating_contract.mode != OperatingMode::Exact {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::UnsupportedFacet,
            ));
        }
        let boundary = self
            .scheduler(graph, activation)
            .map_err(RuntimePollFailure::Admission)?
            .position(&token.route.node)
            .map_err(|error| {
                RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.to_string()))
            })?;
        if reached != boundary || reached.phase != Phase::BoundaryControl {
            self.contain_roster(token.route());
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        self.nodes
            .get(&token.route.node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?
            .validate_outcome(&admission, &outcome)
            .map_err(RuntimePollFailure::Native)?;
        self.acknowledge(token, &[])
    }
}
