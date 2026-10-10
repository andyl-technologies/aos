//! Original runtime admission for immutable authored BoundaryControl mutations.
//!
//! Native controller observations are data only. Dispatch uses the same actual
//! owner/domain reservation, original operation token and retained completion
//! ledger as execution. No timestamp, program hash or public facet description
//! can bypass selected native validation.

use super::*;

impl NodeRuntime {
    pub(super) fn has_fault_scope(&self) -> bool {
        self.snapshots
            .values()
            .any(|snapshot| snapshot.facets.contains(&FacetKind::FaultInjection))
    }

    /// Reads the next selected original controller decision without effects.
    ///
    /// # Errors
    /// Refuses foreign worlds, unsupported native controllers, changed admitted
    /// declarations, busy owners, malformed decisions and terminal fences.
    pub fn next_fault_mutation(
        &mut self,
        activation: &WorldActivation,
        node: &NodeId,
    ) -> Result<Option<super::super::FaultMutationRequest>, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        if self.terminal.is_some() || self.condition_fenced() {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        let route = self
            .checked_route(node)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_owners_available(&route)
            .map_err(RuntimePollFailure::Admission)?;
        let profile = self
            .facet(node, FacetKind::FaultInjection)
            .map_err(RuntimePollFailure::Admission)?
            .profile()
            .clone();
        let handle = self
            .nodes
            .get(node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let next = handle
            .next_fault_mutation(activation)
            .map_err(RuntimePollFailure::Native)?;
        if next
            .as_ref()
            .is_some_and(|request| request.validate().is_err() || request.facet_profile != profile)
        {
            self.contain_roster(&route);
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        Ok(next)
    }

    /// Begins the exact next immutable transition at its actual stopped cursor.
    ///
    /// Every reused operation identity remains in the original ledger. Unknown
    /// native effects retain original custody and are queried using `recover`
    /// and `poll`; calling this method again cannot repeat the mutation.
    ///
    /// # Errors
    /// Refuses unsupported selections, stale/foreign authority, changed native
    /// state, other phases, outstanding input/publication custody and credits.
    pub fn begin_fault_injection(
        &mut self,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &WorldActivation,
        node: &NodeId,
        operation: OperationId,
    ) -> Result<BeginResult, RuntimePollFailure> {
        let admission = self.admit_fault_injection(graph, activation, node, operation)?;
        self.begin_admitted(admission)
            .map_err(RuntimePollFailure::Admission)
    }

    /// Reserves the actual next mutation for common retained-round dispatch.
    ///
    /// # Errors
    /// Refuses foreign authority, changed native scope, reused identities, an
    /// unsafe coordinate or outstanding original native/coordinator obligations.
    pub fn admit_fault_injection(
        &mut self,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &WorldActivation,
        node: &NodeId,
        operation: OperationId,
    ) -> Result<crate::node_scheduling::ExecutionAdmission, RuntimePollFailure> {
        let request =
            self.next_fault_mutation(activation, node)?
                .ok_or(RuntimePollFailure::Admission(
                    RuntimeError::UnsupportedFacet,
                ))?;
        let route = self
            .checked_route(node)
            .map_err(RuntimePollFailure::Admission)?;
        if self.operations.contains_key(&operation) || self.input_batches.contains_key(&operation) {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::DuplicateOperation,
            ));
        }
        let handle = self
            .nodes
            .get_mut(node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let status = handle.status().map_err(RuntimePollFailure::Native)?;
        if status.lifecycle != Lifecycle::Stopped
            || status.physical != super::super::PhysicalState::Suspended
            || status.boundary != Some(request.at)
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidTiming));
        }
        // Re-read under original owning-thread custody before reserving the
        // common operation. A description or saved source request is insufficient.
        if handle
            .next_fault_mutation(activation)
            .map_err(RuntimePollFailure::Native)?
            != Some(request.clone())
        {
            self.contain_roster(&route);
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        let admission = self
            .scheduler(graph, activation)
            .map_err(RuntimePollFailure::Admission)?
            .admit_fault_injection(graph, node, operation, request)
            .map_err(|error| {
                RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.to_string()))
            })?;
        Ok(admission)
    }
}
