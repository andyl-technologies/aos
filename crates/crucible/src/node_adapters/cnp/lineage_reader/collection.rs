//! Retains collection purpose beside original typed native and host custody.

use super::{LineageControlledReference, negotiation::ReaderTransport, readiness};
use crate::{
    node_adapters::reference_device::ControlledReferenceNode,
    node_admission::{ConformanceGraph, InstalledConformancePlan},
    node_contract::OperationFailure,
};
use crucible_node_contract::Id;

impl LineageControlledReference {
    /// Installs an actual typed source into an independently authorized collection graph.
    ///
    /// The original opaque plan is retained in the complete native capsule.
    /// No ordinary graph is returned, and common ordinary runtimes refuse the
    /// resulting collection-only node. All original structural/source checks
    /// remain conjunctive with independently installed fixture authentication.
    ///
    /// # Errors
    /// Refuses ordinary policy, changed plan, stale registrar or native/source
    /// custody, unsupported graph interpretation or exhausted operation credit.
    /// Failure transfers the same complete capsule to its retained supervisor.
    pub fn into_conformance_node(
        mut self,
        graph: &ConformanceGraph,
        node: &Id,
        maximum_operations: usize,
    ) -> Result<ControlledReferenceNode<Self>, OperationFailure> {
        graph
            .authenticate_quantized()
            .map_err(|error| readiness::refused(&error.message))?;
        let state = self.state_mut().map_err(readiness::unknown)?;
        if state.transport != ReaderTransport::Negotiated
            || state.collection.is_some()
            || state.qualification.collection_plan() != Some(graph.plan().evidence().plan_ref)
        {
            return Err(readiness::refused(
                "original typed collection purpose differs",
            ));
        }
        authenticate(state, graph.plan())?;
        state.collection = Some(graph.plan().retained());
        self.install_node(
            &graph.graph,
            node,
            maximum_operations,
            ReaderTransport::Negotiated,
        )
    }
}

pub(super) fn authenticate(
    state: &super::control::ReaderState,
    plan: &InstalledConformancePlan,
) -> Result<(), OperationFailure> {
    plan.reauthenticate()
        .map_err(|error| readiness::refused(&error.message))?;
    if state.qualification.collection_plan() != Some(plan.evidence().plan_ref) {
        return Err(readiness::refused("retained fixture plan identity changed"));
    }
    state.verify_native_custody().map_err(readiness::unknown)?;
    state
        .guard
        .with_original_realization(&state.realization, |original| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                state
                    .qualification
                    .authenticate_collection_scope(&state.guard, &original, plan)
            }))
            .map_err(|_| {
                crucible_node_provider::ProviderError::Correlation(
                    "installed collection source callback panicked",
                )
            })?
        })
        .map_err(readiness::unknown)?;
    state.verify_native_custody().map_err(readiness::unknown)
}
