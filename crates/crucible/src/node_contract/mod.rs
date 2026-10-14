//! Process-local node interfaces and exclusive execution-owner custody.
//!
//! [`NodeRuntime`] retains operations across cancellation and lost replies.
//! [`WorldActivation`] is minted only after complete owner readiness and a
//! trusted durable publication acknowledgement. Neither type is a wire format.
//! Existing execution adapters remain separate until their node profiles qualify.

mod activation;
mod activation_preparation;
mod condition_debug;
mod conformance;
mod fault;
mod installed_provider;
mod provider;
mod provider_preparation;
mod provider_revision;
mod provider_world;
mod quarantine;
mod retirement_data;
mod retirement_release;
mod role_descriptions;
mod runtime;
mod terminal;
mod traits;
mod types;
mod validation;

pub use activation::*;
pub use activation_preparation::*;
pub use condition_debug::*;
pub use conformance::*;
pub(crate) use conformance::OriginalCollectingCaptureScope;
pub use fault::*;
pub use installed_provider::*;
pub use provider::*;
pub use provider_preparation::{ProviderWorldContribution, ProviderWorldPreparation};
pub use provider_revision::*;
pub use provider_world::*;
pub use quarantine::*;
pub(crate) use retirement_data::RetirementActivation;
pub use retirement_release::GracefulRetirementQualification;
pub use role_descriptions::*;
pub use runtime::*;
pub use terminal::*;
pub use traits::*;
pub use types::*;

#[cfg(test)]
pub(crate) fn test_original_admission(name: &str) -> OperationAdmission {
    runtime::test_original_admission(name)
}

#[cfg(test)]
pub(crate) fn test_nodes(
    graph: &crate::node_admission::AdmittedGraph,
) -> Vec<Box<dyn SimulationNode>> {
    runtime::test_nodes(graph)
}

#[cfg(test)]
pub(crate) fn test_custody_slot() -> Box<dyn RuntimeCustodySlot> {
    runtime::test_custody_slot()
}

mod host_scheduling_owner;
pub use host_scheduling_owner::*;
