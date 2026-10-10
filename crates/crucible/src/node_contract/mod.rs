//! Process-local node interfaces and exclusive execution-owner custody.
//!
//! [`NodeRuntime`] retains operations across cancellation and lost replies.
//! [`WorldActivation`] is minted only after complete owner readiness and a
//! trusted durable publication acknowledgement. Neither type is a wire format.
//! Existing execution adapters remain separate until their node profiles qualify.

mod activation;
mod activation_preparation;
mod condition_debug;
mod fault;
mod provider;
mod quarantine;
mod runtime;
mod terminal;
mod traits;
mod types;
mod validation;

pub use activation::*;
pub use activation_preparation::*;
pub use condition_debug::*;
pub use fault::*;
pub use provider::*;
pub use quarantine::*;
pub use runtime::*;
pub use terminal::*;
pub use traits::*;
pub use types::*;

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
