//! Typed page adapters for canonical control-plane workflows.

mod delivery_endpoints;
mod infrastructure;
mod network_boundaries;
mod networking;
mod resources;

pub(crate) use resources::ResourceWorkflow;
