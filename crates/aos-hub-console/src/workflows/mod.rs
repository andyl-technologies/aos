//! Typed page adapters for canonical control-plane workflows.

mod access_policy;
mod delivery_endpoints;
mod infrastructure;
mod network_boundaries;
mod networking;
mod resources;
mod storage_gateways;

pub(crate) use resources::ResourceWorkflow;
