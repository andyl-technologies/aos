//! Typed page adapters for canonical control-plane workflows.

mod access_policy;
mod delivery_endpoints;
mod infrastructure;
mod instance_settings;
mod network_boundaries;
mod networking;
mod organization_identity;
mod organization_sso;
mod placements;
mod resources;
mod storage_gateways;

pub(crate) use resources::ResourceWorkflow;
