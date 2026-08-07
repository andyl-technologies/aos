//! Typed page adapters for canonical control-plane workflows.

mod access_policy;
mod access_tokens;
mod cache_gc;
mod cache_gc_jobs;
mod cache_gc_safety;
mod cache_integration_preview;
mod cache_integrations;
mod cache_manual_roots;
mod cache_objects;
mod cache_population;
mod cache_retention;
mod cache_retention_refresh;
mod cache_root_reasons;
mod cache_stack;
mod delivery_endpoints;
mod delivery_routes;
mod infrastructure;
mod instance_settings;
mod network_boundaries;
mod networking;
mod organization_identity;
mod organization_sso;
mod placement_policies;
mod placements;
mod registry_catalog;
mod registry_configuration;
mod registry_images;
mod registry_mirror;
mod registry_publication;
mod resources;
mod signing_keys;
mod storage_gateways;

pub(crate) use resources::ResourceWorkflow;
